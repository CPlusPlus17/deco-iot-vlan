#!/bin/sh
# Own existing-VAP-only native BSS refresh. Installer must pin native
# hostapd.sh SHA256 1e0e8479602b841f5371ca22622e32ecc0072fd592437ab8073662dc935db3ed.
# Missing VAPs stay held: cold-boot creation is not established by this file.
# Caller holds worker lock, journals intent, holds both IoT VAPs down, and has
# moved this target to the owned private bridge before calling this helper.

deco_iot_radio_projection() {
    case "$1" in ath02) deco_expected_wiphy=0 ;; ath12) deco_expected_wiphy=2 ;; *) return 1 ;; esac
    iw dev "$1" info | awk -v expected="$deco_expected_wiphy" '
      /^[ \t]*type / { nt++; if ($2!="AP") bad=1; }
      /^[ \t]*wiphy / { np++; if ($2!=expected) bad=1; }
      /^[ \t]*channel / {
        if ($2 !~ /^[0-9]+$/ || $3 !~ /^\([0-9]+$/ || $4 != "MHz)," ||
            $5 != "width:" || $6 !~ /^[0-9]+$/ || $7 != "MHz," ||
            $8 != "center1:" || $9 !~ /^[0-9]+$/ || $10 != "MHz") bad=1;
        c=$2; f=$3; sub(/^\(/,"",f); w=$6; m=$9; n++;
      }
      END { if (!bad && n==1 && nt==1 && np==1 && c>0 && c<=177 && f>=2400 && f<6000 &&
                  (w==20 || w==40 || w==80 || w==160) && m>=2400 && m<6000)
              print c, f, w, m; else exit 1; }'
}

deco_iot_parent_binding() {
    [ "$(cat "/sys/class/net/$deco_radio/phy80211/name")" = "$deco_phy" ] &&
    [ "$(cat "/sys/class/net/$deco_main/phy80211/name")" = "$deco_phy" ] &&
    [ "$(cat "/sys/class/net/$deco_vif/phy80211/name")" = "$deco_phy" ] &&
    [ "$(cat "/sys/class/net/$deco_radio/ifindex")" = "$deco_radio_index" ] &&
    [ "$(cat "/sys/class/net/$deco_main/ifindex")" = "$deco_main_index" ]
}

deco_iot_vap_binding() {
    [ "$(cat "/sys/class/net/$deco_vif/ifindex")" = "$deco_index" ] &&
    [ "$(cat "/sys/class/net/$deco_vif/master/bridge/bridge_id")" = "$deco_bridge" ] &&
    [ "$(cat /sys/class/net/br-iot/bridge/bridge_id)" = "$deco_bridge" ] &&
    deco_iot_parent_binding
}

deco_iot_fst_package_absent() { [ ! -e /etc/config/fst ] && [ ! -L /etc/config/fst ]; }

deco_iot_fst_inactive() {
    # Native hostapd.sh executes its FST branch only after config_load succeeds.
    # An actually absent fixed package follows that exact native inactive path;
    # an existing malformed/unknown package is not silently treated as disabled.
    if config_load fst; then
        config_get deco_fst_disabled config disabled
        [ "$deco_fst_disabled" = 1 ]
    else
        deco_iot_fst_package_absent
    fi
}

deco_iot_bss_path_safe() {
    [ ! -L "/var/run/hostapd-$deco_vif.conf" ] &&
    { [ ! -e "/var/run/hostapd-$deco_vif.conf" ] || [ -f "/var/run/hostapd-$deco_vif.conf" ]; }
}

deco_iot_bss_present() { [ -f "/var/run/hostapd-$deco_vif.conf" ]; }

deco_iot_validate_bss() {
    awk -F= -v vif="$deco_vif" -v channel="$deco_channel" -v width="$deco_width" \
      -v radio="$deco_radio" -v center="$deco_center" -v htmode="$deco_htmode" '
      /^interface=/ { ni++; if ($2!=vif) bad=1; }
      /^bridge=/ { nb++; if ($2!="br-iot") bad=1; }
      /^channel=/ { nc++; if ($2!=channel) bad=1; }
      /^hw_mode=/ { nh++; if ($2!=(radio=="wifi0" ? "g" : "a")) bad=1; }
      /^(vht|he)_oper_chwidth=/ {
        nw++; if ($2!=(width==160 ? 2 : width==80 ? 1 : 0)) bad=1;
      }
      /^(vht|he)_oper_centr_freq_seg0_idx=/ {
        nm++; if ($2!=(center-5000)/5) bad=1;
      }
      /^ht_capab=/ {
        if (width==20 && $2 ~ /HT40/) bad=1;
        if (width==40 && index($2,"[" htmode "]")==0) bad=1;
      }
      /^bss=|^iapp_interface=|^dynamic_vlan=|^acs_|^op_class=/ { bad=1; }
      END { exit (bad || ni!=1 || nb!=1 || nc!=1 || nh!=1 ||
                  (radio=="wifi2" && (nw!=1 || nm!=1))); }' "/var/run/hostapd-$deco_vif.conf"
}

deco_iot_native_control() { command /usr/sbin/wpa_cli "$@"; }

# Native hostapd_setup_vif dispatches through this exact function. Only its
# fixed ADD is accepted; response bytes, rather than CLI exit alone, attest it.
# Remove the target BSS only after the replacement configuration validates.
wpa_cli() {
    [ "$#" = 5 ] && [ "$1" = -g ] && [ "$2" = /var/run/hostapd/global ] &&
    [ "$3" = raw ] && [ "$4" = ADD ] &&
    [ "$5" = "bss_config=$deco_vif:/var/run/hostapd-$deco_vif.conf" ] || return 1
    deco_iot_bss_path_safe && deco_iot_bss_present || return 1
    deco_iot_validate_bss && deco_iot_ready && deco_iot_vap_binding || return 1
    [ "$(deco_iot_radio_projection "$deco_main")" = "$deco_projection" ] || return 1
    deco_iot_native_control -g /var/run/hostapd/global raw REMOVE "$deco_vif" >/dev/null 2>&1
    deco_reply=$(deco_iot_native_control "$@") || return 1
    [ "$deco_reply" = OK ] || return 1
    deco_added=1
}

deco_iot_setup_existing_vap() (
    set -f
    case "$1" in
        ath08) deco_vif=ath08; deco_radio=wifi0; deco_main=ath02; deco_phy=phy0; deco_option=enable_2g ;;
        ath18) deco_vif=ath18; deco_radio=wifi2; deco_main=ath12; deco_phy=phy2; deco_option=enable_5g ;;
        *) return 1 ;;
    esac
    [ "$#" = 1 ] && deco_iot_ready || return 1
    [ "$(uci -q get iot_wifi.iot.enable)" = 0 ] &&
    [ "$(uci -q get "iot_wifi.iot.$deco_option")" = 1 ] || return 1
    deco_index=$(cat "/sys/class/net/$deco_vif/ifindex") || return 1
    case "$deco_index" in ''|*[!0-9]*) return 1 ;; esac
    deco_radio_index=$(cat "/sys/class/net/$deco_radio/ifindex") || return 1
    deco_main_index=$(cat "/sys/class/net/$deco_main/ifindex") || return 1
    case "$deco_radio_index:$deco_main_index" in *[!0-9:]*|:*|*:) return 1 ;; esac
    deco_bridge=$(cat /sys/class/net/br-iot/bridge/bridge_id) || return 1
    [ -n "$deco_bridge" ] && deco_iot_vap_binding || return 1
    deco_flags=$(cat "/sys/class/net/$deco_vif/flags") || return 1
    case "$deco_flags" in 0x*) deco_digits=${deco_flags#0x} ;; *) return 1 ;; esac
    case "$deco_digits" in ''|*[!0-9a-fA-F]*) return 1 ;; esac
    [ "${#deco_digits}" -le 8 ] || return 1
    [ $((deco_flags & 1)) = 0 ] || return 1
    deco_iot_bss_path_safe || return 1
    deco_iot_fst_inactive || return 1
    config_load wireless || return 1
    config_get deco_type "$deco_vif" type
    config_get deco_mode "$deco_vif" mode
    config_get deco_device "$deco_vif" device
    config_get deco_vapname "$deco_vif" vapname
    config_get deco_network "$deco_vif" network
    config_get deco_disabled "$deco_vif" disabled
    [ "$deco_type" = iot ] && [ "$deco_mode" = ap ] && [ "$deco_device" = "$deco_radio" ] &&
    [ "$deco_vapname" = "$deco_vif" ] && [ "$deco_network" = iot ] && [ "$deco_disabled" = 0 ] || return 1
    config_get_bool deco_dpp "$deco_vif" dpp 0
    config_get_bool deco_wps "$deco_vif" wps_pbc 0
    config_get_bool deco_label "$deco_vif" wps_label 0
    [ "$deco_dpp" = 0 ] && [ "$deco_wps" = 0 ] && [ "$deco_label" = 0 ] || return 1
    config_get deco_hwmode "$deco_radio" hwmode
    case "$deco_radio:$deco_hwmode" in
        wifi0:11axg|wifi0:11ng|wifi2:11axa|wifi2:11ac) ;;
        *) return 1 ;;
    esac
    deco_projection=$(deco_iot_radio_projection "$deco_main") || return 1
    set -- $deco_projection
    [ "$#" = 4 ] || return 1
    deco_channel=$1; deco_width=$3; deco_center=$4
    case "$deco_width" in
        20) deco_htmode=HT20 ;;
        40) if [ "$deco_center" -gt "$2" ]; then deco_htmode=HT40+; else deco_htmode=HT40-; fi ;;
        80|160) [ "$deco_radio" = wifi2 ] || return 1; deco_htmode=HT$deco_width ;;
        *) return 1 ;;
    esac
    # In-memory only: current channel/width, no ACS, no edge substitution, no
    # shared WPS-tie. No persistent UCI commit or radio ioctl is performed.
    config_set "$deco_radio" channel "$deco_channel"
    config_set "$deco_radio" htmode "$deco_htmode"
    config_set "$deco_radio" edge_channel_deprioritize 0
    config_set qcawifi wps_vap_tie_dbdc 0
    config_set "$deco_vif" bridge br-iot
    config_set "$deco_vif" ifname "$deco_vif"
    ht_capab=; vht_capab=; wps_possible=; config_methods=
    deco_added=0
    hostapd_setup_vif "$deco_vif" nl80211 no_nconfig >/dev/null 2>&1 || return 1
    [ "$deco_added" = 1 ] && deco_iot_ready && deco_iot_vap_binding || return 1
    [ "$(deco_iot_radio_projection "$deco_main")" = "$deco_projection" ] || return 1
    printf '%s\n' DECO_IOT_VAP_REFRESHED
)

# FIXED_ENTRYPOINT: fixtures load only definitions, with all I/O mocked.
[ "$#" = 1 ] || exit 1
case "$1" in ath08|ath18) ;; *) exit 1 ;; esac
umask 077
. /lib/functions.sh
. /lib/wifi/hostapd.sh
. /tmp/deco-iot-managed/native_hooks.sh
deco_iot_setup_existing_vap "$1"
