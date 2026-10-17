# Stock Firmware 1.5.0 VLAN, Bridge & Config-Persistence Analysis

**Target Firmware:** TP-Link Deco XE75 Pro V3 — `1.5.0 Build 20260603 Rel. 15804`

This document records the static reverse-engineering findings from the extracted SquashFS rootfs explaining why stock IoT VLAN tagging and AP-mode Guest VLAN tagging do not work out of the box, and how `/etc/config` is persisted across reboots.

---

## 1. Stock Wireless VAP -> Bridge Mapping (`/lib/wifi/wificommon.sh`)

- All wireless VAPs (`lan`, `guest`, `iot`) are assigned to `network 'lan'` (`br-lan`) by `/lib/wifi/wificommon.sh` (lines 517, 651).
- Separate Linux bridges per SSID are **not** used by default on stock firmware; only `br-lan`, `br-iptv`, and `br-wan` exist in `/etc/apsd.json`.
- For the **IoT Network**, the active VAP interface names on the XE75 Pro V3 are:
  - **`ath08`** (`2.4 GHz` IoT VAP, `mode 'ap'`, `type 'iot'`)
  - **`ath18`** (`5 GHz` IoT VAP, `mode 'ap'`, `type 'iot'`)
  - *(Note: `ath05` / `ath15` / `ath25` are `default_bk` mesh backhaul VAPs, not IoT VAPs).*

---

## 2. Why `iot_wifi.iot.vlan_enable=1` Is a 100% No-Op on Stock Firmware

In `/etc/config/iot_wifi`, TP-Link includes `option vlan_enable '0'`. However, setting `iot_wifi.iot.vlan_enable='1'` and `iot_wifi.iot.vlan_id='30'` in UCI has zero effect on the datapath because:
1. **`/etc_ro/init.d/iot_network` has all VLAN logic commented out:**
   - Line 9 (`# . /lib/iot_network/iot_eth.sh`) is commented out.
   - Lines 27–28 and 41–69 (`iot_vlan_id`, `iot_vlan_enable`, `switch_iot_config`) are commented out.
   - Only `/lib/iot_network/client_isolate.sh` (`tpbrctl` bridge isolation table + `/proc/tpbr_filter/iot_isolate`) is active.
2. **`/lib/iot_network/iot_eth.sh` does not exist in the rootfs:** TP-Link never shipped the helper script in the `1.5.0` image.
3. **`/lib/wifi/wificommon.sh` ignores `vlan_enable` / `vlan_id` on `iot`:**
   - `wifi_config_list` (lines 1176–1182) only watches `iot.{ssid,encryption,password,enable,enc_type,enable_2g,enable_5g}` and hardcodes `uci_set wireless $section network "lan"` (line 651).

---

## 3. Why Guest Network VLAN Tagging (`0x4008`) Is Gated Off in `AP` Mode

Even if you try to repurpose the Guest Network's VLAN feature (`wifi.guest.vlan_enable='1'`, `wifi.guest.vlan_id='<VID>'`) while running the Deco mesh in **Access Point (`AP`) mode**:
1. **`/etc/init.d/guest-eth.sh` (`switch_guest_config`, lines 206–248)** checks `/etc/config/sysmode` (`sysmode.sysmode.mode`) and `/tmp/device_type`:
   - In **`Router` mode**, it configures hardware `switch1` (`vlan.guest`) with external switch ports (`0t 1t 2t 3t 6t`) and creates `eth1.<vid>` via `vconfig`.
   - On a main unit in **`AP` mode** (`sysmode == "AP"`, `device_type == "AP"`), `guest-eth.sh` sets `vlan.guest.ports='6t'` (internal CPU port only!) and skips external switch port tagging.
   - On satellites (`device_type == "RE"`), `guest-eth.sh` line 53 checks `elif [ "$device_type" == "RE" ] && [ "$wan_detect" == "1" ]`, which leaves satellites inconsistent if `wan_detect` is not set.
2. **`/etc/init.d/apsd` (lines 101–179)** likewise gates `eth1.<vid>` creation behind `Router` mode or `RE` with `eth_backhaul == "1"`.

### Reconciling the `0x4008` (`wireless_guest_write`) Handler Schemas
- Top-level opcode `0x4008` (`luci.controller.admin.mobile_app.wireless`, `form="wlan"`, `op="write"`) reads `band2_4.guest` (or `band5_1.guest` / `band5_2.guest`) in `mobile_wireless.lua` (lines 243–301, 1239–1287).
- If `band2_4.guest.vlan_id` is truthy and `~= network.vlan.id`, `mobile_wireless.lua` sets `L27_2.vlan_id = band2_4.guest.vlan_id` and unconditionally forces `L27_2.vlan_enable = "1"`, then passes `L27_2` to `app_wifi:set_guest(L27_2)` (`app_wifi.lua`).
- Furthermore, when `wifi.guest.vlan_enable='0'`, `switch_guest_config` (`guest-eth.sh:196`) returns early without removing `vlan.guest` or `eth1.<vid>`.

---

## 4. Reload Traps (`wificommon.sh` & `/etc/init.d/network`)

A naive manual `brctl` / `ip link` setup does not survive a stock network or Wi-Fi reload without lifecycle hooks because:
1. `/lib/wifi/wificommon.sh:651` re-pins IoT VAPs (`ath08`, `ath18`) back to `network='lan'` (`br-lan`) on Wi-Fi reload.
2. `/etc/init.d/network:1293-1302` purges non-allowlisted sub-interfaces on network reload (`guest-eth.sh`'s `del_invalid_guest_eth` only protects the guest VLAN sub-interface).

---

## 5. How `/etc/config` Persistence Works (`loaduci`, `saveconfig`, `nvrammanager`)

`/etc` and `/etc/config` are mounted as volatile `ramfs` filesystems at boot (`/etc/init.d/boot:66`). Persistent configuration is stored in `/tp_data/user_data/` (`ubi2:ubi_runtime_data`, mounted `rw,sync` by `/sbin/mount_tpdata` at `START00`).

Decompilation of `luci/sys/config.lua` and `luci/model/crypto.lua` reveals the exact persistence pipeline:
1. **`/sbin/saveconfig` (`require("luci.sys.config").saveconfig(partition)`):**
   - Serializes all `/etc/config/*` packages belonging to `user-config` (or `device-config`) into `/tmp/save-userconf.xml` via `fileToXml`.
   - Compresses and encrypts `/tmp/save-userconf.xml` -> `/tmp/save-userconf.cry` using `zlib` + `AES-256-CBC` (`openssl zlib -e | openssl enc -e -aes-256-cbc -K <K> -iv <IV>`), where `<K>` and `<IV>` are fetched from `libtrkutil crypto.lua.key` and `libtrkutil crypto.lua.iv` (with fallback constants in `luci/model/crypto.lua`).
   - Invokes `nvrammanager -w /tmp/save-userconf.cry -p user-config`, writing the encrypted container into `/tp_data/user_data/`.
2. **`/sbin/loaduci` (run at `START10` during boot):**
   - Calls `nvrammanager -r /tmp/user-config.cry -p user-config`, decrypts `.cry` -> `.xml` via `luci.model.crypto.dec_file_entry`, parses the XML via `xmlToFile`, and populates `/etc/config/*`.
3. **`/sbin/reload_config`:**
   - Hashes `/etc/config/*` against `/var/run/config.md5` (`uci show <file> | sort | md5sum`) and emits `ubus call service event '{"type":"config.change","data":{"package":"<pkg>"}}'` for each modified package.
