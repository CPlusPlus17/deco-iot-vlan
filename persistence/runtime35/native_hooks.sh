# Own fixed native reload callbacks. This file is sourced, never evals data.
deco_iot_is_managed() {
    [ -e /etc/config/deco_iot_vlan ] ||
    [ -e /tmp/deco-iot-managed/installation.json ] ||
    [ -e /tp_data/user_data/deco-iot-vlan/installation.json ]
}
deco_iot_ready() {
    /usr/bin/lua /tmp/deco-iot-managed/hook_query.lua ready
}
deco_iot_owns_vlan() {
    /usr/bin/lua /tmp/deco-iot-managed/hook_query.lua own_vlan
}
deco_iot_owns_network() {
    /usr/bin/lua /tmp/deco-iot-managed/hook_query.lua own_network
}
deco_iot_before_change() {
    case "$1" in guest|network|firewall|wifi) ;; *) return 1 ;; esac
    deco_iot_is_managed || return 0
    /usr/bin/lua /tmp/deco-iot-managed/hook_action.lua "before_$1" "$$"
}
deco_iot_before_switch_load() {
    deco_iot_is_managed || return 0
    /usr/bin/lua /tmp/deco-iot-managed/hook_query.lua preserve_vlan && return 0
    /usr/bin/lua /tmp/deco-iot-managed/hook_query.lua cold_switch_load "$$"
}
deco_iot_after_change() {
    case "$1" in guest|network|firewall|wifi) ;; *) return 1 ;; esac
    deco_iot_is_managed || return 0
    /usr/bin/lua /tmp/deco-iot-managed/hook_action.lua "after_$1" "$$"
}
