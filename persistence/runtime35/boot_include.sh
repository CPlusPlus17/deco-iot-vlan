# Own native firewall include. File/code staging and fixed bind guards happen
# synchronously before uhttpd/TMP startup can accept an ordinary IoT toggle.
# Private network activation is detached and waits for this service to finish.
deco_iot_bootstrap_include() {
    [ -f /tp_data/user_data/deco-iot-vlan/installation.json ] || return 0
    [ -f /tp_data/user_data/deco-iot-vlan/boot_entry.lua ] || return 1
    /usr/bin/lua /tp_data/user_data/deco-iot-vlan/boot_entry.lua "$$"
}
deco_iot_bootstrap_include
