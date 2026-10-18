-- Own wrapper for the exact saved native mobile WiFi module. Ordinary requests
-- retain its original dispatch and result behavior. No extra opcode is added.
local BASE='/tmp/deco-iot-managed'
local NAME='luci.controller.admin.mobile_app.wireless'
local control=assert(loadfile(BASE..'/managed_control.lua'))()
assert(loadfile(BASE..'/stock/mobile_wireless.luac'))(NAME)
local original=assert(package.loaded[NAME],'saved native wireless module unavailable')
assert(type(original)=='table' and type(original.dispatch)=='function','native wireless dispatch invalid')
original.dispatch=control.wrap(original.dispatch)
return original
