-- Own replacement source for the ONE reviewed stock luci.model.uci module.
-- Not installed by this file. No native UCI configuration is changed here.
local BASE="/tmp/deco-iot-managed"
local fs=require("nixio.fs")
local loader=assert(loadfile(BASE.."/uci_guard_loader.lua"))()
local guard=assert(loadfile(BASE.."/managed_cursor_guard.lua"))()
local function managed()
    return fs.stat("/etc/config/deco_iot_vlan")~=nil
        or fs.stat(BASE.."/installation.json")~=nil
        or fs.stat("/tp_data/user_data/deco-iot-vlan/installation.json")~=nil
end
return loader.load(assert(loadfile(BASE.."/stock/luci_model_uci.luac")),package.loaded,guard,managed)
