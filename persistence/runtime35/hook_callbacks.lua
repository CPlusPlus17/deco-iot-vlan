-- Own concrete device callbacks. The native adapter supplies only the fixed
-- switch/network/BSS operations reviewed separately; no placeholder succeeds.
local M={}
local BASE="/tmp/deco-iot-managed"
local function trim(s) return s and s:match("^%s*(.-)%s*$") end
function M.new(manifest)
    local install=assert(loadfile(BASE.."/runtime_install.lua"))().new(manifest)
    local hooks=assert(loadfile(BASE.."/native_adapter.lua"))().new()
    local function target(path)
        assert(install.io.hash(path)==manifest.targets[path].patched_sha1,"required native hook missing")
        return true
    end
    local native_quiet=assert(hooks.verify_native_wifi_quiet,"native event gate missing")
    function hooks.verify_native_wifi_quiet(platform)
        assert(native_quiet(platform)==true,"native Wi-Fi event active")
        target("/sbin/wifi");target("/lib/wifi/wifiupdate.sh")
        assert(install.io.hash("/lib/wifi/hostapd.sh")=="633cfee544667a9cdbebcdb1f10820fa6496cc83",
            "native BSS source version changed")
        return assert(loadfile(BASE.."/wifi_quiet.lua"))().check()==true
    end
    function hooks.verify_own_installation(platform)
        assert(manifest.committed==true and manifest.generation==platform.policy.generation
            and manifest.native_iot_saved_disabled==true,"installation not committed")
        local control=assert(loadfile(BASE.."/managed_control.lua"))()
        assert(type(control.verify_attestation)=="function"
            and control.verify_attestation(manifest,platform.policy)==true,"all-three generation attestation missing")
        for _,name in ipairs(install.FILES or {}) do
            assert(install.io.hash(BASE.."/"..name)==manifest.files[name].sha1,"runtime source changed")
        end
        return install:verify_targets()
    end
    function hooks.install_native_writer_guard()
        target("/usr/lib/lua/luci/model/uci.lua")
        target("/usr/lib/lua/luci/controller/admin/mobile_app/wireless.lua")
        -- Future TMP/CGI processes load the bound wrapper. Also protect this
        -- already-running worker if it loaded the native model before binding.
        local uci=require("luci.model.uci");local meta=assert(getmetatable(uci.cursor()))
        if not meta.__deco_iot_guard then
            local fs=require("nixio.fs")
            assert(loadfile(BASE.."/managed_cursor_guard.lua"))().install(meta,function()
                return fs.stat("/etc/config/deco_iot_vlan")~=nil or fs.stat(BASE.."/installation.json")~=nil
            end)
        end
        return meta.__deco_iot_guard==true
    end
    function hooks.install_generator_guard() return target("/lib/wifi/wificommon.sh") end
    function hooks.protect_network_cleanup() return target("/etc_ro/init.d/network") end
    function hooks.protect_guest_cleanup()
        return target("/lib/guest-eth/guest-eth.sh") and target("/lib/guest-eth/guest-vlan.sh")
            and target("/lib/firewall/core.sh")
    end
    function hooks.wait_native_firewall_finished(platform)
        local nx,json=require("nixio"),require("luci.json")
        local uci=require("uci").cursor(nil,"/var/state")
        local until_time=platform.io.time()+5
        repeat
            platform:guard()
            local raw=platform:read(BASE.."/firewall-complete",2048)
            local good,value=pcall(json.decode,raw or "")
            uci:unload("firewall")
            if good and type(value)=="table" and value.schema==1 and value.finished==true
                and value.event=="firewall" and value.device_id==platform.context.device_id
                and value.boot_id==platform.context.boot_id and uci:get("firewall","core","loaded")=="1" then return true end
            if platform.io.time()>=until_time then return false end
            assert(nx.nanosleep(0,50000000))
        until false
    end
    return hooks
end
return M
