-- Own intended firewall-include loader. No flash/boot variables/reboot/network
-- changes. Native iot_wifi.iot.enable must already be saved0 on all three.
local M={}
local BASE="/tmp/deco-iot-managed"
local PERSIST="/tp_data/user_data/deco-iot-vlan"
local function trim(s) return s and s:match("^%s*(.-)%s*$") end
local function proc(a,pid)
    local body=a.read("/proc/"..tostring(pid).."/stat",4096)
    if not body then return nil end
    local rest=body:match("^%d+ %(.+%) (.*)$");if not rest then return nil end
    local fields={};for token in rest:gmatch("%S+") do fields[#fields+1]=token end
    return {pid=pid,start=tonumber(fields[20]),parent=tonumber(fields[2])}
end
-- Exact native getfirm_cached() lazily creates the same files consumed by
-- boot_wait/worker. Shell getfirm alone populates a different cache namespace.
local function initialize_identity_cache(device_id)
    assert(device_id=="@MAIN_DEVICE_ID@"
        or device_id=="@BEDROOM_DEVICE_ID@"
        or device_id=="@CELLAR_DEVICE_ID@","fixed boot device required")
    -- The native getter uses value:trim(); util installs string.trim.
    require("luci.util")
    local getter=require("luci.model.getfirm").getfirm_cached
    assert(type(getter)=="function","native cached identity getter unavailable")
    local expected={DEV_ID=device_id,MODEL="XE75Pro",HARDVERSION="3.0",
        SOFTVERSION="1.5.0 Build 20260603 Rel. 15804"}
    for _,key in ipairs({"DEV_ID","MODEL","HARDVERSION","SOFTVERSION"}) do
        local value=getter(key)
        assert(type(value)=="string" and #value<=512 and trim(value)==expected[key],"native boot identity cache mismatch")
        local f=assert(io.open("/tmp/sync-cached-"..key,"rb"),"native identity cache missing")
        local body=f:read(513);local closed=f:close()
        assert(closed and type(body)=="string" and #body<=512 and trim(body)==expected[key],"native identity cache readback mismatch")
    end
    return true
end
M.initialize_identity_cache=initialize_identity_cache
function M.prepare(source_pid)
    local nx,json=require("nixio"),require("luci.json")
    assert(nx.getuid()==0 and type(source_pid)=="number" and source_pid>1 and source_pid<=4194304
        and source_pid==math.floor(source_pid),"fixed native source required")
    local installer_module=assert(loadfile(PERSIST.."/runtime_install.lua"))()
    local function read(path,limit)
        local f=assert(io.open(path,"rb"));local b=f:read(limit+1);assert(f:close())
        assert(type(b)=="string" and #b<=limit,"boot manifest bound");return b
    end
    local manifest=json.decode(read(PERSIST.."/installation.json",32768))
    assert(initialize_identity_cache(manifest.device_id))
    local installer=installer_module.new(manifest);local a=installer.io
    local prior=a.read(BASE.."/installation.json",32768)
    local prior_manifest=prior and json.decode(prior) or nil
    local was_installed=type(prior_manifest)=="table" and prior_manifest.ram_guards_installed==true
    installer:stage();installer:identity()
    local cursor=require("uci").cursor()
    assert(cursor:get("iot_wifi","iot","enable")=="0","native IoT must be disabled before boot installation")
    local function prepare_ui(cold)
        if manifest.device_id=="@MAIN_DEVICE_ID@" then
            assert(manifest.ui_role=="main" and type(manifest.ui_boot)=="table"
                and type(manifest.ui_boot.module)=="table","main UI boot metadata missing")
            assert(a.hash(PERSIST.."/ui_boot_install.lua")==manifest.ui_boot.module.sha1,"UI boot source changed")
            return assert(loadfile(PERSIST.."/ui_boot_install.lua"))().prepare(manifest,cold)
        end
        assert(manifest.ui_role=="none" and manifest.ui_boot==nil,"satellite UI scope changed")
        return {installed=false,not_required=true}
    end
    if was_installed then
        -- A normal subsequent native reload already owns its paired event.
        -- Never erase that event or invent an initial completion marker.
        local ui=prepare_ui(false)
        installer:verify_targets();return {prepared=true,already_installed=true,worker_queued=false,ui=ui}
    end
    local boot=trim(assert(a.read("/proc/sys/kernel/random/boot_id",128)))
    local identity={device_id=manifest.device_id,boot_id=boot}
    local source=assert(proc(a,source_pid),"native firewall source unavailable")
    assert(source.start,"native firewall start unavailable")
    local ancestor=nx.getppid();local found=false
    for _=1,4 do
        if ancestor==source_pid then found=true;break end
        local parent=proc(a,ancestor);if not parent then break end
        ancestor=parent.parent or 0;if ancestor<=1 then break end
    end
    assert(found,"source is not the native include ancestor")
    local command=assert(a.read("/proc/"..tostring(source_pid).."/cmdline",4096))
    local known=false
    for word in command:gmatch("([^%z]+)%z") do
        if word=="/etc/init.d/firewall" or word=="/etc/rc.d/S45firewall" then known=true end
    end
    assert(known,"first boot include must be inside native firewall service")
    local events=assert(loadfile(BASE.."/event_state.lua"))()
    local current_events=a.read(BASE.."/active-events.json",32768)
    assert(not current_events or events.empty(json.decode(current_events),identity),"native event blocks first boot install")
    assert(a.atomic(BASE.."/active-events.json",a.encode(events.initial(identity))))
    local state_cursor=require("uci").cursor(nil,"/var/state")
    local loaded_before=state_cursor:get("firewall","core","loaded") or "unset"
    assert(a.atomic(BASE.."/boot-parent.json",a.encode({schema=1,device_id=identity.device_id,
        boot_id=identity.boot_id,pid=source.pid,start=source.start,loaded_before=loaded_before})))
    -- Parent admin/network mounts must precede the nested mobile-wireless
    -- child bind. A manual install only reuses the already verified seven UI
    -- mounts; it never remounts a parent over an existing child.
    local ui=prepare_ui(loaded_before=="unset" or loaded_before=="0")
    -- Source files/guard targets only; no network command is permitted here.
    installer:install_targets();installer:verify_targets()
    local installed=json.decode(assert(a.read(BASE.."/installation.json",32768)))
    installed.ram_guards_installed=true
    assert(a.atomic(BASE.."/installation.json",a.encode(installed)))
    if loaded_before~="unset" and loaded_before~="0" then
        -- An already-loaded first manual install has no observable old-stock
        -- completion transition. A later fully guarded native restart must
        -- publish its normal paired completion; keep IoT held meanwhile.
        return {prepared=true,already_installed=false,worker_queued=false,requires_guarded_reload=true,ui=ui}
    end
    local ready_read,ready_write=nx.pipe()
    assert(ready_read and ready_write,"cold boot waiter pipe failed")
    local pid=assert(nx.fork(),"cold boot waiter fork failed")
    if pid==0 then
        pcall(function()
            assert(ready_read:close())
            assert(nx.setsid()==nx.getpid(),"cold waiter detach failed")
            -- A deliberately independent worker must not inherit the bounded
            -- native command's process-group ownership marker.
            assert(nx.setenv("DECO_IOT_OWN_COMMAND_SESSION"))
            assert(nx.getenv("DECO_IOT_OWN_COMMAND_SESSION")==nil)
            assert(ready_write:write("R")==1);assert(ready_write:close())
            local null=assert(nx.open("/dev/null","w+"))
            assert(nx.dup(null,nx.stdin));assert(nx.dup(null,nx.stdout));assert(nx.dup(null,nx.stderr))
            local n=assert(tonumber(tostring(null):match("^nixio file (%d+)$")))
            if n>2 then assert(null:close()) end
            nx.execp("/usr/bin/lua",BASE.."/boot_wait.lua","wait")
        end)
        os.exit(127)
    end
    assert(ready_write:close())
    assert(ready_read:read(1)=="R","cold boot waiter failed before detach")
    assert(ready_read:close())
    return {prepared=true,already_installed=false,worker_queued=pid>1,ui=ui}
end
if arg and arg[0]==PERSIST.."/boot_entry.lua" then
    local pid=arg[1] and arg[1]:match("^%d+$") and tonumber(arg[1])
    if #arg~=1 or not pid then os.exit(2) end
    local ok,value=pcall(M.prepare,pid)
    os.exit(ok and value.prepared and 0 or 1)
end
return M
