-- Own detached cold boot waiter. The ONLY CLI argument is the literal wait.
-- It never fabricates a completed stock firewall call from loaded1 alone.
local M={}
local BASE="/tmp/deco-iot-managed"
local function trim(s) return s and s:match("^%s*(.-)%s*$") end
function M.wait()
    local nx,json=require("nixio"),require("luci.json")
    local function read(path,limit)
        local f=io.open(path,"rb");if not f then return nil end
        local b=f:read(limit+1);local closed=f:close()
        assert(closed and type(b)=="string" and #b<=limit,"bounded boot wait read");return b
    end
    local function time() return assert(tonumber((read("/proc/uptime",128) or ""):match("^[%d.]+"))) end
    local manifest=json.decode(assert(read(BASE.."/installation.json",32768)))
    local source=json.decode(assert(read(BASE.."/boot-parent.json",2048)))
    local boot=trim(assert(read("/proc/sys/kernel/random/boot_id",128)))
    assert(nx.getuid()==0 and source.schema==1 and source.device_id==manifest.device_id and source.boot_id==boot
        and type(source.pid)=="number" and source.pid>1 and source.pid<=4194304
        and type(source.start)=="number" and source.start>0
        and (source.loaded_before=="unset" or source.loaded_before=="0"),"cold boot source binding")
    local events=assert(loadfile(BASE.."/event_state.lua"))()
    local identity={device_id=manifest.device_id,boot_id=boot}
    local function source_finished()
        local b=read("/proc/"..tostring(source.pid).."/stat",4096)
        if not b then return true end
        local rest=b:match("^%d+ %(.+%) (.*)$");if not rest then return false end
        local fields={};for token in rest:gmatch("%S+") do fields[#fields+1]=token end
        return tonumber(fields[20])~=source.start
    end
    local cursor=require("uci").cursor(nil,"/var/state")
    local function finished()
        if not source_finished() then return false end
        cursor:unload("firewall")
        if cursor:get("firewall","core","loaded")~="1" then return false end
        local good,active=pcall(json.decode,read(BASE.."/active-events.json",32768) or "")
        if not good or not events.empty(active,identity) then return false end
        if trim(read("/tmp/sync-cached-DEV_ID",128))~=manifest.device_id then return false end
        local link=tonumber(trim(read("/proc/rtk_gsw/phylink",128)))
        return link and math.floor(link/4)%2==1
    end
    local deadline=time()+30
    while not finished() do
        assert(trim(read("/proc/sys/kernel/random/boot_id",128))==boot,"boot changed")
        assert(time()<deadline,"native boot readiness timed out")
        assert(nx.nanosleep(0,100000000))
    end
    local q=assert(loadfile(BASE.."/native_quiesce.lua"))().native_adapter()
    local fd=q.open_lock();local held=false;local result
    local ok=pcall(function()
        local until_time=time()+5
        repeat
            if q.try_lock(fd) then held=true;break end
            assert(time()<until_time,"boot completion lock busy");q.sleep()
        until false
        assert(held and finished(),"native boot completion changed")
        local installer=assert(loadfile(BASE.."/runtime_install.lua"))().new(manifest)
        assert(installer.io.atomic(BASE.."/firewall-complete",json.encode({schema=1,
            device_id=identity.device_id,boot_id=boot,event="firewall",finished=true,
            source_event="cold_boot",source_pid=source.pid,source_start=source.start})))
    end)
    local closed=q.close(fd);assert(ok and closed,"cold boot completion failed")
    result=assert(loadfile(BASE.."/worker.lua"))().reconcile()
    return result
end
if arg and arg[0]==BASE.."/boot_wait.lua" then
    if #arg~=1 or arg[1]~="wait" then os.exit(2) end
    local ok,value=pcall(M.wait);os.exit(ok and value.completed and 0 or 1)
end
return M
