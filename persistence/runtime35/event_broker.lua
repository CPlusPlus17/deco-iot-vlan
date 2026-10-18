-- Own fixed native-event journal. No caller-selected paths or commands.
-- Entry point and installer must stage/verify all dependencies before binding
-- native scripts. This module does not install, save config or enable IoT.
local M={}
local BASE="/tmp/deco-iot-managed"
local EVENTS={guest=true,network=true,firewall=true,wifi=true}
local NODES={["@MAIN_DEVICE_ID@"]=true,
    ["@BEDROOM_DEVICE_ID@"]=true,["@CELLAR_DEVICE_ID@"]=true}
local function trim(s) return s and s:match("^%s*(.-)%s*$") end
-- Parent acknowledges the new independent session BEFORE the child may exec.
-- Otherwise the native caller can exit while its child still belongs to the
-- bounded command's group and be mistaken for an unquiesced descendant.
local function spawn_worker(nx,process)
    local ready_rd,ready_wr=nx.pipe();assert(ready_rd and ready_wr,"worker ready pipe failed")
    local gate_rd,gate_wr=nx.pipe()
    if not gate_rd then ready_rd:close();ready_wr:close();error("worker gate pipe failed") end
    local pid
    local ok=pcall(function()
        pid=assert(nx.fork(),"fixed worker fork failed")
        if pid==0 then
            pcall(function()
                assert(ready_rd:close());assert(gate_wr:close())
                assert(nx.setsid()==nx.getpid(),"worker session create failed")
                -- Exact native setenv(name) invokes unsetenv(name). Only the
                -- inherited marker for OUR bounded helper group is removed.
                assert(nx.setenv("DECO_IOT_OWN_COMMAND_SESSION"),"worker session marker unset failed")
                assert(nx.getenv("DECO_IOT_OWN_COMMAND_SESSION")==nil,"worker session marker remained")
                local null=assert(nx.open("/dev/null","w+"))
                assert(nx.dup(null,nx.stdin));assert(nx.dup(null,nx.stdout));assert(nx.dup(null,nx.stderr))
                local number=assert(tonumber(tostring(null):match("^nixio file (%d+)$")),"native null FD unavailable")
                if number>2 then assert(null:close()) end
                assert(ready_wr:write("R")==1);assert(ready_wr:close())
                assert(gate_rd:read(1)=="G","worker launch gate revoked");assert(gate_rd:close())
                nx.execp("/usr/bin/lua",BASE.."/worker.lua","reconcile")
            end)
            os.exit(127)
        end
        assert(ready_wr:close());ready_wr=nil;assert(gate_rd:close());gate_rd=nil
        local actor=assert(process(pid),"worker identity unavailable")
        assert(actor.state~="Z","worker exited before readiness")
        -- Exact native poll.c returns false on timeout, positive count on
        -- readiness. A pipe EOF cannot be mistaken for the required byte.
        local count=nx.poll({{fd=ready_rd,events=nx.poll_flags("in")}},1000)
        assert(type(count)=="number" and count==1 and ready_rd:read(1)=="R","worker session readiness failed")
        assert(ready_rd:close());ready_rd=nil
        local fresh=assert(process(pid),"worker disappeared before launch")
        assert(fresh.start==actor.start and fresh.state~="Z" and fresh.group==pid and fresh.session==pid,
            "worker independent session not verified")
        assert(gate_wr:write("G")==1);assert(gate_wr:close());gate_wr=nil
    end)
    -- Before G the child has no mutation permission. EOF on a failed parent's
    -- gate prevents a detached child from starting an unacknowledged worker.
    for _,fd in pairs({ready_rd,ready_wr,gate_rd,gate_wr}) do pcall(fd.close,fd) end
    return ok and pid and pid>1 or false
end
local function native_process(pid)
    local f=io.open("/proc/"..tostring(pid).."/stat","rb");if not f then return nil end
    local body=f:read(4097);assert(f:close());assert(type(body)=="string" and #body<=4096,"worker process stat bound")
    local rest=assert(body:match("^%d+ %(.+%) (.*)$"),"worker process stat shape")
    local fields={};for token in rest:gmatch("%S+") do fields[#fields+1]=token end
    return {start=assert(tonumber(fields[20])),state=fields[1],group=tonumber(fields[3]),session=tonumber(fields[4])}
end
local function native()
    local nx,json=require("nixio"),require("luci.json")
    local q=assert(loadfile(BASE.."/native_quiesce.lua"))()
    local state=assert(loadfile(BASE.."/event_state.lua"))()
    local a=q.native_adapter()
    function a.read_json(path)
        local f=assert(io.open(path,"rb"),"native event journal unavailable")
        local body=f:read(32769);assert(f:close())
        assert(type(body)=="string" and #body<=32768,"native event journal oversized")
        return assert(json.decode(body),"native event journal invalid")
    end
    function a.atomic(path,value)
        local body=assert(json.encode(value));assert(#body<=32768,"own event state oversized")
        local temp=path..".next-"..tostring(nx.getpid())
        local f=assert(nx.open(temp,"w","rw-------"),"own event write unavailable")
        local done=0
        while done<#body do
            local n=assert(f:write(body,done));assert(n>0 and n<=#body-done);done=done+n
        end
        assert(f:sync());assert(f:close());assert(os.rename(temp,path));return true
    end
    function a.identity()
        local id={device_id=a.read("/tmp/sync-cached-DEV_ID"),boot_id=a.read("/proc/sys/kernel/random/boot_id")}
        assert(NODES[id.device_id] and type(id.boot_id)=="string" and #id.boot_id==36,"event identity unavailable")
        return id
    end
    function a.parent(caller_pid)
        local pid=caller_pid or nx.getppid()
        assert(type(pid)=="number" and pid>1 and pid<=4194304
            and (pid==nx.getppid() or pid==nx.getpid()),"native parent invalid")
        local f=assert(io.open("/proc/"..tostring(pid).."/stat","rb"));local body=f:read(4097);assert(f:close())
        assert(type(body)=="string" and #body<=4096,"native parent stat unavailable")
        local rest=assert(body:match("^%d+ %(.+%) (.*)$"),"native parent shape")
        local fields={};for token in rest:gmatch("%S+") do fields[#fields+1]=token end
        return {pid=pid,start=assert(tonumber(fields[20]),"native parent start unavailable")}
    end
    function a.firewall_loaded()
        local c=require("uci").cursor(nil,"/var/state");local value=c:get("firewall","core","loaded");c:unload("firewall")
        return value=="1"
    end
    function a.nonce()
        local value=(a.read("/proc/sys/kernel/random/uuid") or ""):gsub("%-",""):gsub("%s","")
        assert(#value==32 and not value:find("[^%x]"),"native completion nonce unavailable")
        return value
    end
    function a.enqueue()
        -- Fixed worker must exist; its own entrypoint checks empty event state
        -- and a new epoch before touching the kernel. No recursive native reload.
        local f=assert(io.open(BASE.."/worker.lua","rb"),"fixed worker not installed");assert(f:close())
        return spawn_worker(nx,native_process)
    end
    return a,q,state
end
local function under_lock(a,callback)
    local fd;local ok,value=pcall(function()
        fd=a.open_lock();local until_time=a.time()+5;local held=false
        repeat
            if a.try_lock(fd) then held=true;break end
            if a.time()>=until_time then break end;a.sleep()
        until false
        assert(held,"native completion lock busy")
        return callback()
    end)
    local closed=true;if fd then closed=a.close(fd) end
    if not ok or not closed then return false end
    return true,value
end
function M.change(event,entering,adapter,quiesce,state_module,caller_pid)
    assert(EVENTS[event] and type(entering)=="boolean","fixed native event required")
    local a,q,state
    if adapter then a,q,state=adapter,quiesce,state_module else a,q,state=native() end
    local identity=a.identity();local parent=a.parent(caller_pid)
    if entering then
        a.on_locked=function()
            local changed=state.change(a.read_json(BASE.."/active-events.json"),identity,event,parent,true)
            return a.atomic(BASE.."/active-events.json",changed)
        end
        return q.run(event,a)==true
    end
    local ok,should_enqueue=under_lock(a,function()
        local changed=state.change(a.read_json(BASE.."/active-events.json"),identity,event,parent,false)
        assert(a.atomic(BASE.."/active-events.json",changed))
        if not state.empty(changed,identity) then return false end
        -- No other guarded native event may still be destructive. A native
        -- core.loaded1 is required even when the completed event was network.
        if not a.firewall_loaded() then return false end
        local completion_nonce=a.nonce()
        assert(a.atomic(BASE.."/firewall-complete",{schema=1,device_id=identity.device_id,
            boot_id=identity.boot_id,event="firewall",finished=true,source_event=event,
            completion_nonce=completion_nonce,parent_pid=parent.pid,parent_start=parent.start}))
        assert(a.atomic(BASE.."/pending.json",{schema=1,device_id=identity.device_id,
            boot_id=identity.boot_id,event=event,pending=true,completion_nonce=completion_nonce,
            parent_pid=parent.pid,parent_start=parent.start}))
        return true
    end)
    if not ok then return false end
    -- Release the parent event lock before enqueueing: a child worker may then
    -- acquire the lock, and must recheck no newer native event appeared.
    if should_enqueue then return a.enqueue()==true end
    return true
end
M.spawn_worker=spawn_worker -- Dependency injection is used only by own-source fixtures.
return M
