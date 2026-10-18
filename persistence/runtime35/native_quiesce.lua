-- Own fixed quiesce barrier shared by native reload hooks and the worker.
-- No normal worker constructor is entered: cancellation must work even when
-- the desired policy is invalid. Mock I/O is only for local own-source tests.
local M={}
local BASE="/tmp/deco-iot-managed"
local EVENTS={guest=true,network=true,firewall=true,wifi=true}
local function trim(s) return s and s:match("^%s*(.-)%s*$") end
local function native()
    local nx,fs=require("nixio"),require("nixio.fs")
    local a={uid=nx.getuid}
    function a.read(path)
        local f=io.open(path,"rb");if not f then return nil end
        local body=f:read(129);local closed=f:close()
        assert(closed and type(body)=="string" and #body<=128,"bounded quiesce read")
        return trim(body)
    end
    function a.remove(path)
        if os.remove(path) then return true end
        return fs.stat(path)==nil
    end
    function a.exists(path) return fs.stat(path)~=nil end
    function a.time() return assert(tonumber((a.read("/proc/uptime") or ""):match("^[%d.]+"))) end
    function a.sleep() assert(nx.nanosleep(0,50000000)) end
    local bounded
    function a.command(argv)
        if not bounded then
            local nonce=(a.read("/proc/sys/kernel/random/uuid") or ""):gsub("%-",""):gsub("%s","")
            assert(#nonce==32 and not nonce:find("[^%x]"),"quiesce nonce unavailable")
            bounded=assert(loadfile(BASE.."/bounded_command.lua"))().new({base=BASE,nonce=nonce})
        end
        local body,code=bounded:command(argv)
        assert(type(body)=="string" and #body<=256,"bounded quiesce output")
        return trim(body),code
    end
    function a.open_lock()
        local body,code=a.command({"/bin/busybox","stat","-c","%A|%u|%g",BASE})
        assert(code==0 and body=="drwx------|0|0","private runtime base required")
        assert(not fs.readlink(BASE.."/worker.lock"),"worker lock may not be a link")
        local fd=assert(nx.open(BASE.."/worker.lock","w","rw-------"),"worker lock open")
        local info=assert(fd:stat(),"worker lock fstat")
        local path=assert(fs.stat(BASE.."/worker.lock"),"worker lock path stat")
        assert(info.type=="reg" and info.uid==0 and info.ino==path.ino and info.dev==path.dev,"worker lock identity")
        return fd
    end
    function a.try_lock(fd) return fd:lock("tlock")==true end
    function a.close(fd) return fd:close()==true end
    return a
end
function M.run(event,adapter)
    assert(EVENTS[event],"unknown fixed quiesce event")
    local a=adapter or native()
    assert(a.uid()==0,"root required")
    -- Invalidate in-flight worker checkpoints BEFORE waiting on its lock.
    local revoke={"epoch","ready.json"}
    if a.preserve_complete~=true then revoke[#revoke+1]="firewall-complete" end
    for _,path in ipairs(revoke) do
        assert(a.remove(BASE.."/"..path),"cancellation revoke failed")
    end
    local fd
    local ok,why=pcall(function()
        fd=a.open_lock()
        local until_time=a.time()+5
        local locked=false
        repeat
            if a.try_lock(fd) then locked=true;break end
            if a.time()>=until_time then break end
            a.sleep()
        until false
        assert(locked,"worker quiesce timeout")
        -- A queued worker could have published another epoch while this caller
        -- waited for the lock. Revoke AGAIN under the barrier before down.
        for _,path in ipairs(revoke) do assert(a.remove(BASE.."/"..path),"locked cancellation revoke failed") end
        -- After acquiring the same process-owned lock, an older worker cannot
        -- still be inside a normal mutation. Keep the lock through down+check.
        for _,name in ipairs({"ath08","ath18"}) do
            if a.exists("/sys/class/net/"..name.."/ifindex") then
                local kind,code=a.command({"/sbin/uci","-q","get","wireless."..name..".type"})
                assert(code==0 and kind=="iot","native VAP type changed")
                local _,status=a.command({"/bin/busybox","ifconfig",name,"down"})
                local flags=tonumber(a.read("/sys/class/net/"..name.."/flags"))
                assert(status==0 and flags and flags%2==0,"IoT down verification failed")
            end
        end
        if a.on_locked then assert(a.on_locked(event)==true,"native event journal failed") end
    end)
    local closed=true
    if fd then closed=a.close(fd) end
    -- A timeout/error must abort the caller's destructive reset/flush. Do not
    -- turn a best-effort down into a successful synchronization barrier.
    return ok and closed,ok and closed and nil or "quiesce_barrier_failed"
end
-- Only the reviewed event broker uses this to acquire the SAME lock for its
-- completion journal. No path or command is accepted from the native hook CLI.
M.native_adapter=native
return M
