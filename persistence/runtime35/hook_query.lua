-- Fixed read-only CLI for native shell hooks. No payload is printed.
local BASE="/tmp/deco-iot-managed"
local function cold_switch_load(caller)
    local nx,fs,json=require("nixio"),require("nixio.fs"),require("luci.json")
    local function trim(s) return s and s:match("^%s*(.-)%s*$") end
    local function int(n,hi) return type(n)=="number" and n%1==0 and n>=1 and n<=(hi or 2147483647) end
    local function hex(v,n) return type(v)=="string" and #v==n and not v:find("[^0-9a-f]") end
    local function same(a,b) return a and b and a.type==b.type and a.uid==b.uid and a.gid==b.gid
        and a.dev==b.dev and a.ino==b.ino and a.nlink==b.nlink and a.size==b.size and a.modestr==b.modestr end
    local function plain(path)
        local target,code=fs.readlink(path)
        assert(target==nil and code==22,"cold path link or unknown")
        return assert(fs.stat(path),"cold path unavailable")
    end
    local function read(path,limit,private)
        local before=plain(path)
        assert(before.type=="reg" and before.uid==0 and before.gid==0 and before.nlink==1
            and (not private or before.modestr=="rw-------"),"cold file ownership")
        local fd=assert(nx.open(path,nx.open_flags("rdonly","nonblock")+32768),"cold file open")
        local ok,body=pcall(function()
            assert(same(before,fd:stat()),"cold read inode changed")
            local chunks,total={},0
            repeat
                local n=math.min(8192,limit+1-total);assert(n>=1,"cold read bound")
                local part=fd:read(n);assert(type(part)=="string" and #part<=n,"cold read failed")
                if #part==0 then break end
                total=total+#part;assert(total<=limit,"cold read bound");chunks[#chunks+1]=part
            until false
            assert(same(before,fd:stat()) and same(before,plain(path)),"cold read changed")
            return table.concat(chunks)
        end)
        local closed,value=pcall(fd.close,fd)
        assert(ok and closed and value==true,"cold read or close failed")
        return body
    end
    local function absent(path)
        -- Exact nixio API: nil, numeric errno, message. UNKNOWN is denied.
        local value,code=fs.stat(path);local link,link_code=fs.readlink(path)
        assert(value==nil and code==2 and link==nil and link_code==2,"cold resource present or unknown")
    end
    local function process(pid)
        local raw=read("/proc/"..tostring(pid).."/stat",4096)
        local found,_,rest=raw:match("^(%d+) %((.*)%) (.*)$")
        assert(found==tostring(pid),"cold caller stat shape")
        local fields={};for word in rest:gmatch("%S+") do fields[#fields+1]=word end
        local start=tonumber(fields[20])
        assert(#fields>=20 and #fields<=64 and fields[1]:match("^[RSDTtKWPI]$")
            and int(start) and tostring(start)==fields[20],"cold caller not live")
        return start
    end
    local function decode(path,limit) return assert(json.decode(read(path,limit,true)),"cold JSON invalid") end
    local started=tonumber(trim(read("/proc/uptime",128)):match("^[%d.]+"))
    assert(started and nx.getuid()==0 and int(caller,4194304) and caller>1
        and caller==nx.getppid(),"cold native parent required")
    local base=plain(BASE)
    assert(base.type=="dir" and base.uid==0 and base.gid==0 and base.modestr=="rwx------","cold private base")
    local lock_path=BASE.."/worker.lock";local before=plain(lock_path)
    assert(before.type=="reg" and before.uid==0 and before.gid==0 and before.nlink==1,"cold lock ownership")
    local fd=assert(nx.open(lock_path,nx.open_flags("rdwr","nonblock")+32768),"cold lock open")
    local ok,accepted=pcall(function()
        assert(same(before,fd:stat()) and same(before,plain(lock_path)),"cold lock inode changed")
        assert(fd:lock("tlock")==true,"cold worker busy")
        local install=assert(loadfile(BASE.."/runtime_install.lua"))()
        local policy_module=assert(loadfile(BASE.."/declarative_policy.lua"))()
        local actor_start
        local originals={}
        local function context()
            assert(nx.getuid()==0 and caller==nx.getppid(),"cold parent changed")
            local id=trim(read("/tmp/sync-cached-DEV_ID",128))
            local boot=trim(read("/proc/sys/kernel/random/boot_id",128))
            assert(type(boot)=="string" and boot:match("^%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x$"),"cold boot invalid")
            local manifest=install.validate(decode(BASE.."/installation.json",32768))
            assert(manifest.device_id==id and manifest.boot_id==boot and manifest.committed==true
                and manifest.all_three_generation_committed==true and manifest.ram_guards_installed==true,"cold installation binding")
            local cursor=require("uci").cursor()
            local policy=policy_module.read(cursor:get_all("deco_iot_vlan","iot"))
            assert(policy.configured==true and policy.valid==true and type(policy.enabled)=="boolean"
                and policy.generation==manifest.generation and cursor:get("iot_wifi","iot","enable")=="0"
                and cursor:get("sysmode","sysmode","mode")=="AP","cold native policy")
            for _,package in ipairs({"deco_iot_vlan","iot_wifi","sysmode"}) do cursor:unload(package) end
            local policy_key=tostring(policy.enabled)..":"..tostring(policy.generation)
            assert(not originals.policy or originals.policy==policy_key,"cold policy changed");originals.policy=policy_key
            assert(trim(read("/tmp/sync-cached-MODEL",256))=="XE75Pro"
                and trim(read("/tmp/sync-cached-HARDVERSION",256))=="3.0"
                and trim(read("/tmp/sync-cached-SOFTVERSION",512))=="1.5.0 Build 20260603 Rel. 15804","cold firmware")
            local parent=decode(BASE.."/boot-parent.json",2048)
            assert(parent.schema==1 and parent.device_id==id and parent.boot_id==boot and int(parent.pid,4194304)
                and parent.pid>1 and int(parent.start) and (parent.loaded_before=="unset" or parent.loaded_before=="0"),"cold boot parent")
            local fresh=process(caller);assert(not actor_start or actor_start==fresh,"cold parent reused");actor_start=fresh
            local raw=read(BASE.."/active-events.json",32768,true);local events=assert(json.decode(raw))
            assert(events.schema==1 and events.device_id==id and events.boot_id==boot and type(events.entries)=="table","cold events binding")
            local count=0;local found=false
            for key,row in pairs(events.entries) do
                count=count+1;assert(count<=128 and type(row)=="table" and ({guest=true,network=true,firewall=true,wifi=true})[row.event]
                    and int(row.pid,4194304) and row.pid>1 and int(row.start) and int(row.count,64)
                    and key==row.event..":"..tostring(row.pid)..":"..tostring(row.start),"cold event malformed")
                local fields=0;for name in pairs(row) do assert(({event=true,pid=true,start=true,count=true})[name],"cold event field");fields=fields+1 end
                assert(fields==4,"cold event fields")
                if row.event=="guest" and row.pid==caller and row.start==actor_start then found=true end
            end
            assert(found,"cold active guest caller required")
            for _,name in ipairs({"installation.json","boot-parent.json","active-events.json"}) do
                local value=read(BASE.."/"..name,32768,true)
                assert(not originals[name] or originals[name]==value,"cold context changed");originals[name]=value
            end
            for _,path in ipairs({BASE.."/state.json",BASE.."/ready.json",BASE.."/epoch",
                "/sys/class/net/br-iot","/sys/class/net/eth1.30","/proc/net/vlan/eth1.30"}) do absent(path) end
            assert(same(base,plain(BASE)) and same(before,fd:stat()) and same(before,plain(lock_path)),"cold lock context changed")
            return manifest
        end
        local manifest=context()
        -- Reuse the installed exact-child/reaping hasher; no timeout watchdog.
        local io=install.new(manifest).io
        for _,name in ipairs({"native_hooks.sh","hook_query.lua","runtime_install.lua",
            "declarative_policy.lua","observe_owned_state.lua","hook_decision.lua","bounded_command.lua"}) do
            assert(io.hash(BASE.."/"..name)==manifest.files[name].sha1,"cold source changed")
        end
        local function vlan_empty()
            local c=require("uci").cursor("/etc/vlan.d")
            local good,value=pcall(function()
                assert(c:load("vlan")==true,"cold VLAN package unavailable")
                local rows=c:get_all("vlan")
                assert(type(rows)=="table","cold VLAN enumeration failed")
                local found=false
                for name,row in pairs(rows) do
                    found=true
                    assert(type(name)=="string" and type(row)=="table" and row[".name"]==name
                        and type(row[".type"])=="string" and type(row[".anonymous"])=="boolean"
                        and type(row[".index"])=="number" and row[".index"]%1==0 and row[".index"]>=0,
                        "cold VLAN section malformed")
                    assert(name~="deco_iot","cold owned section present")
                    if row[".type"]=="switch_vlan" then
                        assert(type(row.device)=="string","cold switch device unknown")
                        if row.device=="switch1" then
                            assert(type(row.vlan)=="string" and row.vlan:match("^%d+$")
                                and type(row.vid)=="string" and row.vid:match("^%d+$")
                                and tonumber(row.vlan)~=30 and tonumber(row.vid)~=30,"cold foreign or unknown VID30 section")
                        end
                    end
                end
                assert(found,"cold VLAN enumeration failed")
                return true
            end)
            local unloaded,result=pcall(c.unload,c,"vlan")
            assert(good and value and unloaded and result~=false,"cold VLAN query failed")
        end
        vlan_empty()
        local nonce=trim(read("/proc/sys/kernel/random/uuid",128)):gsub("%-","")
        assert(hex(nonce,32),"cold query nonce")
        local bounded=assert(loadfile(BASE.."/bounded_command.lua"))().new({base=BASE,nonce=nonce})
        local body,code=bounded:command({"/sbin/swconfig","dev","switch1","vlan","30","get","ports"})
        assert(type(body)=="string" and #body<=4096 and code==0 and trim(body)=="","cold hardware VID30 not empty")
        vlan_empty();context()
        assert(tonumber(trim(read("/proc/uptime",128)):match("^[%d.]+"))-started<=20,"cold query deadline")
        return true
    end)
    local closed,value=pcall(fd.close,fd)
    return ok and accepted==true and closed and value==true
end
local operation=arg and arg[1]
if operation=="cold_switch_load" then
    local caller=arg and arg[2] and arg[2]:match("^[1-9]%d*$") and tonumber(arg[2])
    if not (arg and #arg==2 and caller and tostring(caller)==arg[2]) then os.exit(2) end
    local ok,accepted=pcall(cold_switch_load,caller)
    os.exit(ok and accepted and 0 or 1)
end
if not (arg and #arg==1 and (operation=="ready" or operation=="own_vlan" or operation=="own_network" or operation=="preserve_vlan")) then os.exit(2) end
local ok,accepted=pcall(function()
    local observe=assert(loadfile(BASE.."/observe_owned_state.lua"))()
    local decision=assert(loadfile(BASE.."/hook_decision.lua"))()
    return decision.evaluate(operation,observe.collect(operation))==true
end)
os.exit(ok and accepted and 0 or 1)
