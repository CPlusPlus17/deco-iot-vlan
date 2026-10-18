-- Own fixed read-only getters. Does not construct the kernel adapter, acquire
-- a worker lock, commit UCI, alter interfaces or execute a caller-selected task.
-- Bounded command capture uses only private temporary files owned by its runner.
local M={}
local BASE="/tmp/deco-iot-managed"
local TARGETS={"/lib/wifi/wificommon.sh","/lib/guest-eth/guest-eth.sh","/lib/guest-eth/guest-vlan.sh",
    "/etc/init.d/network","/lib/firewall/core.sh","/usr/lib/lua/luci/model/uci.lua",
    "/usr/lib/lua/luci/controller/admin/mobile_app/wireless.lua","/sbin/wifi","/lib/wifi/wifiupdate.sh"}
local RULES={{"INPUT","-i","br-iot","-j","DROP"},
    {"FORWARD","-i","br-iot","!","-o","br-iot","-j","DROP"},
    {"FORWARD","-o","br-iot","!","-i","br-iot","-j","DROP"}}
local function trim(value) return value and value:match("^%s*(.-)%s*$") end
local function native()
    local nx,json=require("nixio"),require("luci.json")
    local a={uid=nx.getuid,decode=json.decode}
    function a.read(path,limit)
        local f=io.open(path,"rb");if not f then return nil end
        local data=f:read(limit+1);local closed=f:close()
        if data==nil and closed then data="" end
        assert(closed and type(data)=="string" and #data<=limit,"bounded readonly getter failed")
        return data
    end
    function a.time() return assert(tonumber((a.read("/proc/uptime",128) or ""):match("^[%d.]+"))) end
    function a.section(dir,package,name)
        local cursor
        if dir=="/var/state" then cursor=require("uci").cursor(nil,dir)
        else cursor=require("uci").cursor(dir) end
        local section=cursor:get_all(package,name);cursor:unload(package)
        return section
    end
    local bounded
    function a.command(argv)
        if not bounded then
            local nonce=(a.read("/proc/sys/kernel/random/uuid",128) or ""):gsub("%-",""):gsub("%s","")
            assert(#nonce==32 and not nonce:find("[^%x]"),"query nonce unavailable")
            bounded=assert(loadfile(BASE.."/bounded_command.lua"))().new({base=BASE,nonce=nonce})
        end
        local data,code=bounded:command(argv)
        assert(type(data)=="string" and #data<=4096 and type(code)=="number","bounded readonly command failed")
        return data,code
    end
    function a.verify_network(state)
        local adapter=assert(loadfile(BASE.."/native_adapter.lua"))().new({read_section=a.section})
        return adapter.verify_registered_network({state=state})==true
    end
    function a.read_policy(section)
        return assert(loadfile(BASE.."/declarative_policy.lua"))().read(section)
    end
    function a.events_empty(current,identity)
        return assert(loadfile(BASE.."/event_state.lua"))().empty(current,identity)
    end
    return a
end
local function json_file(a,path,limit)
    local raw=a.read(path,limit)
    if not raw then return nil end
    local ok,value=pcall(a.decode,raw)
    if ok and type(value)=="table" then return value end
    return nil
end
local function ports(value)
    local seen={};local count=0
    for p in (value or ""):gmatch("%S+") do
        if (p~="2t" and p~="6t") or seen[p] then return nil end
        count=count+1;seen[p]=true
    end
    return count==2 and "2t 6t" or nil
end
function M.collect(operation,adapter)
    assert(operation=="ready" or operation=="own_vlan" or operation=="own_network" or operation=="preserve_vlan","unknown fixed observation")
    local a=adapter or native();local started=a.time()
    local function read(path,limit) return trim(a.read(path,limit or 128)) end
    local function command(argv)
        assert(a.time()-started<18,"readonly hook query time budget")
        return a.command(argv)
    end
    local s={uid=a.uid(),device_id=read("/tmp/sync-cached-DEV_ID"),boot_id=read("/proc/sys/kernel/random/boot_id"),
        installation=json_file(a,BASE.."/installation.json",32768),state=json_file(a,BASE.."/state.json",32768)}
    s.resources={bridge_index=tonumber(read("/sys/class/net/br-iot/ifindex")),
        vlan_index=tonumber(read("/sys/class/net/eth1.30/ifindex")),
        private_bridge_id=read("/sys/class/net/br-iot/bridge/bridge_id"),
        vlan_master_bridge_id=read("/sys/class/net/eth1.30/master/bridge/bridge_id")}
    local shape=a.read("/proc/net/vlan/eth1.30",4096) or ""
    s.resources.vlan_id=tonumber(shape:match("VID:%s*(%d+)%s"))
    s.resources.vlan_parent=shape:match("Device:%s*([%w_.:-]+)")
    if operation=="own_vlan" then return s end
    if operation=="own_network" then
        local ok,registered=pcall(a.verify_network,s.state);s.network_registered=ok and registered==true
        return s
    end
    local row=a.section("/etc/vlan.d","vlan","deco_iot")
    if type(row)=="table" then
        local valid=true
        for key in pairs(row) do
            if key:sub(1,1)~="." and key~="device" and key~="vlan" and key~="vid" and key~="ports" then valid=false end
        end
        if valid then s.load_section={name=row[".name"],type=row[".type"],device=row.device,vlan=row.vlan,vid=row.vid,ports=ports(row.ports)} end
    end
    if operation=="preserve_vlan" then return s end
    s.policy=a.read_policy(a.section(nil,"deco_iot_vlan","iot"))
    local iot=a.section(nil,"iot_wifi","iot")
    s.native_iot_enable=type(iot)=="table" and iot.enable or nil
    local mode=a.section(nil,"sysmode","sysmode");s.mode=type(mode)=="table" and mode.mode or nil
    s.firmware_verified=read("/tmp/sync-cached-MODEL",256)=="XE75Pro"
        and read("/tmp/sync-cached-HARDVERSION",256)=="3.0"
        and read("/tmp/sync-cached-SOFTVERSION",512)=="1.5.0 Build 20260603 Rel. 15804"
    s.epoch=read(BASE.."/epoch",64);s.ready=json_file(a,BASE.."/ready.json",8192)
    s.native_events_empty=a.events_empty(json_file(a,BASE.."/active-events.json",32768),s)==true
    local data,code=command({"/sbin/swconfig","dev","switch1","vlan","30","get","ports"})
    s.tagged_ports=code==0 and ports(data) or nil
    for _,item in ipairs({{6,"cpu_pvid"},{2,"uplink_pvid"}}) do
        data,code=command({"/sbin/swconfig","dev","switch1","port",tostring(item[1]),"get","pvid"})
        s[item[2]]=code==0 and tonumber(trim(data)) or nil
    end
    local link=tonumber(read("/proc/rtk_gsw/phylink"));s.wired_p2_live=link and math.floor(link/4)%2==1 or false
    local rules=true
    for _,binary in ipairs({"/usr/sbin/iptables","/usr/sbin/ip6tables"}) do
        for _,rule in ipairs(RULES) do
            local argv={binary,"-w","-C"};for _,item in ipairs(rule) do argv[#argv+1]=item end
            local _,status=command(argv)
            if status~=0 then rules=false end
        end
    end
    s.firewall_rules_verified=rules
    local addresses,address_code=command({"/usr/sbin/ip","addr","show","dev","br-iot"})
    s.resources.no_local_address=address_code==0 and not addresses:find("inet ",1,true)
        and not addresses:find("inet6 ",1,true)
    local flags=tonumber(read("/sys/class/net/br-iot/flags"));s.resources.bridge_up=flags and flags%2==1 or false
    flags=tonumber(read("/sys/class/net/eth1.30/flags"));s.resources.vlan_up=flags and flags%2==1 or false
    s.resources.ipv6_disabled=read("/proc/sys/net/ipv6/conf/br-iot/disable_ipv6")=="1"
    s.resources.arp_ignored=read("/proc/sys/net/ipv4/conf/br-iot/arp_ignore")=="1"
    local ok,registered=pcall(a.verify_network,s.state);s.network_registered=ok and registered==true
    local complete=json_file(a,BASE.."/firewall-complete",2048)
    local cursor=a.section("/var/state","firewall","core")
    s.firewall_finished=type(complete)=="table" and complete.schema==1 and complete.finished==true
        and complete.event=="firewall" and complete.device_id==s.device_id and complete.boot_id==s.boot_id
        and type(cursor)=="table" and cursor.loaded=="1" or false
    local hashes=type(s.installation)=="table" and s.installation.hook_sha1 or nil
    local expected_count=0
    if type(hashes)=="table" then for _ in pairs(hashes) do expected_count=expected_count+1 end end
    s.hooks_verified=false
    if expected_count==#TARGETS then
        local argv={"/bin/busybox","sha1sum"};local expected=true
        for _,path in ipairs(TARGETS) do
            local value=hashes[path]
            if type(value)~="string" or #value~=40 or value:find("[^0-9a-f]") then expected=false end
            argv[#argv+1]=path
        end
        if expected then
            data,code=command(argv)
            if code==0 then
                local seen={};local count=0;local valid=true
                for line in data:gmatch("[^\r\n]+") do
                    local digest,path=line:match("^(%x+)  (/.+)$")
                    if not path or seen[path] or hashes[path]~=digest then valid=false else seen[path]=true;count=count+1 end
                end
                s.hooks_verified=valid and count==#TARGETS
            end
        end
    end
    assert(read("/tmp/sync-cached-DEV_ID")==s.device_id and read("/proc/sys/kernel/random/boot_id")==s.boot_id,
        "identity changed during readonly query")
    if read(BASE.."/epoch",64)~=s.epoch then s.epoch=nil end
    assert(a.time()-started<=20,"readonly hook query exceeded deadline")
    return s
end
return M
