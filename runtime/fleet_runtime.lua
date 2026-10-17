-- Fixed, temporary all-three IoT30 phases. Host supplies reviewed immutable PLAN.
-- MODE/BASE/NONCE/PLAN precede this source; stage additionally supplies this
-- exact own RUNTIME_SOURCE. No service reload, UCI write or persistence exists.
local nx=require("nixio")
local fs=require("nixio.fs")
local json=require("luci.json")
local sp=require("luci.model.subprocess")
local BB,SW,BR,IP="/bin/busybox","/sbin/swconfig","/usr/sbin/brctl","/usr/sbin/ip"
local ACTIVE="/tmp/deco-iot-trial-active"
local VAPS={"ath08","ath18"}
local ATTRS={"path_cost","priority","hairpin_mode","guard","root_block","fastleave","learning","unicast_flood","proxyarp","proxyarp_wifi","multicast_router","multicast_flood","broadcast_flood","neigh_suppress","isolated"}
local RULES={
    {"INPUT","-i","br-iot","-j","DROP"},
    {"FORWARD","-i","br-iot","!","-o","br-iot","-j","DROP"},
    {"FORWARD","-o","br-iot","!","-i","br-iot","-j","DROP"}}
local function read(path)
    local f=io.open(path,"rb");if not f then return nil end
    local body=f:read("*a");f:close();return body
end
local function write(path,body)
    local f=assert(io.open(path,"wb"),"open failed")
    assert(f:write(body),"write failed");assert(f:close(),"close failed")
end
local function trim(v) return v and v:match("^%s*(.-)%s*$") end
local function uptime() return assert(tonumber((read("/proc/uptime") or ""):match("^[%d.]+")),"uptime unavailable") end
local function process(pid)
    local value=read("/proc/"..tostring(pid).."/stat");if not value then return nil end
    local name,rest=value:match("^%d+ %((.*)%) (.*)$");if not rest then return nil end
    local a={};for v in rest:gmatch("%S+") do a[#a+1]=v end
    return {pid=pid,name=name,state=a[1],ppid=tonumber(a[2]),start=tonumber(a[20])}
end
local function same_process(p)
    local now=p and process(p.pid)
    return now and now.start==p.start and now.name==p.name and now.state~="Z" and now
end
local function same(a,b,depth)
    if type(a)~=type(b) then return false end
    if type(a)~="table" then return a==b end
    depth=(depth or 0)+1;assert(depth<10,"plan depth invalid")
    for k,v in pairs(a) do if not same(v,b[k],depth) then return false end end
    for k in pairs(b) do if a[k]==nil then return false end end
    return true
end
local function context()
    assert(nx.getuid()==0,"root required")
    assert(trim(read("/tmp/sync-cached-DEV_ID")):upper()==PLAN.device_id:upper(),"device identity changed")
    assert(trim(read("/proc/sys/kernel/random/boot_id"))==PLAN.boot_id,"device boot changed")
end
assert(type(NONCE)=="string" and #NONCE==32 and NONCE:match("^[0-9a-f]+$"),"nonce invalid")
assert(type(BASE)=="string" and #BASE<=128 and BASE:match("^/tmp/deco%-[%w_%-]+$") and BASE:find(NONCE,1,true),"base invalid")
assert(type(PLAN)=="table" and type(PLAN.device_id)=="string" and #PLAN.device_id==40 and PLAN.device_id:match("^[%x]+$"),"plan identity invalid")
assert(type(PLAN.boot_id)=="string" and #PLAN.boot_id==36 and PLAN.boot_id:match("^[%x%-]+$"),"plan boot invalid")
assert(type(PLAN.management_ipv4)=="string" and PLAN.management_ipv4:match("^%d+%.%d+%.%d+%.%d+$"),"management address invalid")
assert(PLAN.gateway=="192.168.68.254" and PLAN.uplink_bridge_port==5 and PLAN.uplink_vlan_device=="eth1.4" and PLAN.tagged_ports=="2t 6t","unsupported fixed trunk plan")
assert(type(PLAN.test_client_mac)=="string" and PLAN.test_client_mac:match("^%x%x:%x%x:%x%x:%x%x:%x%x:%x%x$"),"pinned client required")
assert(type(PLAN.deadline)=="number" and PLAN.deadline==math.floor(PLAN.deadline),"integer deadline required")
for _,v in ipairs({"2","3","4","500"}) do assert(type(PLAN.old_vlans)=="table" and type(PLAN.old_vlans[v])=="string","old VLAN plan invalid") end
for _,v in ipairs({"0","1","2","6"}) do assert(type(PLAN.old_pvids)=="table" and type(PLAN.old_pvids[v])=="string" and PLAN.old_pvids[v]:match("^%d+$"),"old PVID plan invalid") end
assert(tonumber(PLAN.old_pvids["2"])>0 and tonumber(PLAN.old_pvids["6"])>0,"zero selected PVID forbidden")
context()

-- STATION_PARSER_START
-- Own parser for exact-release wlanconfig list sta output. No I/O or commands.
-- Native unsigned-byte powers/opclasses, signed-byte SNR, 44 7-bit rates;
-- supported classes/channels are conditional, and every other footer is fixed.
local function parse_stations(output)
    local function fail(reason) return {parsed=false,count=0,macs={},error=reason} end
    if type(output)~="string" or #output==0 or #output>8192 then return fail("size") end
    output=output:gsub("\r\n","\n")
    if output:sub(-1)~="\n" or output:find("[^\t\n\032-\126]") then return fail("encoding_or_truncation") end
    local lines={}
    for line in output:gmatch("([^\n]*)\n") do
        if #line>1024 or #lines>=512 then return fail("line_bound") end
        lines[#lines+1]=line
    end
    local function trim(value) return value and value:match("^%s*(.-)%s*$") end
    local header="ADDR AID CHAN TXRATE RXRATE RSSI MINRSSI MAXRSSI IDLE TXSEQ RXSEQ CAPS XCAPS ACAPS ERP STATE MAXRATE(DOT11) HTCAPS VHTCAPS ASSOCTIME IEs MODE RXNSS TXNSS PSMODE"
    if trim(lines[1]):gsub("%s+"," ")~=header then return fail("header") end
    local modes={}
    for suffix in ("AUTO 11A 11B 11G FH TURBO_A TURBO_G 11NA_HT20 11NG_HT20 "..
        "11NA_HT40PLUS 11NA_HT40MINUS 11NG_HT40PLUS 11NG_HT40MINUS 11NG_HT40 11NA_HT40 "..
        "11AC_VHT20 11AC_VHT40PLUS 11AC_VHT40MINUS 11AC_VHT40 11AC_VHT80 11AC_VHT160 11AC_VHT80_80 "..
        "11AXA_HE20 11AXG_HE20 11AXA_HE40PLUS 11AXA_HE40MINUS 11AXG_HE40PLUS 11AXG_HE40MINUS "..
        "11AXA_HE40 11AXG_HE40 11AXA_HE80 11AXA_HE160 11AXA_HE80_80"):gmatch("%S+") do
        modes["IEEE80211_MODE_"..suffix]=true
    end
    local function integer(value,minimum,maximum)
        if not value or not value:match("^%-?%d+$") or #value>10 then return nil end
        local number=tonumber(value)
        return number and number>=minimum and number<=maximum and number or nil
    end
    local function numbers(value,minimum,maximum,limit)
        if not value or value:find("[^%d%s]") then return false end
        local count=0
        for token in value:gmatch("%S+") do
            count=count+1
            if count>limit or not integer(token,minimum,maximum) then return false end
        end
        return true
    end
    local at=2
    local function value(label)
        local line=lines[at]
        if not line then return nil end
        local found=trim(line):match("^"..label.."%s*:%s*(.-)%s*$")
        if found~=nil then at=at+1 end
        return found
    end
    local out={parsed=false,count=0,macs={}}
    while at<=#lines do
        if out.count>=32 then return fail("station_bound") end
        local address,aid,channel,txrate,rxrate,rest=lines[at]:match(
            "^%s*(%x%x:%x%x:%x%x:%x%x:%x%x:%x%x)%s+(%d+)%s+(%d+)%s+(%d+)M%s+(%d+)M%s+(.+)$")
        if not address or not integer(aid,1,2007) or not integer(channel,1,233)
            or not integer(txrate,0,100000) or not integer(rxrate,0,100000) then return fail("station_row") end
        address=address:lower()
        if out.macs[address] or address=="00:00:00:00:00:00"
            or tonumber(address:sub(1,2),16)%2~=0 then return fail("station_address") end
        local rowmode,rxnss,txnss,psmode=rest:match("%s+(IEEE80211_MODE_[%w_]+)%s+(%d+)%s+(%d+)%s+(%d+)%s*$")
        local minutes,seconds=rest:match("%s+%d+:(%d%d):(%d%d)%s+")
        if not modes[rowmode] or not integer(rxnss,1,8) or not integer(txnss,1,8)
            or not integer(psmode,0,1) or not integer(minutes,0,59) or not integer(seconds,0,59) then return fail("station_fields") end
        at=at+1
        -- Ordered subset generated from the seven native radio-measurement bits.
        local flags=lines[at]
        if flags==nil then return fail("footer_truncated") end
        local order={LM=1,NR=2,BRP=3,BRA=4,BRT=5,LCIM=6,FTMRR=7}
        local prior=0
        for flag in flags:gmatch("%S+") do
            local index=order[flag]
            if not index or index<=prior then return fail("measurement_flags") end
            prior=index
        end
        at=at+1
        if trim(lines[at])~="RSSI is combined over chains in dBm" then return fail("rssi_note") end
        at=at+1
        local minimum=integer(value("Minimum Tx Power"),0,255)
        local maximum=integer(value("Maximum Tx Power"),0,255)
        if not minimum or not maximum or minimum>maximum then return fail("tx_power") end
        for _,label in ipairs({"HT Capability","VHT Capability","MU capable"}) do
            local flag=value(label)
            if flag~="Yes" and flag~="No" then return fail("capability") end
        end
        if not integer(value("SNR"),-128,127) then return fail("snr") end
        local band=value("Operating band")
        if band~="2.4GHz" and band~="5GHz" and band~="6GHz" then return fail("band") end
        if not integer(value("Current Operating class"),0,255) then return fail("operating_class") end
        local classes=value("Supported Operating classes")
        if classes~=nil and not numbers(classes,1,255,255) then return fail("operating_class_list") end
        if not numbers(value("Supported Rates"),0,127,44) then return fail("rates") end
        local channels=value("Channels supported")
        if channels~=nil then
            local low,high=2400,2500
            if band=="5GHz" then low,high=4900,5900 elseif band=="6GHz" then low,high=5900,7200 end
            if channels=="" or not numbers(channels,low,high,255) then return fail("channel_frequencies") end
        end
        if not modes[value("Max STA phymode")] then return fail("maximum_mode") end
        out.macs[address]=true
        out.count=out.count+1
    end
    out.parsed=true
    return out
end
-- STATION_PARSER_END

local CURRENT,IN_ROLLBACK
local function state_save(state)
    write(BASE.."/state.next",json.encode(state));assert(os.rename(BASE.."/state.next",BASE.."/state.json"))
end
local function state_load()
    local state=json.decode(assert(read(BASE.."/state.json"),"state unavailable"))
    assert(state.nonce==NONCE and state.node_id==PLAN.device_id and same(state.plan,PLAN),"journal binding changed")
    assert(state.deadline==PLAN.deadline,"journal deadline changed")
    return state
end
local function guard()
    if CURRENT and not IN_ROLLBACK then
        assert(not read(BASE.."/abort") and not read(BASE.."/done.json") and uptime()<CURRENT.deadline,"trial expired")
    end
end
local function run(argv)
    guard()
    local pid=assert(sp.exec(argv),"utility start failed")
    local child=process(pid)
    if child then child.exec_name=argv[1]:match("([^/]+)$"):sub(1,15) end
    if CURRENT and not IN_ROLLBACK then
        CURRENT.active_child=child
        if not pcall(state_save,CURRENT) then
            nx.kill(pid,9);nx.waitpid(pid);CURRENT.active_child=nil;error("mutator journal failed")
        end
    end
    local started=uptime()
    while true do
        local waited,reason,code=nx.waitpid(pid,"nohang")
        if waited and waited>0 then
            if CURRENT and not IN_ROLLBACK then CURRENT.active_child=nil;state_save(CURRENT) end
            assert(reason=="exited" and code==0,"fixed command failed");guard();return
        end
        if uptime()-started>=5 or (CURRENT and not IN_ROLLBACK and (read(BASE.."/abort") or uptime()>=CURRENT.deadline)) then
            local now=process(pid)
            if child and now and now.start==child.start then nx.kill(pid,9) end
            nx.waitpid(pid);error("fixed command timed out")
        end
        nx.nanosleep(0,50000000)
    end
end
local function cmd(argv)
    local body,code=sp.call_output(argv);assert(code==0,"fixed read failed");return body or ""
end
local function sw(args)
    local argv={SW,"dev","switch1"};for _,v in ipairs(args) do argv[#argv+1]=v end
    return trim(cmd(argv))
end
local function ports(vid) return sw({"vlan",tostring(vid),"get","ports"}):gsub("%s+"," ") end
local function ifindex(name) return tonumber(read("/sys/class/net/"..name.."/ifindex")) end
local function bridge(name) return read("/sys/class/net/"..name.."/bridge/bridge_id") end
local function master(name) return read("/sys/class/net/"..name.."/master/bridge/bridge_id") end
local function is_vap(name) return name=="ath08" or name=="ath18" end
local function members()
    local out={};local count=0
    for name in fs.dir("/sys/class/net/br-lan/brif") do
        if name~="." and name~=".." then
            assert(#name<=15 and name:match("^[%w_.:-]+$"),"bridge member invalid")
            count=count+1;assert(count<=32,"bridge member limit")
            out[name]=assert(ifindex(name),"bridge member disappeared")
        end
    end
    return out
end
local function old_ports_unchanged(state)
    for vid,value in pairs(state.old_vlans) do assert(ports(tonumber(vid))==value,"existing VLAN changed") end
    for port,value in pairs(state.old_pvids) do assert(sw({"port",port,"get","pvid"})==value,"existing PVID changed") end
end
local function main_unchanged(state)
    context()
    assert(bridge("br-lan")==state.main_bridge_id,"main bridge changed")
    assert(cmd({IP,"addr","show","dev","br-lan"})==state.main_addresses,"main addresses changed")
    assert(cmd({IP,"route","show","default"})==state.main_routes,"main routes changed")
    local actual=members()
    for name,index in pairs(state.main_members) do
        if not is_vap(name) then assert(actual[name]==index and master(name)==state.main_bridge_id,"main member changed") end
    end
    for name,index in pairs(actual) do assert(state.main_members[name]==index,"foreign main member") end
    old_ports_unchanged(state)
end
local function stations()
    local count=0
    for _,name in ipairs(VAPS) do
        local text=cmd({"/usr/sbin/wlanconfig",name,"list","sta"})
        assert(#text<=8192,"station table truncated")
        local parsed=parse_stations(text)
        assert(parsed.parsed,"unknown station format")
        count=count+parsed.count
        for address in pairs(parsed.macs) do assert(address==PLAN.test_client_mac:lower(),"unknown IoT client") end
    end
    assert(count<=1,"multiple IoT station rows on node")
    return count
end
local function uplink(state)
    local gateway_mac
    for line in (read("/proc/net/arp") or ""):gmatch("[^\n]+") do
        local address,mac=line:match("^(%S+)%s+%S+%s+%S+%s+(%S+)")
        if address==PLAN.gateway then gateway_mac=mac end
    end
    assert(gateway_mac,"gateway ARP missing")
    local found=false
    for line in cmd({BR,"showmacs","br-lan"}):gmatch("[^\n]+") do
        local port,mac,local_flag=line:match("^%s*(%d+)%s+(%S+)%s+(%S+)")
        if mac==gateway_mac and tonumber(port)==PLAN.uplink_bridge_port and local_flag=="no" then found=true end
    end
    assert(found and tonumber(trim(read("/sys/class/net/eth1.4/brport/port_no")))==PLAN.uplink_bridge_port
        and master("eth1.4")==state.main_bridge_id,"uplink changed")
    local mask=tonumber(trim(read("/proc/rtk_gsw/phylink")))
    local speed=tonumber((read("/proc/rtk_gsw/linkspeed") or ""):match("port:%s*2%s+speed:%s*(%d+)"))
    assert(mask and mask>=0 and mask<=127 and mask==math.floor(mask) and math.floor(mask/4)%2==1 and speed and speed>0,"uplink link unavailable")
end
local function rule_argv(binary,action,rule)
    local argv={binary,action};for _,v in ipairs(rule) do argv[#argv+1]=v end;return argv
end
local function rule_present(binary,rule)
    local code=sp.call(rule_argv(binary,"-C",rule));assert(code==0 or code==1,"firewall check unsupported");return code==0
end
-- Exact-release nixio implements tlock with process-owned lockf(F_TLOCK).
-- Kernel death releases it; forked watchdogs do not inherit lock ownership.
-- Keep each descriptor strongly held, and never unlink the locked inode.
local HELD_LOCKS={}
local function claim_lock(path)
    assert(not HELD_LOCKS[path],"lock already held by this invocation")
    local fd=nx.open(path,"w","rw-------")
    if not fd then return false end
    local ok,held=pcall(fd.lock,fd,"tlock")
    if not ok or not held then fd:close();return false end
    HELD_LOCKS[path]=fd;return true
end
local function release_lock(path)
    local fd=HELD_LOCKS[path]
    if fd then HELD_LOCKS[path]=nil;fd:close() end
end
local function partial_own_reservation(state,owner)
    return state.reservation_created and type(owner)=="string" and #owner<#NONCE
        and owner==NONCE:sub(1,#owner)
end
local function result_base(phase)
    return {nonce=NONCE,node_id=PLAN.device_id,deadline=PLAN.deadline,phase=phase}
end
local function done_result()
    local body=read(BASE.."/done.json");if not body then return nil end
    local result=json.decode(body)
    assert(result.nonce==NONCE and result.node_id==PLAN.device_id and result.deadline==PLAN.deadline and result.rolled_back==true,"done binding changed")
    local state=state_load();main_unchanged(state)
    assert(not ifindex("br-iot") and not ifindex("eth1.30") and ports(30)=="" and not fs.stat(ACTIVE),"cleanup no longer holds")
    for _,name in ipairs(VAPS) do assert(ifindex(name)==state.vaps[name].ifindex and master(name)==state.main_bridge_id,"restored VAP changed") end
    for _,entry in ipairs(state.rules) do assert(not rule_present(entry.binary,entry.rule),"trial rule remains") end
    result.fresh_verified=true
    return result
end
local stop_actor
local function restore(memory_state)
    context()
    local done=done_result();if done then return done end
    pcall(write,BASE.."/abort","rollback\n")
    -- Always inspect the fresh journal: a failed concurrent activate may hold
    -- a stale memory snapshot from before the other phase acquired its lock.
    local loaded,fresh=pcall(state_load)
    if loaded then stop_actor(fresh) end
    local own_memory=memory_state and memory_state.actor and memory_state.actor.pid==nx.getpid()
        and same_process(memory_state.actor)
    local initial
    if own_memory then stop_actor(memory_state);initial=memory_state
    else initial=state_load();stop_actor(initial);initial=state_load() end
    local lock=BASE.."/rollback-lock"
    if not claim_lock(lock) then
        local busy=result_base("rollback_failed");busy.rolled_back=false;busy.busy=true;busy.errors={"rollback_busy"};return busy
    end
    local previous=IN_ROLLBACK;IN_ROLLBACK=true
    local ok,result=pcall(function()
        local state=initial
        local owner=read(ACTIVE.."/owner")
        assert(owner==NONCE or owner==nil or partial_own_reservation(state,owner),"trial reservation changed")
        if owner~=NONCE then assert(not ifindex("br-iot") and not ifindex("eth1.30") and ports(30)=="","reservation incomplete with resources") end
        if state.bridge_intent and not state.bridge_index and ifindex("br-iot") then
            assert(bridge("br-iot"),"reserved bridge type changed")
            for name in fs.dir("/sys/class/net/br-iot/brif") do
                assert(name=="." or name==".." or name=="eth1.30" or state.vaps[name],"foreign private member")
                if state.vaps[name] then assert(ifindex(name)==state.vaps[name].ifindex,"VAP identity changed") end
            end
            state.bridge_index=ifindex("br-iot")
        end
        if state.vlan_intent and not state.vlan_index and ifindex("eth1.30") then
            local value=read("/proc/net/vlan/eth1.30") or ""
            assert(value:find("VID: 30",1,true) and value:find("Device: eth1",1,true),"reserved VLAN shape changed")
            assert(not master("eth1.30") or master("eth1.30")==bridge("br-iot"),"foreign VLAN master")
            state.vlan_index=ifindex("eth1.30")
        end
        local errors={}
        local function attempt(label,fn) if not pcall(fn) then errors[#errors+1]=label end end
        for _,name in ipairs(VAPS) do
            local original=state.vaps[name]
            attempt("restore_"..name,function()
                assert(ifindex(name)==original.ifindex,"VAP identity changed")
                if original.move_intent then
                    if master(name)==bridge("br-iot") and state.bridge_index then
                        assert(ifindex("br-iot")==state.bridge_index,"bridge owner changed");run({BR,"delif","br-iot",name})
                    end
                    if not master(name) then run({BR,"addif","br-lan",name}) end
                    assert(master(name)==state.main_bridge_id,"foreign VAP master")
                    for attr,value in pairs(original.attributes) do write("/sys/class/net/"..name.."/brport/"..attr,value) end
                else assert(master(name)==state.main_bridge_id,"untouched VAP master changed") end
            end)
        end
        if state.switch_intent then attempt("restore_switch30",function()
            local current=ports(30);assert(current==state.applied_ports or current=="","foreign VLAN30 change")
            if current~="" then run({SW,"dev","switch1","vlan","30","set","ports",""}) end
            assert(ports(30)=="","VLAN30 remains")
        end) end
        if state.vlan_index then attempt("remove_vlan_interface",function()
            if ifindex("eth1.30") then
                assert(ifindex("eth1.30")==state.vlan_index,"VLAN device owner changed")
                if master("eth1.30")==bridge("br-iot") then run({BR,"delif","br-iot","eth1.30"}) end
                assert(not master("eth1.30"),"foreign VLAN master")
                run({BB,"ifconfig","eth1.30","down"});run({BB,"vconfig","rem","eth1.30"})
            end
        end) end
        if state.bridge_index then attempt("remove_private_bridge",function()
            if ifindex("br-iot") then
                assert(ifindex("br-iot")==state.bridge_index,"bridge owner changed")
                for name in fs.dir("/sys/class/net/br-iot/brif") do assert(name=="." or name=="..","private bridge not empty") end
                run({BB,"ifconfig","br-iot","down"});run({BR,"delbr","br-iot"})
            end
        end) end
        for _,entry in ipairs(state.rules) do attempt("remove_interface_rule",function()
            if rule_present(entry.binary,entry.rule) then run(rule_argv(entry.binary,"-D",entry.rule)) end
        end) end
        local preserved=false
        attempt("main_baseline",function() main_unchanged(state);preserved=true end)
        local value=result_base("rollback_failed")
        value.rollback_initiated_by=MODE
        value.errors=errors;value.main_preserved=preserved
        value.private_bridge_removed=not ifindex("br-iot");value.vlan_device_removed=not ifindex("eth1.30")
        value.rolled_back=#errors==0 and value.private_bridge_removed and value.vlan_device_removed
        if value.rolled_back then value.phase="rolled_back" end
        if value.rolled_back then
            local owner_now=read(ACTIVE.."/owner")
            if owner_now==NONCE or partial_own_reservation(state,owner_now) then
                if not os.remove(ACTIVE.."/owner") or not fs.rmdir(ACTIVE) then
                    value.rolled_back=false;value.phase="rollback_failed";value.errors[#value.errors+1]="reservation_cleanup_failed"
                end
            elseif owner_now==nil and state.reservation_created then
                if fs.stat(ACTIVE) and not fs.rmdir(ACTIVE) then
                    value.rolled_back=false;value.phase="rollback_failed";value.errors[#value.errors+1]="reservation_cleanup_failed"
                end
            elseif owner_now~=nil then
                value.rolled_back=false;value.phase="rollback_failed";value.errors[#value.errors+1]="foreign_reservation"
            end
            if value.rolled_back then pcall(write,BASE.."/done.json",json.encode(value)) end
        end
        value.fresh_verified=value.rolled_back
        pcall(write,BASE.."/rollback-result.json",json.encode(value))
        return value
    end)
    release_lock(lock);IN_ROLLBACK=previous
    if ok then return result end
    local value=result_base("rollback_failed");value.rolled_back=false;value.errors={"rollback_internal_error"};return value
end
local function same_child(p)
    local now=p and process(p.pid)
    return now and now.start==p.start and now.state~="Z"
        and (p.lineage_owned or now.name==p.name or now.name==p.exec_name) and now
end
stop_actor=function(state)
    local actor=state.mutation_in_progress and same_process(state.actor)
    local children={}
    if actor and actor.pid~=nx.getpid() then
        assert(actor.pid>1,"actor identity invalid")
        assert(nx.kill(actor.pid,19),"cannot freeze phase actor")
        local owned={[actor.pid]=true}
        for pass=1,3 do for text in fs.dir("/proc") do
            local pid=tonumber(text)
            if pid and pid~=nx.getpid() and not owned[pid] then
                local p=process(pid);if p and owned[p.ppid] then p.lineage_owned=true;owned[pid]=true;children[#children+1]=p end
            end
        end end
        for _,p in ipairs(children) do if same_child(p) then assert(nx.kill(p.pid,9),"cannot stop owned child") end end
        assert(nx.kill(actor.pid,9),"cannot stop phase actor");children[#children+1]=actor
    end
    if state.active_child and state.active_child.pid~=nx.getpid() and same_child(state.active_child) then
        nx.kill(state.active_child.pid,9);children[#children+1]=state.active_child
    end
    for attempt=1,100 do
        local live=false;for _,p in ipairs(children) do if same_child(p) then live=true end end
        if not live then return end
        nx.nanosleep(0,100000000);assert(attempt<100,"owned child did not terminate")
    end
end
local function show(state)
    main_unchanged(state)
    assert((state.phase=="staged" or state.phase=="active") and not state.mutation_in_progress,"phase incomplete")
    assert(read(ACTIVE.."/owner")==NONCE and not read(BASE.."/abort") and not read(BASE.."/done.json")
        and uptime()<state.deadline and same_process(state.watchdog),"phase reservation or timer invalid")
    assert(ifindex("br-iot")==state.bridge_index and ifindex("eth1.30")==state.vlan_index
        and master("eth1.30")==bridge("br-iot") and ports(30)==state.applied_ports,"phase resources changed")
    for _,name in ipairs(VAPS) do
        assert(ifindex(name)==state.vaps[name].ifindex,"phase VAP identity changed")
        assert(master(name)==(state.phase=="active" and bridge("br-iot") or state.main_bridge_id),"phase VAP master changed")
    end
    local value=result_base(state.phase)
    value.main_preserved=true;value.active=state.phase=="active";value.staged=state.phase=="staged"
    value.remaining_seconds=math.max(0,math.floor(state.deadline-uptime()))
    value.vlan30_ports=ports(30);value.vaps={}
    for _,name in ipairs(VAPS) do value.vaps[name]={on_main=master(name)==state.main_bridge_id,on_iot=bridge("br-iot")~=nil and master(name)==bridge("br-iot")} end
    return value
end
if MODE=="watchdog" then
    local state=state_load()
    write(BASE.."/watchdog-ready",tostring(nx.getpid()))
    sp.call({BB,"sleep",tostring(math.max(0,math.floor(state.deadline-uptime())))})
    local done=done_result();if done then return done end
    pcall(write,BASE.."/abort","expired\n")
    state=state_load();stop_actor(state)
    local value
    for attempt=1,20 do value=restore();if not value.busy then break end;nx.nanosleep(0,100000000) end
    return value
end
if MODE=="rollback" then
    if not read(BASE.."/state.json") then
        assert(not fs.stat(ACTIVE) and not ifindex("br-iot") and not ifindex("eth1.30") and ports(30)=="","unstaged node has resources")
        old_ports_unchanged({old_vlans=PLAN.old_vlans,old_pvids=PLAN.old_pvids})
        assert(cmd({IP,"addr","show","dev","br-lan"}):find("inet "..PLAN.management_ipv4.."/",1,true),"management address changed")
        local value=result_base("rolled_back");value.rolled_back=true;value.no_changes=true;value.main_preserved=true
        value.rollback_initiated_by=MODE
        value.private_bridge_removed=true;value.vlan_device_removed=true;value.errors={};value.fresh_verified=true;return value
    end
    return restore()
end
if MODE=="status" then local done=done_result();if done then return done end;return show(state_load()) end
assert(MODE=="stage" or MODE=="activate","unknown fixed mode")
assert(PLAN.deadline-uptime()>=30 and PLAN.deadline-uptime()<=1800,"insufficient or invalid trial window")
local state,phase_lock
local ok,value=pcall(function()
    if MODE=="stage" then
        assert(type(RUNTIME_SOURCE)=="string" and #RUNTIME_SOURCE>=1000,"own runtime source required")
        assert(not ifindex("br-iot") and not ifindex("eth1.30") and ports(30)=="","trial resources already exist")
        assert(sw({"get","enable_vlan"})=="1","switch mode changed")
        local sysmode=read("/etc/config/sysmode") or ""
        local section=sysmode:match("config%s+config%s+['\"]sysmode['\"](.-)config") or sysmode:match("config%s+config%s+['\"]sysmode['\"](.*)")
        assert(section and section:match("option%s+mode%s+['\"]AP['\"]"),"AP mode required")
        state={nonce=NONCE,node_id=PLAN.device_id,plan=PLAN,deadline=PLAN.deadline,phase="preparing",
            old_vlans=PLAN.old_vlans,old_pvids=PLAN.old_pvids,applied_ports=PLAN.tagged_ports,
            main_bridge_id=bridge("br-lan"),main_addresses=cmd({IP,"addr","show","dev","br-lan"}),
            main_routes=cmd({IP,"route","show","default"}),main_members=members(),vaps={},rules={}}
        assert(state.main_bridge_id and state.main_addresses:find("inet "..PLAN.management_ipv4.."/",1,true),"management baseline changed")
        main_unchanged(state);uplink(state);state.station_rows=stations()
        for _,name in ipairs(VAPS) do
            assert(master(name)==state.main_bridge_id,"unexpected IoT master")
            local item={ifindex=assert(ifindex(name)),attributes={},move_intent=false}
            for _,attr in ipairs(ATTRS) do local v=read("/sys/class/net/"..name.."/brport/"..attr);if v then item.attributes[attr]=v end end
            state.vaps[name]=item
        end
        for _,binary in ipairs({"/usr/sbin/iptables","/usr/sbin/ip6tables"}) do
            assert(sp.call({binary,"-S","INPUT"})==0 and sp.call({binary,"-S","FORWARD"})==0,"firewall unavailable")
            for _,rule in ipairs(RULES) do assert(not rule_present(binary,rule),"preexisting trial rule") end
        end
        assert(fs.mkdir(BASE),"trial directory exists");run({BB,"chmod","0700",BASE})
        state.reservation_intent=true;state_save(state)
        assert(fs.mkdir(ACTIVE),"another trial active");state.reservation_created=true;state_save(state)
        write(ACTIVE.."/owner",NONCE)
        state_save(state)
        write(BASE.."/runtime.lua",RUNTIME_SOURCE)
        local header="local BASE="..string.format("%q",BASE).."\nlocal NONCE="..string.format("%q",NONCE).."\nlocal PLAN=require('luci.json').decode("..string.format("%q",json.encode(PLAN))..")\n"
        write(BASE.."/watchdog.lua","local MODE='watchdog'\n"..header..RUNTIME_SOURCE)
        write(BASE.."/rollback.lua","local MODE='rollback'\n"..header..RUNTIME_SOURCE)
        -- Allocate the rollback-lock inode before any dataplane mutation.
        assert(claim_lock(BASE.."/rollback-lock"),"rollback lock unavailable")
        release_lock(BASE.."/rollback-lock")
    else
        state=state_load();assert(state.phase=="staged" and not state.mutation_in_progress,"node is not staged")
    end
    phase_lock=BASE.."/phase-lock";assert(claim_lock(phase_lock),"another phase active")
    CURRENT=state;guard()
    state.actor=assert(process(nx.getpid()));state.mutation_in_progress=true;state.current_action=MODE;state_save(state)
    if MODE=="stage" then
        local pid=assert(sp.exec({"/usr/bin/lua",BASE.."/watchdog.lua"}),"watchdog start failed")
        run({BB,"sleep","1"})
        local watcher=process(pid)
        assert(watcher and tonumber(read(BASE.."/watchdog-ready"))==pid,"watchdog readiness failed")
        state.watchdog=watcher;state_save(state)
        for _,binary in ipairs({"/usr/sbin/iptables","/usr/sbin/ip6tables"}) do for _,rule in ipairs(RULES) do
            state.rules[#state.rules+1]={binary=binary,rule=rule};state_save(state);run(rule_argv(binary,"-I",rule))
        end end
        state.bridge_intent=true;state_save(state);run({BR,"addbr","br-iot"})
        state.bridge_index=assert(ifindex("br-iot"));state_save(state)
        write("/proc/sys/net/ipv6/conf/br-iot/disable_ipv6","1\n");write("/proc/sys/net/ipv4/conf/br-iot/arp_ignore","1\n")
        run({BR,"setfd","br-iot","0"})
        state.vlan_intent=true;state_save(state);run({BB,"vconfig","add","eth1","30"})
        state.vlan_index=assert(ifindex("eth1.30"));state_save(state)
        assert((read("/proc/net/vlan/eth1.30") or ""):find("VID: 30",1,true),"VLAN device mismatch")
        write("/proc/sys/net/ipv6/conf/eth1.30/disable_ipv6","1\n")
        run({BB,"ifconfig","eth1.30","mtu","1500","up"});run({BR,"addif","br-iot","eth1.30"})
        run({BB,"ifconfig","br-iot","mtu","1500","up"})
        old_ports_unchanged(state);state.switch_intent=true;state_save(state)
        run({SW,"dev","switch1","vlan","30","set","ports",state.applied_ports})
        assert(ports(30)==state.applied_ports,"VLAN30 readback failed")
        for _,name in ipairs(VAPS) do assert(master(name)==state.main_bridge_id,"IoT moved during staging") end
        state.phase="staged"
    else
        assert(same_process(state.watchdog),"independent watchdog unavailable")
        main_unchanged(state);uplink(state);stations()
        assert(ifindex("br-iot")==state.bridge_index and ifindex("eth1.30")==state.vlan_index
            and master("eth1.30")==bridge("br-iot") and ports(30)==state.applied_ports,"staged resources changed")
        for _,name in ipairs(VAPS) do
            assert(ifindex(name)==state.vaps[name].ifindex and master(name)==state.main_bridge_id,"IoT changed before activation")
            state.vaps[name].move_intent=true;state_save(state)
            run({BR,"delif","br-lan",name});run({BR,"addif","br-iot",name})
            assert(master(name)==bridge("br-iot"),"IoT bridge move failed");main_unchanged(state)
        end
        state.phase="active"
    end
    main_unchanged(state);guard()
    state.mutation_in_progress=false;state.actor=nil;state.active_child=nil;state.current_action=nil;state_save(state)
    return show(state)
end)
if phase_lock then release_lock(phase_lock) end
if ok then return value end
pcall(write,BASE.."/abort","phase failed\n")
local failed=result_base("failed");failed.staged=false;failed.active=false;failed.failed_phase=MODE;failed.error="fixed_phase_failed"
if state and read(ACTIVE.."/owner")==NONCE and read(BASE.."/state.json") then failed.rollback=restore(state)
else
    local noop=result_base("rolled_back");noop.rolled_back=true;noop.no_changes=true;noop.errors={};noop.rollback_initiated_by=MODE
    noop.private_bridge_removed=not ifindex("br-iot");noop.vlan_device_removed=not ifindex("eth1.30")
    local owner=read(ACTIVE.."/owner")
    if state and state.reservation_created then
        if owner==NONCE or partial_own_reservation(state,owner) then pcall(os.remove,ACTIVE.."/owner");pcall(fs.rmdir,ACTIVE)
        elseif owner==nil then pcall(fs.rmdir,ACTIVE)
        else noop.rolled_back=false;noop.errors={"foreign_reservation"} end
        if (owner~=nil and owner~=NONCE and not partial_own_reservation(state,owner)) or fs.stat(ACTIVE) then noop.rolled_back=false end
    end
    if not noop.private_bridge_removed or not noop.vlan_device_removed then noop.rolled_back=false end
    if state and state.main_addresses then noop.main_preserved=pcall(main_unchanged,state) else noop.main_preserved=false end
    if not noop.main_preserved then noop.rolled_back=false end
    if not noop.rolled_back then noop.phase="rollback_failed";if #noop.errors==0 then noop.errors={"prepare_cleanup_failed"} end end
    failed.rollback=noop
end
return failed
