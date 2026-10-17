package.path = "runtime/?.lua;" .. package.path
-- Own observer/parser only, virtual files and exact fixed command mocks.
local source=assert(loadfile("runtime/association_observer.lua"))
PARSE_STATIONS=assert(loadfile("runtime/station_parser.lua"))()
local fixture=assert(loadfile("runtime/station_fixtures.lua"))()
local case=arg[1] or "success"
NONCE=string.rep("a",32);FLEET_NONCE=string.rep("b",32)
BASE="/tmp/deco-iot-fleet-"..NONCE
PLAN={device_id=string.rep("A",40),boot_id="11111111-2222-4333-8444-555555555555",
    fleet_nonce=FLEET_NONCE,test_client_mac="02:00:00:00:00:01",deadline=200}
local state={nonce=NONCE,node_id=PLAN.device_id,plan=PLAN,deadline=PLAN.deadline,
    phase="active",bridge_index=40,vlan_index=41,vaps={ath08={ifindex=28},ath18={ifindex=29}}}
local files={
    ["/proc/uptime"]="100 0\n",["/tmp/sync-cached-DEV_ID"]=PLAN.device_id.."\n",
    ["/proc/sys/kernel/random/boot_id"]=PLAN.boot_id.."\n",[BASE.."/state.json"]="own-state",
    ["/tmp/deco-iot-trial-active/owner"]=NONCE,
    ["/sys/class/net/br-iot/bridge/bridge_id"]="7fff.021122334455\n",
    ["/sys/class/net/br-iot/ifindex"]="40\n",["/sys/class/net/eth1.30/ifindex"]="41\n",
    ["/sys/class/net/eth1.30/master/bridge/bridge_id"]="7fff.021122334455\n"}
for _,item in ipairs({{"ath08",28},{"ath18",29}}) do
    local path="/sys/class/net/"..item[1]
    files[path.."/master/bridge/bridge_id"]="7fff.021122334455\n"
    files[path.."/ifindex"]=tostring(item[2]).."\n"
    files[path.."/address"]="02:11:22:33:44:55\n"
end
local exists={}
if case=="wrong_device" then files["/tmp/sync-cached-DEV_ID"]=string.rep("B",40) end
if case=="wrong_boot" then files["/proc/sys/kernel/random/boot_id"]="different" end
if case=="wrong_phase" then state.phase="staged" end
if case=="mutating" then state.mutation_in_progress=true end
if case=="wrong_nonce" then state.nonce=string.rep("c",32) end
if case=="wrong_owner" then files["/tmp/deco-iot-trial-active/owner"]="foreign" end
if case=="wrong_deadline" then state.deadline=201 end
if case=="expired" then files["/proc/uptime"]="201 0\n" end
if case=="near_expiry" then files["/proc/uptime"]="195 0\n" end
if case=="abort" then exists[BASE.."/abort"]=true end
if case=="wrong_master" then files["/sys/class/net/ath18/master/bridge/bridge_id"]="mainbridge" end
if case=="wrong_vap_index" then files["/sys/class/net/ath18/ifindex"]="99" end
if case=="wrong_bridge_index" then files["/sys/class/net/br-iot/ifindex"]="99" end
if case=="invalid_bssid" then files["/sys/class/net/ath18/address"]="03:11:22:33:44:55" end
local commands=0
local sp={call_output=function(argv)
    assert(#argv==10 and argv[1]=="/bin/busybox" and argv[2]=="timeout" and argv[3]=="-t"
        and argv[4]=="2" and argv[5]=="-s" and argv[6]=="KILL" and argv[7]=="/usr/sbin/wlanconfig"
        and argv[9]=="list" and argv[10]=="sta","nonfixed getter")
    commands=commands+1
    assert(argv[8]==(commands==1 and "ath08" or "ath18"),"wrong fixed band")
    if case=="getter_failure" then return "",137 end
    if case=="expires_during_getter" then files["/proc/uptime"]="201 0\n" end
    if case=="invalid_station" then return fixture.main.."unknown footer\n",0 end
    if commands==1 or case=="empty" then return fixture.header,0 end
    return fixture.main,0
end}
local nx={getuid=function() return case=="not_root" and 1000 or 0 end}
local modules={nixio=nx,["nixio.fs"]={stat=function(path) return exists[path] end},
    ["luci.json"]={decode=function(value) assert(value=="own-state");return state end},
    ["luci.model.subprocess"]=sp}
require=function(name) return assert(modules[name],"unexpected module") end
io.open=function(path,mode)
    assert(mode=="rb","observer tried to write")
    local body=files[path]
    if not body then return nil end
    return {read=function(_,limit) assert(type(limit)=="number");return body:sub(1,limit) end,
        close=function() return true end}
end
local ok,value=pcall(source)
local valid=case=="success" or case=="empty"
assert(ok==valid,"unexpected observer acceptance for "..case)
if valid then
    assert(value.phase=="active" and value.uid==0 and not value.network_configuration_changed and not value.trial_extended)
    assert(value.bands.ath08.count==0 and value.bands.ath08.pinned_phone_present==false)
    assert(value.bands.ath18.count==(case=="success" and 1 or 0))
    assert(value.bands.ath18.pinned_phone_present==(case=="success"))
    assert(commands==2)
end
print('{"case":"'..case..'","passed":true,"device_contact":false}')
