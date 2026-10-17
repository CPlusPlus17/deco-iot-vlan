-- Fixed read-only observation of an already active, original fleet trial.
-- PLAN/BASE/NONCE/FLEET_NONCE/PARSE_STATIONS are frozen by the host helper.
local nx=require("nixio")
local fs=require("nixio.fs")
local json=require("luci.json")
local sp=require("luci.model.subprocess")
local function read(path,limit)
    local f=assert(io.open(path,"rb"),"fixed observation file unavailable")
    local body=f:read((limit or 16384)+1);assert(f:close())
    assert(type(body)=="string" and #body<=(limit or 16384),"observation file size invalid")
    return body
end
local function trim(value) return value:match("^%s*(.-)%s*$") end
local function uptime() return assert(tonumber(read("/proc/uptime",128):match("^[%d.]+"))) end
local function same(a,b,depth)
    if type(a)~=type(b) then return false end
    if type(a)~="table" then return a==b end
    depth=(depth or 0)+1;assert(depth<10,"plan depth invalid")
    for key,value in pairs(a) do if not same(value,b[key],depth) then return false end end
    for key in pairs(b) do if a[key]==nil then return false end end
    return true
end
local function valid_mac(value)
    return type(value)=="string" and value:match("^%x%x:%x%x:%x%x:%x%x:%x%x:%x%x$")
        and value~="00:00:00:00:00:00" and tonumber(value:sub(1,2),16)%2==0
end
assert(type(BASE)=="string" and BASE=="/tmp/deco-iot-fleet-"..NONCE,"wrong fixed trial base")
assert(type(NONCE)=="string" and #NONCE==32 and NONCE:match("^[0-9a-f]+$"),"wrong trial owner")
assert(type(FLEET_NONCE)=="string" and #FLEET_NONCE==32 and FLEET_NONCE:match("^[0-9a-f]+$"),"wrong fleet owner")
assert(type(PLAN)=="table" and PLAN.fleet_nonce==FLEET_NONCE and valid_mac(PLAN.test_client_mac),"wrong trial plan")
assert(type(PARSE_STATIONS)=="function","own strict parser unavailable")
local function active_state()
    assert(nx.getuid()==0,"root observation required")
    assert(trim(read("/tmp/sync-cached-DEV_ID",128))==PLAN.device_id,"device identity changed")
    assert(trim(read("/proc/sys/kernel/random/boot_id",128))==PLAN.boot_id,"device boot changed")
    local state=json.decode(read(BASE.."/state.json",32768))
    assert(type(state)=="table" and state.nonce==NONCE and state.node_id==PLAN.device_id
        and same(state.plan,PLAN) and state.deadline==PLAN.deadline,"trial journal binding changed")
    assert(state.phase=="active" and not state.mutation_in_progress,"trial is not active")
    assert(read("/tmp/deco-iot-trial-active/owner",128)==NONCE,"trial reservation changed")
    assert(not fs.stat(BASE.."/abort") and not fs.stat(BASE.."/done.json"),"trial has ended")
    assert(uptime()<PLAN.deadline,"trial deadline passed")
    local private_bridge=trim(read("/sys/class/net/br-iot/bridge/bridge_id",128))
    assert(tonumber(trim(read("/sys/class/net/br-iot/ifindex",32)))==state.bridge_index,"private bridge identity changed")
    assert(tonumber(trim(read("/sys/class/net/eth1.30/ifindex",32)))==state.vlan_index
        and trim(read("/sys/class/net/eth1.30/master/bridge/bridge_id",128))==private_bridge,"private VLAN identity changed")
    for _,name in ipairs({"ath08","ath18"}) do
        assert(type(state.vaps[name])=="table"
            and tonumber(trim(read("/sys/class/net/"..name.."/ifindex",32)))==state.vaps[name].ifindex
            and trim(read("/sys/class/net/"..name.."/master/bridge/bridge_id",128))==private_bridge,"IoT VAP changed")
    end
    return state
end
local before=uptime()
active_state()
assert(PLAN.deadline-before>=10,"insufficient observation time")
local bands={}
for _,item in ipairs({{"ath08","2.4GHz"},{"ath18","5GHz"}}) do
    local name,band=item[1],item[2]
    local output,code=sp.call_output({"/bin/busybox","timeout","-t","2","-s","KILL",
        "/usr/sbin/wlanconfig",name,"list","sta"})
    assert(code==0 and type(output)=="string" and #output<=8192,"bounded station getter failed")
    local parsed=PARSE_STATIONS(output)
    assert(parsed.parsed==true,"strict station format rejected")
    local address=trim(read("/sys/class/net/"..name.."/address",64)):lower()
    assert(valid_mac(address),"VAP address invalid")
    bands[name]={band=band,parsed=true,count=parsed.count,macs=parsed.macs,
        pinned_phone_present=parsed.macs[PLAN.test_client_mac]==true,
        bssid=address,raw_station_output=output}
end
active_state()
local after=uptime()
assert(after>=before and after-before<=8 and after<PLAN.deadline,"observation freshness expired")
return {kind="deco_fleet_trial_association",fleet_nonce=FLEET_NONCE,nonce=NONCE,
    device_id=PLAN.device_id,boot_id=PLAN.boot_id,uid=nx.getuid(),phase="active",
    deadline=PLAN.deadline,uptime_before=before,uptime_after=after,
    remaining_seconds=math.max(0,math.floor(PLAN.deadline-after)),bands=bands,
    network_configuration_changed=false,trial_extended=false}
