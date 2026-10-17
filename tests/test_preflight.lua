package.path = "runtime/?.lua;" .. package.path
-- Host-only fixtures for our source. No firmware code or actual command runs.
local case=arg[1] or "main"
local source=assert(loadfile("runtime/preflight.lua"))
local stations_fixture=assert(loadfile("runtime/station_fixtures.lua"))()
local data={
    ["/proc/sys/kernel/random/boot_id"]="11111111-2222-4333-8444-555555555555\n",
    ["/tmp/sync-cached-DEV_ID"]=string.rep("A",40),
    ["/tmp/sync-cached-MAC"]="AA-BB-CC-EC-66-90",
    ["/tmp/sync-cached-MODEL"]="XE75Pro",
    ["/tmp/sync-cached-HARDVERSION"]="3.0",
    ["/tmp/sync-cached-SOFTVERSION"]="1.5.0 Build 20260603 Rel.15804",
    ["/sys/class/net/eth1/address"]="AA:BB:CC:ec:66:90\n",
    ["/sys/class/net/br-lan/address"]="AA:BB:CC:ec:66:90\n",
    ["/fw_data/soft-version"]="soft_ver:1.5.0 Build 20260603 Rel. 15804\n",
    ["/etc/config/sysmode"]="config router 'router'\n option mode 'Router'\nconfig config 'sysmode'\n option mode 'AP'\n",
    ["/proc/net/arp"]="IP address HW type Flags HW address Mask Device\n192.168.68.254 0x1 0x2 00:11:22:33:44:55 * br-lan\n",
    ["/proc/net/vlan/config"]="VLAN Dev name | VLAN ID\neth1.4 | 4 | eth1\n",
    ["/proc/rtk_gsw/phylink"]="5",
    ["/proc/rtk_gsw/linkspeed"]="port: 2 speed: 2500\n"}
local names={"eth1","eth1.2","eth1.3","eth1.4","ath0","ath1","ath2","ath08","ath18","br-lan"}
local exists={}
for index,name in ipairs(names) do
    local base="/sys/class/net/"..name
    exists[base]=true
    for key,value in pairs({ifindex=index,iflink=index,operstate="up",mtu=1500,flags="0x1003"}) do
        data[base.."/"..key]=tostring(value).."\n"
    end
    if name=="br-lan" then data[base.."/bridge/bridge_id"]="7fff.98254aec6690\n"
    elseif name~="eth1" then
        data[base.."/master/bridge/bridge_id"]="7fff.98254aec6690\n"
        data[base.."/brport/port_no"]=tostring(index).."\n"
        data[base.."/brport/state"]="3\n"
    end
end
local ticks,boots,commands=0,0,0
io.open=function(path,mode)
    assert(mode=="rb","Collector attempted a file write")
    local value=data[path]
    if path=="/proc/uptime" then
        ticks=ticks+1
        value=tostring(100+ticks*.01).." 0\n"
        if case=="budget" and commands>=3 then value="130 0\n" end
    elseif path=="/proc/sys/kernel/random/boot_id" then
        boots=boots+1
        if case=="boot_changed" and boots>1 then value="99999999-2222-4333-8444-555555555555\n" end
    end
    if case=="missing_identity" and path=="/tmp/sync-cached-DEV_ID" then return nil end
    if value==nil then return nil end
    return {read=function(_,count) return value:sub(1,count) end,close=function() return true end}
end
local function run(argv)
    assert(table.concat(argv," ",1,6)=="/bin/busybox timeout -t 5 -s KILL","Missing bounded command")
    commands=commands+1
    local command=table.concat(argv," ",7)
    local body=""
    if argv[7]=="/sbin/swconfig" then
        assert(command:find(" get ",1,true) or command=="/sbin/swconfig list"
            or command=="/sbin/swconfig dev switch1 help","Non-read switch command")
        if command:find("vlan 500 get ports",1,true) then
            body=case=="satellite" and "0t 1t 2t 6t\n" or case=="no_guest" and "" or "6t\n"
        elseif command:find("vlan 30 get ports",1,true) then body=case=="vlan_used" and "1t 6t\n" or ""
        elseif command:find("get pvid",1,true) then body="4\n"
        elseif command:find("get enable_vlan",1,true) then body="1\n"
        elseif command:find("get info",1,true) then body="members:0000 untag:0000\n" end
        if case=="command_failed" and command:find("vlan 30 get info",1,true) then return "",255 end
    elseif argv[7]=="/usr/sbin/brctl" then
        assert(argv[8]=="show" or argv[8]=="showmacs","Non-read bridge command")
        body="port no mac addr is local? ageing timer\n5 00:11:22:33:44:55 no 0.00\n"
        if case=="truncated" and argv[8]=="showmacs" then body=string.rep("x",17000) end
    elseif argv[7]=="/usr/sbin/ip" then
        assert(argv[8]=="addr" or argv[8]=="route","Non-read IP command")
        body=argv[8]=="addr" and "10: br-lan: <UP>\n    inet 192.168.68.1/20 brd 192.168.68.255 scope global br-lan\n"
            or "default via 192.168.68.254 dev br-lan\n"
    elseif argv[7]=="/usr/sbin/wlanconfig" then
        assert((argv[8]=="ath08" or argv[8]=="ath18") and argv[9]=="list" and argv[10]=="sta","Non-read wireless command")
        body=case=="bad_stations" and "unknown format\n" or stations_fixture.header
        if case=="client" and argv[8]=="ath18" then body=stations_fixture.main end
        if case=="native_satellite_footer" and argv[8]=="ath18" then body=stations_fixture.satellite end
        if case=="unknown_footer" and argv[8]=="ath18" then body=stations_fixture.main.."unknown footer\n" end
        if case=="incomplete_footer" and argv[8]=="ath18" then
            body=stations_fixture.main:gsub(" Max STA phymode[^\n]*\n","")
        end
    else error("Unexpected command utility") end
    return body,0
end
local modules={
    nixio={getuid=function() return 0 end,getgid=function() return 0 end},
    ["nixio.fs"]={stat=function(path) return exists[path] and {type="dir"} or nil end,
        dir=function(path)
            assert(path=="/sys/class/net/br-lan/brif")
            local members={".","..","eth1.2","eth1.3","eth1.4","ath0","ath1","ath2","ath08","ath18"}
            local index=0
            return function() index=index+1;return members[index] end
        end},
    ["luci.model.subprocess"]={call_output=run}}
require=function(name) return assert(modules[name],"Unexpected module: "..name) end
local report=source()
assert(report.read_only and report.collection_only and report.ready_for_activation==false)
local succeeds=case=="main" or case=="satellite" or case=="no_guest" or case=="vlan_used"
    or case=="client" or case=="native_satellite_footer"
assert(report.collection_complete==succeeds,"Unexpected collection outcome: "..case)
assert((case=="client" and report.iot_stations.ath18.count==1) or case~="client")
assert((case=="native_satellite_footer" and report.iot_stations.ath18.count==1) or case~="native_satellite_footer")
local function quote(value)
    return '"'..value:gsub('[%z\1-\31\\"]',function(c)
        return c=='"' and '\\"' or c=='\\' and '\\\\' or string.format('\\u%04x',c:byte())
    end)..'"'
end
local function encode(value)
    if type(value)=="table" then
        local out={}
        for key,item in pairs(value) do out[#out+1]=quote(tostring(key))..":"..encode(item) end
        return "{"..table.concat(out,",").."}"
    elseif type(value)=="string" then return quote(value)
    elseif type(value)=="boolean" or type(value)=="number" then return tostring(value)
    else error("Unexpected report value") end
end
print(encode(report))
