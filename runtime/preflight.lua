-- Fixed collection only. No caller-selected command, path, node or VLAN.
-- Return this table to a private host receipt; never expose station/FDB data publicly.
-- The host must compare identity/boot against its immutable node context.
local nx=require("nixio")
local fs=require("nixio.fs")
local sp=require("luci.model.subprocess")
local report={schema=1,kind="deco_mesh_readonly_preflight",read_only=true,
    collection_only=true,ready_for_activation=false,requires_host_context_match=true,
    files={},commands={},interfaces={},iot_stations={},collection_errors={}}
local function problem(label) report.collection_errors[#report.collection_errors+1]=label end
local function trim(value) return value and value:match("^%s*(.-)%s*$") end
local function read(path,limit)
    local f=io.open(path,"rb")
    if not f then return {available=false,ok=false,truncated=false} end
    local ok,data=pcall(function() return f:read(limit+1) end)
    local closed=pcall(function() return assert(f:close()) end)
    if not ok or type(data)~="string" or not closed then
        return {available=true,ok=false,truncated=false}
    end
    return {available=true,ok=true,value=data:sub(1,limit),
        observed_bytes=#data,truncated=#data>limit}
end
local function fixed_file(key,path,limit)
    local item=read(path,limit)
    report.files[key]=item
    if not item.ok or item.truncated then problem("file:"..key) end
    return item.ok and not item.truncated and trim(item.value) or nil
end
local function uptime()
    local item=read("/proc/uptime",128)
    return item.ok and tonumber(item.value:match("^[%d.]+")) or nil
end
local started=uptime()
report.uid=nx.getuid()
report.gid=nx.getgid()
report.boot_id_before=fixed_file("boot_id_before","/proc/sys/kernel/random/boot_id",128)
report.uptime_before=started
report.identity={
    device_id=fixed_file("device_id","/tmp/sync-cached-DEV_ID",256),
    mac=fixed_file("cached_mac","/tmp/sync-cached-MAC",128),
    model=fixed_file("model","/tmp/sync-cached-MODEL",256),
    hardware_ver=fixed_file("hardware_ver","/tmp/sync-cached-HARDVERSION",256),
    software_ver=fixed_file("software_ver","/tmp/sync-cached-SOFTVERSION",512),
    eth1_mac=fixed_file("eth1_mac","/sys/class/net/eth1/address",128),
    br_lan_mac=fixed_file("br_lan_mac","/sys/class/net/br-lan/address",128)}
local version=fixed_file("firmware_file","/fw_data/soft-version",4096)
if version then
    for line in version:gmatch("[^\r\n]+") do
        local value=line:match("^soft_ver:%s*(.*)$")
        if value then report.identity.firmware_file_ver=trim(value) end
    end
end
local sysmode=fixed_file("sysmode","/etc/config/sysmode",8192)
if sysmode then
    local own_section=false
    for line in sysmode:gmatch("[^\r\n]+") do
        if line:match("^%s*config%s") then
            local section=line:match("^%s*config%s+[%w_%-]+%s+'([^']+)'")
                or line:match('^%s*config%s+[%w_%-]+%s+"([^"]+)"')
                or line:match("^%s*config%s+[%w_%-]+%s+([%w_%-]+)")
            own_section=section=="sysmode"
        elseif own_section then
            local tail=line:match("^%s*option%s+mode%s+(.+)$")
            if tail then
                report.operating_mode=tail:match("^'([^']+)'")
                    or tail:match('^"([^"]+)"') or tail:match("^([%w_%-]+)")
            end
        end
    end
end
if not report.operating_mode then problem("sysmode:unparsed") end
report.arp=fixed_file("arp","/proc/net/arp",12000)
report.vlan_devices=fixed_file("vlan_devices","/proc/net/vlan/config",4096)
report.phy_link=fixed_file("phy_link","/proc/rtk_gsw/phylink",256)
report.phy_speed=fixed_file("phy_speed","/proc/rtk_gsw/linkspeed",4096)

local function command(argv,limit)
    local now=uptime()
    if not started or not now or now-started>=20 then
        return {ran=false,ok=false,skipped="collection_time_budget",truncated=false}
    end
    -- This exact timeout form is already used by our bounded device probes.
    local bounded={"/bin/busybox","timeout","-t","5","-s","KILL"}
    for _,arg in ipairs(argv) do bounded[#bounded+1]=arg end
    local ok,body,code=pcall(sp.call_output,bounded)
    if not ok or type(body)~="string" then
        return {ran=true,ok=false,error="fixed_command_failed",truncated=false,
            timeout_seconds=5}
    end
    return {ran=true,ok=code==0,code=code,output=body:sub(1,limit),
        truncated=#body>limit,observed_bytes=#body,timeout_seconds=5}
end
local requests={
    {"switch_list",{"/sbin/swconfig","list"},1024},
    {"switch_help",{"/sbin/swconfig","dev","switch1","help"},4096},
    {"switch_enabled",{"/sbin/swconfig","dev","switch1","get","enable_vlan"},128},
    {"bridges",{"/usr/sbin/brctl","show"},4096},
    {"bridge_fdb",{"/usr/sbin/brctl","showmacs","br-lan"},16000},
    {"management_addresses",{"/usr/sbin/ip","addr","show","dev","br-lan"},4096},
    {"default_routes",{"/usr/sbin/ip","route","show","default"},4096},
    {"routes",{"/usr/sbin/ip","route","show"},4096},
    {"iot2g_stations",{"/usr/sbin/wlanconfig","ath08","list","sta"},8192},
    {"iot5g_stations",{"/usr/sbin/wlanconfig","ath18","list","sta"},8192}}
for _,port in ipairs({0,1,2,6}) do
    requests[#requests+1]={"port"..port.."_pvid",
        {"/sbin/swconfig","dev","switch1","port",tostring(port),"get","pvid"},128}
end
for _,vid in ipairs({2,3,4,30,500}) do
    requests[#requests+1]={"vlan"..vid.."_ports",
        {"/sbin/swconfig","dev","switch1","vlan",tostring(vid),"get","ports"},512}
    requests[#requests+1]={"vlan"..vid.."_info",
        {"/sbin/swconfig","dev","switch1","vlan",tostring(vid),"get","info"},1024}
end
for _,request in ipairs(requests) do
    local result=command(request[2],request[3])
    report.commands[request[1]]=result
    if not result.ok or result.truncated then problem("command:"..request[1]) end
end

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
local function stations(key)
    local result=report.commands[key]
    if not result.ok or result.truncated then
        return {parsed=false,count=0,macs={},error="command_failed_or_truncated"}
    end
    return parse_stations(result.output)
end
report.iot_stations.ath08=stations("iot2g_stations")
report.iot_stations.ath18=stations("iot5g_stations")
for name,value in pairs(report.iot_stations) do
    if not value.parsed then problem("station_format:"..name) end
end

local function interface(name)
    local path="/sys/class/net/"..name
    local item={exists=fs.stat(path)~=nil,fields={},unavailable={}}
    if not item.exists then return item end
    local leaves={ifindex="ifindex",iflink="iflink",operstate="operstate",mtu="mtu",
        flags="flags",bridge_id="bridge/bridge_id",master_bridge_id="master/bridge/bridge_id",
        port_no="brport/port_no",bridge_port_state="brport/state"}
    for key,leaf in pairs(leaves) do
        local value=read(path.."/"..leaf,128)
        if value.ok and not value.truncated then item.fields[key]=trim(value.value)
        else item.unavailable[key]=true end
    end
    return item
end
for _,name in ipairs({"eth1","eth1.2","eth1.3","eth1.4","eth1.30",
    "ath0","ath1","ath2","ath08","ath18","br-lan","br-iot"}) do
    report.interfaces[name]=interface(name)
end
report.main_bridge_members={directory_ok=false,count=0,by_name={},truncated=false}
local ok,iterator=pcall(fs.dir,"/sys/class/net/br-lan/brif")
if ok and type(iterator)=="function" then
    report.main_bridge_members.directory_ok=true
    for name in iterator do
        if name~="." and name~=".." then
            if #name>15 or not name:match("^[%w_.:-]+$") then
                report.main_bridge_members.directory_ok=false
                problem("bridge_member:invalid_name")
                break
            end
            if report.main_bridge_members.count>=32 then
                report.main_bridge_members.truncated=true
                problem("bridge_member:limit")
                break
            end
            report.main_bridge_members.count=report.main_bridge_members.count+1
            report.main_bridge_members.by_name[name]=true
            if not report.interfaces[name] then report.interfaces[name]=interface(name) end
        end
    end
else problem("bridge_members:unavailable") end
report.boot_id_after=fixed_file("boot_id_after","/proc/sys/kernel/random/boot_id",128)
report.uptime_after=uptime()
report.same_boot=report.boot_id_before~=nil and report.boot_id_before==report.boot_id_after
if not report.same_boot then problem("boot_id:changed_or_unavailable") end
if started and report.uptime_after then report.duration_seconds=report.uptime_after-started end
report.collection_complete=#report.collection_errors==0
return report
