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
return parse_stations
