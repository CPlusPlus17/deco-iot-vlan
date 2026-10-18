-- Own bounded native Wi-Fi actor check. Raw argv stays in memory; the only
-- result is a boolean. This does not claim to freeze autonomous driver CSA.
local M={}
local SCRIPTS={["/sbin/wifi"]=true,["/etc/init.d/wifi"]=true,["/etc/rc.d/S41wifi"]=true,
    ["/lib/wifi/wifiupdate.sh"]=true}
function M.is_actor(words)
    local first=words[1] and words[1]:match("([^/]+)$")
    if SCRIPTS[words[1]] then return true end
    local offset=1
    if first=="busybox" and (words[2]=="sh" or words[2]=="ash") then first=words[2];offset=2 end
    if first=="sh" or first=="ash" or first=="dash" then
        if SCRIPTS[words[offset+1]] then return true end
        if words[offset+1]=="/etc/rc.common" and SCRIPTS[words[offset+2]] then return true end
    end
    if first=="cfg80211tool" or first=="wifitool" or first=="iwconfig" then return true end
    if first=="wlanconfig" then
        for _,word in ipairs(words) do if word=="create" or word=="destroy" then return true end end
    end
    if first=="iw" then
        for _,word in ipairs(words) do if word=="set" or word=="add" or word=="del" then return true end end
    end
    if first=="wpa_cli" then
        for _,word in ipairs(words) do if word=="ADD" or word=="REMOVE" then return true end end
    end
    return false
end
function M.check()
    local fs=require("nixio.fs")
    local count=0
    for name in fs.dir("/proc") do
        if name:match("^%d+$") then
            count=count+1;assert(count<=512,"native process inventory bound")
            local pid=tonumber(name);assert(pid and pid>=1 and pid<=4194304,"native PID bound")
            local f=io.open("/proc/"..name.."/cmdline","rb")
            if f then
                local raw=f:read(4097);assert(f:close())
                if type(raw)=="string" and #raw>0 then
                    assert(#raw<=4096 and raw:sub(-1)=="\0","native argv truncated")
                    local words={}
                    for word in raw:gmatch("([^%z]+)%z") do
                        assert(#words<64,"native argv count");words[#words+1]=word
                    end
                    if M.is_actor(words) then return false end
                end
            end
        end
    end
    return true
end
return M
