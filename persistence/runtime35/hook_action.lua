-- Fixed mutating native hook action. NO arbitrary operation or source input.
local operation=arg and arg[1]
local phase,event
if type(operation)=="string" then
    phase,event=operation:match("^(before)_(%a+)$")
    if not phase then phase,event=operation:match("^(after)_(%a+)$") end
end
local caller_pid=arg and type(arg[2])=="string" and arg[2]:match("^%d+$") and tonumber(arg[2])
if not (arg and #arg==2 and caller_pid and caller_pid>1 and caller_pid<=4194304
    and caller_pid==math.floor(caller_pid) and (phase=="before" or phase=="after")
    and (event=="guest" or event=="network" or event=="firewall" or event=="wifi")) then os.exit(2) end
local ok,accepted=pcall(function()
    return assert(loadfile("/tmp/deco-iot-managed/event_broker.lua"))().change(event,phase=="before",nil,nil,nil,caller_pid)==true
end)
os.exit(ok and accepted and 0 or 1)
