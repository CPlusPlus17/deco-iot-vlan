-- Own-source data-only event barrier. Unknown/stale/partial state is held.
local M={}
local EVENTS={guest=true,network=true,firewall=true,wifi=true}
local function int(n) return type(n)=="number" and n==math.floor(n) and n>=1 end
local function key(event,pid,start) return event..":"..tostring(pid)..":"..tostring(start) end
local function validate(s,identity)
    assert(type(s)=="table" and s.schema==1 and type(s.entries)=="table"
        and s.device_id==identity.device_id and s.boot_id==identity.boot_id,"native event state binding")
    local count=0
    for name,item in pairs(s.entries) do
        count=count+1
        assert(count<=128 and type(item)=="table" and EVENTS[item.event] and int(item.pid) and item.pid>1
            and item.pid<=4194304 and int(item.start) and int(item.count) and item.count<=64
            and name==key(item.event,item.pid,item.start),"invalid native event record")
    end
    return s
end
local function copy(s)
    local out={schema=s.schema,device_id=s.device_id,boot_id=s.boot_id,entries={}}
    for k,v in pairs(s.entries) do out.entries[k]={event=v.event,pid=v.pid,start=v.start,count=v.count} end
    return out
end
function M.initial(identity)
    assert(type(identity)=="table" and type(identity.device_id)=="string" and #identity.device_id==40
        and type(identity.boot_id)=="string" and #identity.boot_id==36,"fresh event identity required")
    return {schema=1,device_id=identity.device_id,boot_id=identity.boot_id,entries={}}
end
function M.change(current,identity,event,parent,entering)
    validate(current,identity)
    assert(EVENTS[event] and type(entering)=="boolean" and type(parent)=="table" and int(parent.pid)
        and parent.pid>1 and parent.pid<=4194304 and int(parent.start),"fixed native caller required")
    local out=copy(current);local name=key(event,parent.pid,parent.start);local item=out.entries[name]
    if entering then
        if not item then item={event=event,pid=parent.pid,start=parent.start,count=0};out.entries[name]=item end
        assert(item.count<64,"native event nesting exceeded");item.count=item.count+1
    else
        assert(item and item.count>=1,"unmatched native event completion")
        item.count=item.count-1;if item.count==0 then out.entries[name]=nil end
    end
    validate(out,identity);return out
end
function M.empty(current,identity)
    local ok=pcall(validate,current,identity)
    return ok and next(current.entries)==nil
end
return M
