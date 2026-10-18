-- Own-source offline prototype. Produces data only: no UCI setters, process
-- execution, file I/O, mesh transport or boot hook is present in this module.
local M={}
local MAX_GENERATION=2147483647
local function whole(value)
    return type(value)=="number" and value==math.floor(value)
        and value>=0 and value<=MAX_GENERATION
end
local function generation(value)
    if type(value)~="string" or not value:match("^%d+$") or #value>10 then return nil end
    local parsed=tonumber(value)
    if not whole(parsed) or tostring(parsed)~=value then return nil end
    return parsed
end
local OPTIONS={schema=true,enabled=true,vlan_id=true,main_untagged=true,
    generation=true,scope=true}
function M.read(section)
    if section==nil then
        return {configured=false,valid=true,enabled=false,generation=0,
            vlan_id=30,main_untagged=true,scope="all_three_wired"}
    end
    if type(section)~="table" then return {configured=true,valid=false,error="section_type"} end
    for key in pairs(section) do
        if type(key)~="string" or (key:sub(1,1)~="." and not OPTIONS[key]) then
            return {configured=true,valid=false,error="unknown_option"}
        end
    end
    local number=generation(section.generation)
    if (section[".type"] and section[".type"]~="policy")
        or (section[".name"] and section[".name"]~="iot")
        or section.schema~="1" or (section.enabled~="0" and section.enabled~="1")
        or section.vlan_id~="30" or section.main_untagged~="1"
        or section.scope~="all_three_wired" or not number then
        return {configured=true,valid=false,error="fixed_policy_invalid"}
    end
    return {configured=true,valid=true,schema=1,enabled=section.enabled=="1",
        vlan_id=30,main_untagged=true,generation=number,scope="all_three_wired"}
end
local function require_policy(policy)
    assert(type(policy)=="table" and policy.valid==true and policy.schema==1
        and type(policy.enabled)=="boolean" and policy.vlan_id==30
        and policy.main_untagged==true and whole(policy.generation)
        and policy.scope=="all_three_wired","invalid fixed policy")
end
function M.options(policy)
    require_policy(policy)
    return {schema="1",enabled=policy.enabled and "1" or "0",vlan_id="30",
        main_untagged="1",generation=tostring(policy.generation),scope="all_three_wired"}
end
function M.serialize(policy)
    local options=M.options(policy)
    local text="config policy 'iot'\n"
    for _,name in ipairs({"schema","enabled","vlan_id","main_untagged","generation","scope"}) do
        text=text.."\toption "..name.." '"..options[name].."'\n"
    end
    return text
end
function M.prepare(current,request)
    assert(type(current)=="table" and current.valid==true and whole(current.generation),"current policy invalid")
    assert(type(request)=="table","request must be data")
    local allowed={enabled=true,vlan_id=true,main_untagged=true,expected_generation=true}
    for key in pairs(request) do assert(allowed[key],"unknown policy request field") end
    assert(type(request.enabled)=="boolean" and request.vlan_id==30 and request.main_untagged==true,"fixed policy required")
    assert(whole(request.expected_generation) and request.expected_generation==current.generation,"stale policy generation")
    assert(current.generation<MAX_GENERATION,"generation exhausted")
    local desired={configured=true,valid=true,schema=1,enabled=request.enabled,vlan_id=30,
        main_untagged=true,generation=current.generation+1,scope="all_three_wired"}
    return {desired=desired,uci_options=M.options(desired),uci_text=M.serialize(desired),
        local_package="deco_iot_vlan",local_section="iot",network_configuration_changed=false,
        durable_save_performed=false,mesh_sync_performed=false,boot_loader_available=false}
end
return M
