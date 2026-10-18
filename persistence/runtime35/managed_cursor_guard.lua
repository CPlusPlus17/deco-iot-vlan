-- Own guard: preserve the exact caller argument list, including explicit nils.
-- Native UCI overloads set() by lua_gettop(); omitted and nil differ.
local M={}
function M.install(meta,managed)
    assert(type(meta)=="table" and type(managed)=="function","guard contract required")
    assert(not meta.__deco_iot_guard,"guard already installed")
    local old={}
    for _,name in ipairs({"set","section","tset","delete","set_list","add_list"}) do
        assert(type(meta[name])=="function","missing native cursor method")
        old[name]=meta[name]
    end
    local function protected(config,section)
        return config=="iot_wifi" and section=="iot" and managed()==true
    end
    local function check_value(value)
        assert(value=="0","native_iot_enable_managed_by_deco_vlan")
    end
    local function check_table(values)
        if values and values.enable~=nil then check_value(values.enable) end
    end
    meta.set=function(...)
        local self,config,section,option,value=...
        if protected(config,section) and option=="enable" then check_value(value) end
        return old.set(...)
    end
    meta.section=function(...)
        local self,config,kind,name,values=...
        if protected(config,name) then check_table(values) end
        return old.section(...)
    end
    meta.tset=function(...)
        local self,config,section,values=...
        if protected(config,section) then check_table(values) end
        return old.tset(...)
    end
    meta.delete=function(...)
        local self,config,section,option=...
        if config=="iot_wifi" and managed()==true
            and (section==nil or (section=="iot" and (option==nil or option=="enable"))) then
            error("native_iot_enable_removal_managed_by_deco_vlan")
        end
        return old.delete(...)
    end
    for _,name in ipairs({"set_list","add_list"}) do
        local method=name
        meta[method]=function(...)
            local self,config,section,option=...
            assert(not (protected(config,section) and option=="enable"),"native_iot_enable_list_forbidden")
            return old[method](...)
        end
    end
    meta.__deco_iot_guard=true
    return function()
        for name,fn in pairs(old) do meta[name]=fn end
        meta.__deco_iot_guard=nil
    end
end
return M
