-- Own fixed UCI registrations for kernel_platform.lua. No standalone CLI.
-- Native callback/installation verification hooks are supplied separately.
local M={}
local SW_VALUES={device='switch1',vlan='30',vid='30',ports='2t 6t'}
local NET_VALUES={proto='none',ifname='br-iot',auto='0',ipv6='0',delegate='0'}
local function copy(value)
    if type(value)~='table' then return value end
    local out={};for key,item in pairs(value) do out[key]=copy(item) end;return out
end
local function equal(a,b)
    if type(a)~=type(b) then return false end
    if type(a)~='table' then return a==b end
    for key,value in pairs(a) do if not equal(value,b[key]) then return false end end
    for key in pairs(b) do if a[key]==nil then return false end end
    return true
end
local function equal_section(row,kind,name,values)
    if type(row)~='table' or row['.type']~=kind or row['.name']~=name then return false end
    for key,value in pairs(values) do if row[key]~=value then return false end end
    for key in pairs(row) do if key:sub(1,1)~='.' and values[key]==nil then return false end end
    return true
end
local function native_reader(dir,package,name)
    local cursor=require('luci.model.uci').cursor(dir)
    local out=cursor:get_all(package,name);cursor:unload(package);return out
end
function M.new(options)
    local get=(options and options.read_section) or native_reader
    local creator=options and options.creation_module
    local event_state=options and options.event_state
    local hooks={}
    local function register(platform,dir,package,name,kind,values,field)
        local current=get(dir,package,name)
        local saved=platform.state[field]
        local expected={name=name}
        if field=='load_section' then expected.type=kind end
        for key,value in pairs(values) do expected[key]=value end
        if saved then
            for key,value in pairs(expected) do assert(saved[key]==value,'journal section binding changed') end
        end
        if current then
            assert(saved,'foreign native section')
            if equal_section(current,kind,name,values) then
                if platform.state[field..'_intent'] then platform.state[field..'_intent']=false;platform:save() end
                return true
            end
            -- Resume only our journaled creation with an exact expected subset.
            assert(platform.state[field..'_intent']==true and current['.type']==kind
                and current['.name']==name,'foreign or incomplete native section')
            for key,value in pairs(current) do
                assert(key:sub(1,1)=='.' or values[key]==value,'foreign native section content')
            end
        else
            assert(not saved or platform.state[field..'_intent']==true,'owned native section disappeared')
            -- Journal exclusive absence and intended content before the first set.
            platform.state[field..'_intent']=true
            platform.state[field]=expected;platform:save()
        end
        local prefix={'/sbin/uci'}
        if dir then prefix[#prefix+1]='-c';prefix[#prefix+1]=dir end
        local function set(key,value)
            local args={};for _,v in ipairs(prefix) do args[#args+1]=v end
            args[#args+1]='set';args[#args+1]=package..'.'..name..(key and '.'..key or '')..'='..value
            platform:run(args)
        end
        if not current then set(nil,kind) end
        for _,key in ipairs(field=='load_section' and {'device','vlan','vid','ports'} or {'proto','ifname','auto','ipv6','delegate'}) do set(key,values[key]) end
        local args={};for _,v in ipairs(prefix) do args[#args+1]=v end
        args[#args+1]='commit';args[#args+1]=package;platform:run(args)
        assert(equal_section(get(dir,package,name),kind,name,values),'native section readback failed')
        platform.state[field..'_intent']=false;platform:save();return true
    end
    function hooks.register_switch_load(platform)
        return register(platform,'/etc/vlan.d','vlan','deco_iot','switch_vlan',SW_VALUES,'load_section')
    end
    function hooks.register_owned_iot_network(platform)
        return register(platform,nil,'network','iot','interface',NET_VALUES,'network_section')
    end
    function hooks.verify_registered_network(platform)
        local saved=platform.state.network_section
        assert(saved and saved.name=='iot','network ownership missing')
        for key,value in pairs(NET_VALUES) do assert(saved[key]==value,'network journal changed') end
        return equal_section(get(nil,'network','iot'),'interface','iot',NET_VALUES)
    end
    function hooks.band_enabled(platform,name)
        local option
        if name=='ath08' then option='enable_2g' elseif name=='ath18' then option='enable_5g' else error('unsupported IoT VAP') end
        local row=get(nil,'iot_wifi','iot')
        assert(type(row)=='table' and row.enable=='0','native IoT writer guard changed')
        assert(row[option]=='0' or row[option]=='1','explicit native band flag required')
        return platform.policy.valid==true and platform.policy.enabled==true and row[option]=='1'
    end
    function hooks.verify_native_wifi_quiet(platform)
        platform:guard()
        local raw=platform:read('/tmp/deco-iot-managed/active-events.json',32768)
        assert(type(raw)=='string','native event state unavailable')
        local value=platform.io.decode(raw)
        if not event_state then event_state=assert(loadfile('/tmp/deco-iot-managed/event_state.lua'))() end
        return event_state.empty(value,{device_id=platform.context.device_id,boot_id=platform.context.boot_id})==true
    end
    function hooks.regenerate_iot_vaps_only(platform)
        local attempted={}
        local ok,why=pcall(function()
            platform:hold_iot_down()
            platform.state.vap_refresh_intent=platform.state.vap_refresh_intent or {}
            for _,name in ipairs({'ath08','ath18'}) do
                local enabled=hooks.band_enabled(platform,name)
                local before=get(nil,'wireless',name)
                local radio=name=='ath08' and 'wifi0' or 'wifi2'
                assert(type(before)=='table' and before.type=='iot' and before.mode=='ap'
                    and before.device==radio and before.vapname==name,'native IoT VAP binding changed')
                before=copy(before)
                local index=platform:index(name)
                if not index and enabled then
                    if not creator then creator=assert(loadfile('/tmp/deco-iot-managed/scoped_create.lua'))() end
                    assert(creator.create(platform,name)==true,'scoped IoT VAP creation failed')
                    index=assert(platform:index(name),'created IoT VAP absent')
                end
                platform.state.vap_refresh_intent[name]={ifindex=index,old_network=before.network,
                    old_disabled=before.disabled,enabled=enabled,phase='prepared'};platform:save()
                platform:run({'/sbin/uci','set','wireless.'..name..'.network=iot'})
                platform:run({'/sbin/uci','set','wireless.'..name..'.disabled='..(enabled and '0' or '1')})
                local after=get(nil,'wireless',name)
                assert(after.network=='iot' and after.disabled==(enabled and '0' or '1'),'IoT generation readback')
                for key,value in pairs(before) do
                    assert(key=='network' or key=='disabled' or equal(after[key],value),'non-target WiFi field changed')
                end
                for key in pairs(after) do assert(before[key]~=nil or key=='network' or key=='disabled','unexpected WiFi field appeared') end
                if enabled then
                    local master=platform:master(name)
                    assert(master==nil or master==platform.state.private_bridge_id or master==platform:bridge('br-lan'),
                        'foreign IoT VAP master')
                    if master and master~=platform.state.private_bridge_id then
                        platform:run({'/usr/sbin/brctl','delif','br-lan',name})
                    end
                    if master~=platform.state.private_bridge_id then
                        platform:run({'/usr/sbin/brctl','addif','br-iot',name})
                    end
                    assert(platform:master(name)==platform.state.private_bridge_id and platform:index(name)==index,'IoT private attach failed')
                    attempted[name]=true
                    platform.state.vap_refresh_intent[name].phase='refreshing';platform:save()
                    local output=platform:command({'/bin/sh','/tmp/deco-iot-managed/scoped_vap.sh',name})
                    assert(output=='DECO_IOT_VAP_REFRESHED\n','scoped native refresh not attested')
                    platform:run({'/bin/busybox','ifconfig',name,'up'})
                    assert(platform:master(name)==platform.state.private_bridge_id and platform:index(name)==index,'IoT private binding changed')
                end
                platform.state.vap_refresh_intent[name].phase='complete';platform:save()
            end
            return true
        end)
        if not ok then
            platform:clear_ready()
            local stopped=true
            for _,name in ipairs({'ath08','ath18'}) do if attempted[name] then
                -- The bounded runner must first quiesce the failed helper's
                -- owned process group. A request already queued in hostapd
                -- still needs its own target-only REMOVE barrier afterward.
                -- This emergency operation bypasses a revoked normal epoch.
                local clean,accepted=pcall(function()
                    local function snapshot()
                        local body,code=platform.io.command({'/usr/sbin/wpa_cli','-g','/var/run/hostapd/global','raw','INTERFACES'})
                        assert(code==0 and type(body)=='string' and #body<=4096,'BSS cleanup observation unavailable')
                        local seen={};local count=0
                        for row in body:gmatch('[^\r\n]+') do
                            count=count+1;assert(count<=64 and row:match('^ath%d+$') and not seen[row],'BSS cleanup observation format')
                            seen[row]=true
                        end
                        return body,seen
                    end
                    local before,seen=snapshot()
                    local output,code=platform.io.command({'/usr/sbin/wpa_cli','-g','/var/run/hostapd/global','raw','REMOVE',name})
                    if code~=0 then return false end
                    local reply=output:match('^%s*(.-)%s*$')
                    if reply=='OK' then return true end
                    if reply~='FAIL' or seen[name] then return false end
                    local after,remaining=snapshot()
                    if before~=after or remaining[name] then return false end
                    -- Native all-three proof attests FAIL for an absent BSS.
                    -- An existing kernel VAP must still be our exact down/private
                    -- target; otherwise absence is not an ownership substitute.
                    local current=platform:index(name)
                    return not current or (current==platform.state.vap_refresh_intent[name].ifindex
                        and platform:master(name)==platform.state.private_bridge_id)
                end)
                if not clean or not accepted then stopped=false end
            end end
            local down,held=pcall(platform.hold_iot_down,platform)
            if not stopped then error('scoped_refresh_cleanup_unverified') end
            assert(down and held==true,'scoped_refresh_hold_failed')
            error(why)
        end
        return true
    end
    return hooks
end
return M
