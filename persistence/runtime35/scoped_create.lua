-- Own fixed missing-IoT-VAP creation candidate. Not a claim that cold boot
-- has been verified. Production
-- requires a reviewed native-WiFi event gate plus fresh stable main snapshots.
local M={}
local function trim(s) return s and s:match('^%s*(.-)%s*$') end
local function projection(body,wiphy)
    assert(type(body)=='string' and #body<=4096,'native WiFi observation bound')
    local channel,kind,phy;local nc,nt,np=0,0,0
    for row in body:gmatch('[^\r\n]+') do
        local value=row:match('^%s*type%s+(%S+)%s*$')
        if value then kind=value;nt=nt+1 end
        value=row:match('^%s*wiphy%s+(%d+)%s*$')
        if value then phy=tonumber(value);np=np+1 end
        if row:match('^%s*channel%s') then
            value=row:match('^%s*(channel %d+ %(%d+ MHz%), width: %d+ MHz, center1: %d+ MHz)%s*$')
            assert(value,'unsupported native radio observation');channel=value;nc=nc+1
        end
    end
    assert(nt==1 and kind=='AP' and np==1 and phy==wiphy,'native AP parent/type changed')
    return channel,nc
end
local function copy_indices(p)
    local out={}
    for _,name in ipairs(p.io.dir('/sys/class/net')) do
        if name~='ath08' and name~='ath18' then out[name]=assert(p:index(name),'native interface disappeared') end
    end
    return out
end
local function indices_equal(a,b)
    for name,index in pairs(a) do if b[name]~=index then return false end end
    for name,index in pairs(b) do if a[name]~=index then return false end end
    return true
end
function M.create(p,name)
    assert(name=='ath08' or name=='ath18','fixed IoT target required')
    assert(type(p.hooks.verify_native_wifi_quiet)=='function','native WiFi quiescence hook unavailable')
    local radio,main,phy,wiphy=name=='ath08' and 'wifi0' or 'wifi2',name=='ath08' and 'ath02' or 'ath12',name=='ath08' and 'phy0' or 'phy2',name=='ath08' and 0 or 2
    local function gate()
        assert(p.hooks.verify_native_wifi_quiet(p)==true,'native WiFi actor not quiescent')
        assert(trim(p:read('/sys/class/net/'..radio..'/phy80211/name',128))==phy
            and trim(p:read('/sys/class/net/'..main..'/phy80211/name',128))==phy,'native physical parent changed')
    end
    gate();assert(not p:index(name),'existing VAP may not be adopted by creator')
    p:guard()
    local cursor=require('uci').cursor()
    local good,row=pcall(function()
        assert(cursor:load('wireless')==true,'native creation binding changed')
        return cursor:get_all('wireless',name)
    end)
    local closed,value=pcall(cursor.unload,cursor,'wireless')
    assert(good and closed and value==true and type(row)=='table','native creation binding changed')
    for option,expected in pairs({type='iot',mode='ap',device=radio,vapname=name}) do
        assert(type(row[option])=='string' and trim(row[option])==expected,'native creation binding changed')
    end
    p:guard()
    local old_indices=copy_indices(p)
    local old_channel,count=projection(p:command({'/usr/sbin/iw','dev',main,'info'}),wiphy)
    assert(old_channel and count==1,'running main-radio projection required')
    p.state.vap_creation=p.state.vap_creation or {}
    assert(not p.state.vap_creation[name],'prior creation requires explicit recovery')
    local intent={name=name,parent=radio,phy=phy,boot_id=p.context.boot_id,absent=true,phase='prepared'}
    p.state.vap_creation[name]=intent;p:save()
    local ok,why=pcall(function()
        gate();assert(not p:index(name),'target appeared before native clone command')
        local stable,n=projection(p:command({'/usr/sbin/iw','dev',main,'info'}),wiphy)
        assert(n==1 and stable==old_channel and indices_equal(old_indices,copy_indices(p)),'native WiFi snapshot not stable')
        -- Exact native create_vap arguments, with no wlanaddr/nosbeacon flags:
        -- both calls are required by the inspected cfg80211 native path.
        p:run({'/usr/sbin/wlanconfig',name,'create','wlandev',radio,'wlanmode','ap','-cfg80211'})
        gate();assert(not p:index(name),'unexpected clone-only creation: native behavior unproved')
        intent.phase='clone_parameters_sent';p:save()
        p:run({'/usr/sbin/iw','phy',phy,'interface','add',name,'type','__ap'})
        intent.ifindex=assert(p:index(name),'native creation returned without a VAP')
        intent.phase='created_unverified';p:save();gate()
        assert(trim(p:read('/sys/class/net/'..name..'/phy80211/name',128))==phy,'created VAP parent changed')
        projection(p:command({'/usr/sbin/iw','dev',name,'info'}),wiphy)
        assert(p:master(name)==nil,'new VAP already belongs to a foreign bridge')
        -- Only the now verified own AP interface may be held down or later used.
        p:run({'/bin/busybox','ifconfig',name,'down'})
        local flags=tonumber(trim(p:read('/sys/class/net/'..name..'/flags',128)))
        assert(flags and flags%2==0,'new VAP hold failed')
        assert(p:index(name)==intent.ifindex and indices_equal(old_indices,copy_indices(p)),'non-IoT interface indices changed')
        local after,n=projection(p:command({'/usr/sbin/iw','dev',main,'info'}),wiphy)
        assert(n==1 and after==old_channel,'main radio changed during scoped creation')
        p:verify_main_unchanged();intent.phase='verified_down';p:save();return true
    end)
    if not ok then
        -- No uncertain ifindex is deleted or adopted. The independent install
        -- transaction must reconcile this private journal and own rollback.
        p:clear_ready();p:hold_iot_down();error(why)
    end
    return true
end
return M
