-- Own fixed XE75 Pro V3 IoT30 kernel adapter. No CLI or arbitrary operations.
-- Native hooks, installation transaction and fresh fleet attestation are
-- mandatory dependencies; this module alone is NOT an installed service.
local M={}
local BASE='/tmp/deco-iot-managed'
local BB,BR,IP,SW='/bin/busybox','/usr/sbin/brctl','/usr/sbin/ip','/sbin/swconfig'
local VAPS={'ath08','ath18'}
local RULES={{'INPUT','-i','br-iot','-j','DROP'},
    {'FORWARD','-i','br-iot','!','-o','br-iot','-j','DROP'},
    {'FORWARD','-o','br-iot','!','-i','br-iot','-j','DROP'}}
local HOOKS={'verify_own_installation','install_native_writer_guard','install_generator_guard',
    'protect_network_cleanup','protect_guest_cleanup','wait_native_firewall_finished',
    'register_owned_iot_network','regenerate_iot_vaps_only'}
local function trim(s) return s and s:match('^%s*(.-)%s*$') end
local function copy(t)
    if type(t)~='table' then return t end
    local out={};for k,v in pairs(t) do out[k]=copy(v) end;return out
end
local function equal(a,b)
    if type(a)~=type(b) then return false end
    if type(a)~='table' then return a==b end
    for k,v in pairs(a) do if not equal(v,b[k]) then return false end end
    for k in pairs(b) do if a[k]==nil then return false end end
    return true
end
local function integer(n) return type(n)=='number' and n==math.floor(n) end
local function hex(s,n) return type(s)=='string' and #s==n and s:match('^[%x]+$')~=nil end
local LEASE_KEYS={'schema','nonce','device_id','boot_id','install_nonce','transaction','generation','enabled','deadline','pid','start','state'}
function M.lease_matches(current,wanted,now)
    if type(current)~='table' or type(wanted)~='table' or type(now)~='number' then return false end
    local count=0;for key in pairs(current)do local known=false;for _,name in ipairs(LEASE_KEYS)do if key==name then known=true end end;if not known then return false end;count=count+1 end
    local other=0;for key in pairs(wanted)do local known=false;for _,name in ipairs(LEASE_KEYS)do if key==name then known=true end end;if not known then return false end;other=other+1 end
    if count~=#LEASE_KEYS or other~=#LEASE_KEYS or not equal(current,wanted)then return false end
    return current.schema==1 and hex(current.nonce,32) and hex(current.device_id,40) and type(current.boot_id)=='string' and #current.boot_id==36
        and hex(current.install_nonce,32) and hex(current.transaction,32) and integer(current.generation) and current.generation>=1
        and type(current.enabled)=='boolean' and type(current.deadline)=='number' and current.deadline==current.deadline and current.deadline<math.huge and current.deadline>now
        and integer(current.pid) and current.pid>1 and type(current.start)=='string' and current.start:match('^[1-9]%d*$')~=nil and current.state=='running'
end
local function argv(binary,action,rule)
    local out={binary,'-w',action};for _,v in ipairs(rule) do out[#out+1]=v end;return out
end
-- Injected I/O is only for own-source virtual-kernel fixtures. Production uses
-- the exact native APIs and bounded fixed argv, never user-provided commands.
local function native(nonce)
    local nx,fs,json=require('nixio'),require('nixio.fs'),require('luci.json')
    -- The reviewed bootstrap verifies every own RAM module before entry here.
    local command_module=assert(loadfile(BASE..'/bounded_command.lua'))()
    local bounded=command_module.new{base=BASE,nonce=nonce}
    local io_adapter={encode=json.encode,decode=json.decode,uid=nx.getuid}
    function io_adapter.read(path,limit)
        local f=io.open(path,'rb');if not f then return nil end
        local body=f:read((limit or 32768)+1);local closed=f:close()
        assert(closed and type(body)=='string' and #body<=(limit or 32768),'bounded read failed')
        return body
    end
    function io_adapter.write(path,body)
        local f=assert(nx.open(path,'w','rw-------'),'owned file open failed')
        local ok,why=pcall(function()
            local offset=0
            while offset<#body do
                local count=f:write(body:sub(offset+1))
                assert(type(count)=='number' and count>0 and count<=#body-offset,'owned short write failed')
                offset=offset+count
            end
        end)
        local closed=f:close();assert(ok and closed,why or 'owned file close failed');return true
    end
    function io_adapter.atomic(path,body)
        io_adapter.write(path..'.next',body)
        assert(os.rename(path..'.next',path),'owned atomic publish failed');return true
    end
    function io_adapter.remove(path)
        if not fs.stat(path) then return true end
        return os.remove(path)==true
    end
    function io_adapter.command(args)
        return bounded:command(args)
    end
    io_adapter.command_id=command_module.command_id
    function io_adapter.time()
        return assert(tonumber((io_adapter.read('/proc/uptime',128) or ''):match('^[%d.]+')))
    end
    function io_adapter.actor()
        local raw=assert(io_adapter.read('/proc/self/stat',4096));local tail=assert(raw:match('^%d+ %b() (.+)$'))
        local fields={};for word in tail:gmatch('%S+')do fields[#fields+1]=word end
        return nx.getpid(),assert(fields[20])
    end
    function io_adapter.activation_lease()
        local path=BASE..'/activation-lease.json';local st,code=fs.stat(path);local link,lcode=fs.readlink(path)
        if not st then assert(code==2 and link==nil and lcode==2,'activation lease absence unknown');return nil end
        assert(link==nil and st.type=='reg' and st.uid==0 and st.gid==0 and st.nlink==1 and st.modestr=='rw-------' and st.size<=2048,'activation lease ownership invalid')
        local value=json.decode(assert(io_adapter.read(path,2048)));assert(type(value)=='table','activation lease malformed');return value
    end
    function io_adapter.current_policy()
        local c=require('uci').cursor();local policy=assert(loadfile(BASE..'/declarative_policy.lua'))().read(c:get_all('deco_iot_vlan','iot'))
        local native=c:get('iot_wifi','iot','enable');c:unload('deco_iot_vlan');c:unload('iot_wifi')
        local manifest=json.decode(assert(io_adapter.read(BASE..'/installation.json',32768)))
        return {policy=policy,manifest=manifest,native_iot_enable=native,
            attested=assert(loadfile(BASE..'/managed_control.lua'))().verify_attestation(manifest,policy)==true}
    end
    function io_adapter.pause() nx.nanosleep(0,100000000) end
    function io_adapter.role(name)
        local index=tonumber(trim(io_adapter.read('/sys/class/net/'..name..'/ifindex',128)))
        local phy=trim(io_adapter.read('/sys/class/net/'..name..'/phy80211/name',128))
        if phy and phy:match('^phy%d+$') then
            local c=require('uci').cursor();local row={kind='wireless',phy=phy,
                native_type=c:get('wireless',name,'type'),mode=c:get('wireless',name,'mode'),device=c:get('wireless',name,'device')}
            c:unload('wireless')
            if row.native_type and row.mode and row.device then return row end
        end
        local vid=name:match('^eth1%.([234])$')
        if vid then
            local text=io_adapter.read('/proc/net/vlan/'..name,4096) or ''
            if tonumber(text:match('VID:%s*(%d+)'))==tonumber(vid) and text:match('Device:%s*(%S+)')=='eth1' then
                return {kind='vlan',parent='eth1',vid=vid}
            end
        end
        -- No generic permission to adopt a recreated unknown main device.
        return {kind='fixed_index',index=index}
    end
    function io_adapter.dir(path)
        local out,seen={},0;for name in fs.dir(path) do
            if name~='.' and name~='..' then
                assert(seen<64 and #name<=32 and name:match('^[%w_.:-]+$'),'directory bound');seen=seen+1
                if path=='/sys/class/net' and name=='bonding_masters' then
                    local node=fs.stat(path..'/'..name);local link,code=fs.readlink(path..'/'..name)
                    assert(type(node)=='table' and node.type=='reg' and link==nil and code==22,'native class attribute unknown')
                else out[#out+1]=name end
            end
        end;return out
    end
    -- Fixed cold-only evidence; no caller-selected paths, commands or setters.
    function io_adapter.cold_guest_evidence()
        local function absent(path,proc)
            local st,code=fs.stat(path);local link,lcode=fs.readlink(path)
            return st==nil and link==nil and (code==2 or proc and code==3)
                and (lcode==2 or proc and lcode==3)
        end
        local function same_node(a,b)
            return a and b and a.dev==b.dev and a.ino==b.ino and a.type==b.type
                and a.uid==b.uid and a.gid==b.gid and a.nlink==b.nlink and a.size==b.size and a.modestr==b.modestr
        end
        local function owned(name,limit)
            local path=BASE..'/'..name;local st=assert(fs.stat(path));local link,code=fs.readlink(path)
            assert(link==nil and code==22 and st.type=='reg' and st.uid==0 and st.gid==0 and st.nlink==1
                and st.modestr=='rw-------' and st.size<=limit,'cold completion ownership unknown')
            local fd=assert(nx.open(path,nx.open_flags('rdonly','nonblock')+32768))
            local ok,body=pcall(function()
                assert(same_node(st,fd:stat()),'cold completion inode changed')
                local parts,total={},0
                while true do
                    local value=fd:read(math.min(8192,limit+1-total))
                    assert(type(value)=='string','cold completion read unknown')
                    if #value==0 then break end
                    total=total+#value;assert(total<=limit,'cold completion oversized');parts[#parts+1]=value
                end
                assert(total==st.size and same_node(st,fd:stat()) and same_node(st,fs.stat(path)),
                    'cold completion changed')
                local fresh,ecode=fs.readlink(path);assert(fresh==nil and ecode==22,'cold completion link changed')
                return table.concat(parts)
            end)
            local closed,value=pcall(fd.close,fd);assert(ok and closed and value==true,'cold completion close failed')
            return assert(json.decode(body),'cold completion malformed')
        end
        local out={pending=owned('pending.json',4096),events=owned('active-events.json',16384),
            firewall=owned('firewall-complete',2048),boot_parent=owned('boot-parent.json',2048),
            ready_absent=absent(BASE..'/ready.json'),vaps_absent={},private_absent={},children={}}
        local parent=out.boot_parent
        assert(integer(parent.pid) and parent.pid>1 and parent.pid<=4194304
            and integer(parent.start) and parent.start>0,'cold parent actor invalid')
        local root='/proc/'..tostring(parent.pid);local f,_,code=io.open(root..'/stat','rb')
        if f then
            local ok,body=pcall(f.read,f,4097);local closed,value=pcall(f.close,f)
            assert(ok and closed and value==true and type(body)=='string' and #body<=4096,'cold parent read unknown')
            local pid,rest=body:match('^(%d+) %b() (.+)$');assert(pid==tostring(parent.pid),'cold parent stat malformed')
            local fields={};for token in rest:gmatch('%S+') do fields[#fields+1]=token end
            assert(#fields>=20 and fields[20]:match('^[1-9]%d*$'),'cold parent start unavailable')
            out.parent_finished=tonumber(fields[20])~=parent.start
        else out.parent_finished=(code==2 or code==3) and absent(root,true) and absent(root..'/exe',true) end
        out.completion_parent_finished=false
        out.completion_parent_status='unknown'
        if out.pending.event=='wifi' then
        local parent={pid=out.pending.parent_pid,start=out.pending.parent_start}
        assert(integer(parent.pid) and parent.pid>1 and parent.pid<=4194304
            and integer(parent.start) and parent.start>0,'cold parent actor invalid')
        local root='/proc/'..tostring(parent.pid);local f,_,code=io.open(root..'/stat','rb')
        if f then
            local ok,body=pcall(f.read,f,4097);local closed,value=pcall(f.close,f)
            assert(ok and closed and value==true and type(body)=='string' and #body<=4096,'cold parent read unknown')
            local pid,rest=body:match('^(%d+) %b() (.+)$');assert(pid==tostring(parent.pid),'cold parent stat malformed')
            local fields={};for token in rest:gmatch('%S+') do fields[#fields+1]=token end
            assert(#fields>=20 and fields[20]:match('^[1-9]%d*$'),'cold parent start unavailable')
            if tonumber(fields[20])~=parent.start then out.completion_parent_status='finished'
            elseif ({R=true,S=true,D=true,T=true,t=true,W=true,K=true,P=true,I=true})[fields[1]] then
                out.completion_parent_status='live'
            end
        elseif (code==2 or code==3) and absent(root,true) and absent(root..'/exe',true) then
            out.completion_parent_status='finished'
        end
        out.completion_parent_finished=out.completion_parent_status=='finished'

        end
        for _,name in ipairs(VAPS) do out.vaps_absent[name]=absent('/sys/class/net/'..name) end
        out.private_absent.bridge=absent('/sys/class/net/br-iot')
        out.private_absent.vlan=absent('/sys/class/net/eth1.30')
        local c=require('uci').cursor()
        local function section(dir,package,name)
            local u=require('uci').cursor(dir);assert(u:load(package),'cold native package unavailable')
            local all=u:get_all(package);assert(type(all)=='table','cold native package unknown')
            local function semantic(row)
                if row==nil then return nil end;assert(type(row)=='table','cold native section unknown')
                local out={['.name']=row['.name'],['.type']=row['.type']}
                for key,value in pairs(row) do if key:sub(1,1)~='.' then out[key]=copy(value) end end;return out
            end
            local row=u:get_all(package,name);assert(equal(semantic(row),semantic(all[name])),'cold native named/package mismatch')
            local delta=u:changes(package);assert(type(delta)=='table','cold native delta unknown')
            for key,value in pairs(delta) do
                assert(key==package and type(value)=='table' and next(value)==nil,'cold native delta present')
            end
            u:unload(package);return row or false
        end
        out.load_section=section('/etc/vlan.d','vlan','deco_iot')
        out.network_section=section(nil,'network','iot')
        assert(c:load('wireless'),'cold wireless package unavailable')
        for _,spec in ipairs({{'ath02.1','ath02','wifi0','phy0'},{'ath12.1','ath12','wifi2','phy2'},
                {'ath22.1','ath22','wifi1','phy1'}}) do
            local name,base=spec[1],spec[2];local prefix='/sys/class/net/'
            local config=c:get_all('wireless',base);local fields={}
            for _,key in ipairs({'type','mode','device','network','wds','disabled','vapname'}) do fields[key]=config and config[key] or false end
            out.children[name]={parent=base,device=spec[3],phy=spec[4],config=fields,
                index=trim(io_adapter.read(prefix..name..'/ifindex',128)),parent_index=trim(io_adapter.read(prefix..base..'/ifindex',128)),
                iflink=trim(io_adapter.read(prefix..name..'/iflink',128)),lower_index=trim(io_adapter.read(prefix..name..'/lower_'..base..'/ifindex',128)),
                type=trim(io_adapter.read(prefix..name..'/type',128)),parent_type=trim(io_adapter.read(prefix..base..'/type',128)),
                address=trim(io_adapter.read(prefix..name..'/address',128)),parent_address=trim(io_adapter.read(prefix..base..'/address',128)),
                uevent=io_adapter.read(prefix..name..'/uevent',1024),parent_uevent=io_adapter.read(prefix..base..'/uevent',1024),
                parent_phy=trim(io_adapter.read(prefix..base..'/phy80211/name',128)),vlan=io_adapter.read('/proc/net/vlan/'..name,4096)}
        end
        c:unload('wireless');return out
    end
    -- Initial cold admission uses the same read-only evidence, with both
    -- known native parents and the complete fixed wireless configuration.
    function io_adapter.first_cold_evidence()
        local out=io_adapter.cold_guest_evidence()
        local function absent(path,proc)
            local st,code=fs.stat(path);local link,lcode=fs.readlink(path)
            return st==nil and link==nil and (code==2 or proc and code==3)
                and (lcode==2 or proc and lcode==3)
        end
        local function status(parent)
            assert(type(parent)=='table' and integer(parent.pid) and parent.pid>1 and parent.pid<=4194304
                and integer(parent.start) and parent.start>0,'first cold parent invalid')
            local root='/proc/'..tostring(parent.pid);local f,_,code=io.open(root..'/stat','rb')
            if not f then
                if (code==2 or code==3) and absent(root,true) and absent(root..'/exe',true) then return 'finished' end
                return 'unknown'
            end
            local good,body=pcall(f.read,f,4097);local closed,value=pcall(f.close,f)
            assert(good and closed and value==true and type(body)=='string' and #body<=4096,'first cold parent read unknown')
            local pid,tail=body:match('^(%d+) %b() (.+)$');assert(pid==tostring(parent.pid),'first cold parent stat malformed')
            local fields={};for word in tail:gmatch('%S+') do fields[#fields+1]=word end
            assert(#fields>=20 and #fields<=64 and fields[20]:match('^[1-9]%d*$'),'first cold parent start unknown')
            if tonumber(fields[20])~=parent.start then return 'finished' end
            if ({R=true,S=true,D=true,T=true,t=true,W=true,K=true,P=true,I=true})[fields[1]] then return 'live' end
            return 'unknown'
        end
        out.boot_parent_status=status(out.boot_parent)
        out.completion_parent_status=status({pid=out.pending.parent_pid,start=out.pending.parent_start})
        out.completion_parent_finished=out.completion_parent_status=='finished'
        out.state_absent=absent(BASE..'/state.json')
        out.configured_absent={}
        for _,name in ipairs({'ath0','ath1','ath2','ath01','ath11','ath21',
                'ath02.1','ath12.1','ath22.1','ath02','ath12','ath22'}) do
            out.configured_absent[name]=absent('/sys/class/net/'..name)
                and absent('/sys/class/net/'..name..'/ifindex')
        end
        out.configured={bss={},radios={}}
        local c=require('uci').cursor();assert(c:load('wireless')==true,'first cold wireless unavailable')
        local good,why=pcall(function()
            for _,name in ipairs({'ath0','ath1','ath2','ath01','ath11','ath21'}) do
                local row=assert(c:get_all('wireless',name),'first cold BSS missing');local fields={}
                for _,key in ipairs({'type','mode','device','vapname','disabled','network'}) do fields[key]=row[key] end
                out.configured.bss[name]=fields
            end
            for _,name in ipairs({'wifi0','wifi1','wifi2'}) do
                local row=assert(c:get_all('wireless',name),'first cold radio missing')
                out.configured.radios[name]={disabled=row.disabled}
            end
            local delta=c:changes('wireless');assert(type(delta)=='table','first cold wireless delta unknown')
            for key,row in pairs(delta) do
                assert(key=='wireless' and type(row)=='table' and next(row)==nil,'first cold wireless delta present')
            end
        end)
        local closed,value=pcall(c.unload,c,'wireless');assert(good and closed and value==true,why or 'first cold wireless unload failed')
        local u=require('uci').cursor(nil,'/var/state')
        local loaded=u:get('firewall','core','loaded');assert(u:unload('firewall')==true,'first cold firewall unload failed')
        out.firewall_loaded=loaded
        local mode=require('uci').cursor();out.mode=mode:get('sysmode','sysmode','mode')
        assert(mode:unload('sysmode')==true,'first cold mode unload failed')
        return out
    end
    function io_adapter.first_cold_state_absent()
        local path=BASE..'/state.json';local st,code=fs.stat(path);local link,lcode=fs.readlink(path)
        if st then
            assert(link==nil and lcode==22 and st.type=='reg' and st.uid==0 and st.gid==0 and st.nlink==1
                and st.modestr=='rw-------' and st.size<=32768,'first cold state ownership unknown')
            return false
        end
        assert(code==2 and link==nil and lcode==2,'first cold state absence unknown');return true
    end
    function io_adapter.lock()
        -- BusyBox stat, unlike this release's nixio.fs.lstat, does not follow
        -- symlinks. Bootstrap must have established this private directory.
        local body,code=io_adapter.command({BB,'stat','-c','%A|%u|%g',BASE})
        assert(code==0 and trim(body)=='drwx------|0|0','runtime directory ownership invalid')
        local fd=assert(nx.open(BASE..'/worker.lock','w','rw-------'),'worker lock open failed')
        local ok,held=pcall(fd.lock,fd,'tlock')
        if not ok or not held then fd:close();error('worker busy') end
        return fd
    end
    function io_adapter.unlock(fd) assert(fd:close(),'worker close failed') end
    return io_adapter
end
-- This gate runs before quiescence/worker.lock. It cannot publish state or
-- wait for a native parent while holding the parent's completion barrier.
local FIRST_BSS={{'ath0','wifi0','phy0','lan'},{'ath1','wifi2','phy2','lan'},
    {'ath2','wifi1','phy1','lan'},{'ath01','wifi0','phy0','guest'},
    {'ath11','wifi2','phy2','guest'},{'ath21','wifi1','phy1','guest'}}
local FIRST_CHILDREN={{'ath02.1','ath02','wifi0','phy0'},
    {'ath12.1','ath12','wifi2','phy2'},{'ath22.1','ath22','wifi1','phy1'}}
local function first_cold_identity(self)
    self:guard()
    assert(self.context.activation_lease==nil and self.io.activation_lease()==nil,'first cold activation present')
    assert(self.io.first_cold_state_absent()==true,'first cold state appeared')
    assert(trim(self:read('/tmp/sync-cached-MODEL',256))=='XE75Pro'
        and trim(self:read('/tmp/sync-cached-HARDVERSION',256))=='3.0'
        and trim(self:read('/tmp/sync-cached-SOFTVERSION',512))=='1.5.0 Build 20260603 Rel. 15804',
        'first cold firmware changed')
end
local function first_cold_pair(self,proof,event,waiting)
    local c=self.context
    assert(type(proof)=='table' and proof.state_absent==true and equal(proof.pending,event)
        and type(event)=='table' and event.schema==1 and event.device_id==c.device_id and event.boot_id==c.boot_id
        and event.pending==true and (event.event=='guest' or event.event=='wifi') and hex(event.completion_nonce,32)
        and integer(event.parent_pid) and event.parent_pid>1 and event.parent_pid<=4194304
        and integer(event.parent_start) and event.parent_start>0,'first cold completion missing')
    assert(type(proof.boot_parent)=='table' and proof.boot_parent.schema==1
        and proof.boot_parent.device_id==c.device_id and proof.boot_parent.boot_id==c.boot_id
        and (proof.boot_parent.loaded_before=='unset' or proof.boot_parent.loaded_before=='0'),
        'first cold boot source changed')
    local f=proof.firewall
    assert(type(f)=='table' and f.schema==1 and f.event=='firewall' and f.finished==true
        and f.device_id==c.device_id and f.boot_id==c.boot_id and f.source_event==event.event
        and f.completion_nonce==event.completion_nonce and f.parent_pid==event.parent_pid
        and f.parent_start==event.parent_start and proof.firewall_loaded=='1' and proof.mode=='AP',
        'first cold completion pair changed')
    local active=proof.events
    assert(type(active)=='table' and active.schema==1 and active.device_id==c.device_id and active.boot_id==c.boot_id
        and type(active.entries)=='table' and next(active.entries)==nil,'first cold event active')
    assert(proof.ready_absent==true and proof.private_absent.bridge==true and proof.private_absent.vlan==true
        and proof.load_section==false and proof.network_section==false,'first cold private resources present')
    for _,name in ipairs(VAPS) do assert(proof.vaps_absent[name]==true,'first cold VAP present') end
    for _,name in ipairs({'boot_parent_status','completion_parent_status'}) do
        assert(proof[name]=='finished' or waiting and proof[name]=='live','first cold parent unknown or active')
    end
end
local function first_cold_origin(row,index,spec)
    assert(type(row)=='table' and row.parent==spec[2] and row.device==spec[3] and row.phy==spec[4]
        and tonumber(row.index)==index and integer(tonumber(row.parent_index)) and tonumber(row.parent_index)>0
        and row.iflink==row.parent_index and row.lower_index==row.parent_index and row.type=='1' and row.parent_type=='1'
        and row.address==row.parent_address and type(row.address)=='string'
        and row.address:match('^%x%x:%x%x:%x%x:%x%x:%x%x:%x%x$') and row.parent_phy==spec[4]
        and equal(row.config,{type='backhaul',mode='ap',device=spec[3],network='backhaul',wds='1',disabled='0',vapname=spec[2]}),
        'first cold backhaul origin changed')
    for _,pair in ipairs({{row.uevent,'vlan'},{row.parent_uevent,'wlan'}}) do
        local count=0;for line in (pair[1] or ''):gmatch('[^\n]+') do
            local kind=line:match('^DEVTYPE=(.+)$');if kind then count=count+1;assert(kind==pair[2],'first cold device type changed') end
        end;assert(count==1,'first cold device type missing')
    end
    assert(type(row.vlan)=='string','first cold VLAN shape missing')
    local vids,devices=0,0
    for vid in row.vlan:gmatch('VID:%s*(%d+)') do vids=vids+1;assert(vid=='1','first cold child VID changed') end
    for device in row.vlan:gmatch('Device:%s*(%S+)') do devices=devices+1;assert(device==spec[2],'first cold child parent changed') end
    assert(vids==1 and devices==1,'first cold child shape ambiguous')
end
local function first_cold_projection(actual,proof,waiting)
    local complete=true
    assert(type(actual)=='table' and type(actual.members)=='table' and type(actual.roles)=='table'
        and equal(actual.pvids,{['0']='2',['1']='3',['2']='4',['6']='1'}),'first cold main PVID changed')
    local allowed={};local configured=proof.configured
    assert(type(configured)=='table' and type(configured.bss)=='table' and type(configured.radios)=='table',
        'first cold wireless configuration missing')
    for _,name in ipairs({'wifi0','wifi1','wifi2'}) do
        assert(equal(configured.radios[name],{disabled='0'}),'first cold radio not enabled')
    end
    for _,spec in ipairs(FIRST_BSS) do
        local name=spec[1];allowed[name]=true
        assert(equal(configured.bss[name],{type=spec[4],mode='ap',device=spec[2],vapname=name,disabled='0',network='lan'})
            ,'first cold configured BSS changed')
        if actual.members[name]==nil then
            assert(waiting==true and proof.configured_absent[name]==true and actual.roles[name]==nil,
                'first cold configured BSS absence unknown');complete=false
        else
            assert(integer(actual.members[name]) and actual.members[name]>0
                and equal(actual.roles[name],{kind='wireless',native_type=spec[4],mode='ap',device=spec[2],phy=spec[3]}),
                'first cold configured BSS incomplete')
        end
    end
    for _,spec in ipairs(FIRST_CHILDREN) do
        local name=spec[1];allowed[name]=true
        local row=proof.children[name]
        if actual.members[name]==nil then
            assert(waiting==true and proof.configured_absent[name]==true and actual.roles[name]==nil,
                'first cold backhaul absence unknown');complete=false
            assert(type(row)=='table' and equal(row.config,{type='backhaul',mode='ap',device=spec[3],
                network='backhaul',wds='1',disabled='0',vapname=spec[2]}),'first cold backhaul configuration changed')
            if proof.configured_absent[spec[2]]~=true then
                assert(integer(tonumber(row.parent_index)) and tonumber(row.parent_index)>0 and row.parent_type=='1'
                    and row.parent_phy==spec[4] and type(row.parent_address)=='string'
                    and row.parent_address:match('^%x%x:%x%x:%x%x:%x%x:%x%x:%x%x$'),
                    'first cold backhaul parent unknown')
                local count=0
                for line in (row.parent_uevent or ''):gmatch('[^\n]+') do
                    local kind=line:match('^DEVTYPE=(.+)$')
                    if kind then count=count+1;assert(kind=='wlan','first cold backhaul parent changed') end
                end;assert(count==1,'first cold backhaul parent unknown')
            end
        else
            assert(integer(actual.members[name]) and actual.members[name]>0
                and equal(actual.roles[name],{kind='fixed_index',index=actual.members[name]}),'first cold backhaul incomplete')
            first_cold_origin(row,actual.members[name],spec)
        end
    end
    for _,vid in ipairs({'2','3','4'}) do
        local name='eth1.'..vid;allowed[name]=true
        assert(integer(actual.members[name]) and actual.members[name]>0
            and equal(actual.roles[name],{kind='vlan',parent='eth1',vid=vid})
            and actual.vlans[vid]==({['2']='0 6t',['3']='1 6t',['4']='2 6t'})[vid],'first cold core VLAN changed')
    end
    local tagged={};assert(type(actual.vlans['591'])=='string','first cold guest VLAN unknown')
    for port in actual.vlans['591']:gmatch('%S+') do
        assert(({['0t']=true,['1t']=true,['2t']=true,['6t']=true})[port] and not tagged[port],'first cold guest VLAN changed');tagged[port]=true
    end
    for name in pairs(actual.members) do assert(allowed[name],'first cold foreign main member') end
    for name in pairs(actual.roles) do assert(allowed[name],'first cold foreign main role') end
    return complete
end
local function first_cold_stable(proof,members)
    local result=copy(proof)
    local labels={'         total frames received','          total bytes received',
        '      Broadcast/Multicast Rcvd','      total frames transmitted','       total bytes transmitted'}
    for _,spec in ipairs(FIRST_CHILDREN) do
        if members==nil or members[spec[1]]~=nil then
        local row=result.children[spec[1]];local counts={}
        row.vlan=row.vlan:gsub('([^\n]*)\n',function(line)
            for i,label in ipairs(labels) do if line:sub(1,#label)==label then
                counts[i]=(counts[i] or 0)+1
                assert(counts[i]==1 and line:match('^'..label..' +%d+$'),'first cold counter format changed')
                return label..' <counter>\n'
            end end;return line..'\n'
        end)
        for i in ipairs(labels) do assert(counts[i]==1,'first cold counter missing') end
        else result.children[spec[1]]=nil end
    end
    return result
end
local function first_cold_progress(previous,current)
    if not previous then return current end
    local old,actual=previous.baseline,current.baseline
    local projected=copy(actual);projected.members=copy(old.members);projected.roles=copy(old.roles)
    assert(equal(projected,old),'first cold core changed while settling')
    for name,index in pairs(old.members) do
        assert(actual.members[name]==index and equal(actual.roles[name],old.roles[name]),
            'first cold configured member changed while settling')
    end
    assert(equal(previous.proof.configured,current.proof.configured)
        and equal(previous.proof.boot_parent,current.proof.boot_parent),'first cold provenance changed while settling')
    for _,spec in ipairs(FIRST_CHILDREN) do
        local name=spec[1];local before,after=previous.proof.children[name],current.proof.children[name]
        if previous.proof.configured_absent[spec[2]]~=true then
            for _,field in ipairs({'parent_index','parent_type','parent_address','parent_uevent','parent_phy','config'}) do
                assert(equal(before[field],after[field]),'first cold backhaul parent changed while settling')
            end
        end
        if old.members[name] then
            local a=first_cold_stable(previous.proof,old.members).children[name]
            local b=first_cold_stable(current.proof,actual.members).children[name]
            assert(equal(a,b),'first cold backhaul origin changed while settling')
        end
    end
    return current
end
function M:first_cold_observation(event,waiting)
    first_cold_identity(self)
    local proof=self.io.first_cold_evidence();self:guard()
    first_cold_pair(self,proof,event,waiting)
    if waiting and (proof.boot_parent_status=='live' or proof.completion_parent_status=='live') then return nil end
    assert(self.hooks.verify_native_wifi_quiet(self)==true,'first cold native WiFi not quiet')
    self:guard()
    assert(self:ports(30)=='','first cold hardware VLAN occupied')
    for _,binary in ipairs({'/usr/sbin/iptables','/usr/sbin/ip6tables'}) do for _,rule in ipairs(RULES) do
        local _,code=self.io.command(argv(binary,'-C',rule));assert(code==1,'first cold firewall rule present or unknown')
        self:guard()
    end end
    local actual=self:baseline();local complete=first_cold_projection(actual,proof,waiting)
    if not complete then return {incomplete=true,baseline=actual,proof=proof} end
    return {baseline=actual,proof=proof}
end
function M.prepare_first_cold(options)
    options=options or {};local bootstrap=options.io
    if not bootstrap then
        local json=require('luci.json');local f=assert(io.open(BASE..'/installation.json','rb'))
        local raw=f:read(32769);local closed=f:close()
        assert(closed and type(raw)=='string' and #raw<=32768,'first cold manifest read failed')
        local m=json.decode(raw);assert(type(m)=='table' and hex(m.install_nonce,32),'first cold manifest unavailable')
        bootstrap=native(m.install_nonce)
    end
    local started=bootstrap.time()
    if bootstrap.first_cold_state_absent()~=true then return nil end
    local fresh=bootstrap.current_policy();local p,m=fresh.policy,fresh.manifest
    assert(type(p)=='table' and p.valid==true and p.configured==true and type(m)=='table','first cold policy unavailable')
    if p.enabled~=true then return nil end
    local self=setmetatable({io=bootstrap,policy=copy(p),manifest=copy(m),closed=false,started=started,
        hooks=options.hooks or assert(loadfile(BASE..'/hook_callbacks.lua'))().new(m),
        context={uid=0,device_id=trim(bootstrap.read('/tmp/sync-cached-DEV_ID',128)),
            boot_id=trim(bootstrap.read('/proc/sys/kernel/random/boot_id',128)),
            epoch=trim(bootstrap.read(BASE..'/epoch',64)),native_iot_enable='0'}},{__index=M})
    first_cold_identity(self)
    local event=copy(bootstrap.first_cold_evidence().pending)
    local first,progress
    repeat
        local observed=self:first_cold_observation(event,true)
        if observed then
            progress=first_cold_progress(progress,observed)
            if observed.incomplete~=true then first=observed end
        else assert(progress==nil,'first cold finished parent changed') end
        if not first then self:guard();self.io.pause();self:guard() end
    until first
    self:guard();self.io.pause();self:guard()
    local second=self:first_cold_observation(event,false)
    first.proof=first_cold_stable(first.proof);second.proof=first_cold_stable(second.proof)
    assert(equal(first,second),'first cold baseline or completion unstable')
    return {schema=1,started=self.started,device_id=self.context.device_id,boot_id=self.context.boot_id,
        install_nonce=m.install_nonce,generation=p.generation,policy=copy(p),manifest=copy(m),event=event,
        observation=second}
end
function M:revalidate_first_cold(token)
    assert(type(token)=='table' and token.schema==1 and type(token.started)=='number' and token.started<=self.io.time()
        and self.started==token.started and token.device_id==self.context.device_id and token.boot_id==self.context.boot_id
        and token.install_nonce==self.manifest.install_nonce and token.generation==self.policy.generation
        and equal(token.policy,self.policy) and equal(token.manifest,self.manifest),'first cold token superseded')
    local fresh=self:first_cold_observation(token.event,false)
    fresh.proof=first_cold_stable(fresh.proof)
    assert(equal(fresh,token.observation),'first cold locked observation changed')
    return true
end
function M.new(options)
    assert(type(options)=='table' and type(options.hooks)=='table','reviewed hooks required')
    assert(type(options.manifest)=='table' and hex(options.manifest.install_nonce,32),'own manifest required')
    local self={io=options.io or native(options.manifest.install_nonce),policy=copy(options.policy),context=copy(options.context),
        manifest=copy(options.manifest),hooks=options.hooks,closed=false}
    local p,c,m=self.policy,self.context,self.manifest
    assert(type(p)=='table' and p.configured==true and p.valid==true and integer(p.generation) and p.generation>=1,'valid own policy required')
    assert(type(c)=='table' and c.uid==0 and hex(c.device_id,40) and type(c.boot_id)=='string' and #c.boot_id==36
        and hex(c.epoch,32) and c.native_iot_enable=='0','fresh native context required')
    assert(type(m)=='table' and m.schema==1 and hex(m.install_nonce,32) and m.device_id==c.device_id,'owned installation required')
    for _,names in ipairs({HOOKS,{'register_switch_load','verify_registered_network','band_enabled'}}) do
        for _,name in ipairs(names) do assert(type(self.hooks[name])=='function','missing reviewed hook: '..name) end
    end
    self.lock=self.io.lock();self.started=options.first_cold and options.first_cold.started or self.io.time()
    setmetatable(self,{__index=M})
    local ok,why=pcall(function()
        self:guard()
        if options.first_cold then
            self:revalidate_first_cold(options.first_cold);self.first_cold=copy(options.first_cold)
        elseif self.policy.enabled and self.context.activation_lease==nil then
            assert(self.io.first_cold_state_absent()~=true,'first cold admission required')
        end
        self:load_state()
    end)
    if not ok then self:close();error(why) end
    return self
end
function M:close()
    if self.closed then return end
    self.closed=true;if self.lock then self.io.unlock(self.lock);self.lock=nil end
end
function M:guard()
    assert(not self.closed and self.io.uid()==0,'worker context unavailable')
    assert(self.io.time()-self.started<90,'worker deadline')
    assert(trim(self.io.read('/tmp/sync-cached-DEV_ID',128))==self.context.device_id,'device changed')
    assert(trim(self.io.read('/proc/sys/kernel/random/boot_id',128))==self.context.boot_id,'boot changed')
    local fresh=self.io.current_policy();local p,m=fresh.policy,fresh.manifest
    assert(type(p)=='table' and p.configured==true and p.valid==true and p.generation==self.policy.generation and p.enabled==self.policy.enabled
        and fresh.native_iot_enable=='0' and type(m)=='table' and m.device_id==self.context.device_id and m.boot_id==self.context.boot_id
        and m.install_nonce==self.manifest.install_nonce and m.generation==self.policy.generation and m.committed==true and m.native_iot_saved_disabled==true
        and (not p.enabled or fresh.attested==true),'current policy or installation superseded')
    local lease=self.io.activation_lease()
    if self.context.activation_lease then
        local wanted=self.context.activation_lease;local pid,start=self.io.actor()
        assert(M.lease_matches(lease,wanted,self.io.time()) and wanted.pid==pid and wanted.start==start
            and wanted.device_id==self.context.device_id and wanted.boot_id==self.context.boot_id and wanted.install_nonce==self.manifest.install_nonce
            and wanted.generation==self.policy.generation and wanted.enabled==self.policy.enabled,'activation lease revoked or superseded')
    else assert(lease==nil,'activation lease requires its own worker')end
    assert(trim(self.io.read(BASE..'/epoch',64))==self.context.epoch,'event superseded')
    local events=self.io.decode(assert(self.io.read(BASE..'/active-events.json',16384),'native event barrier missing'))
    assert(type(events)=='table' and events.schema==1 and events.device_id==self.context.device_id
        and events.boot_id==self.context.boot_id and type(events.entries)=='table'
        and next(events.entries)==nil,'native operation remains active')
    local body,code=self.io.command({'/sbin/uci','-q','get','iot_wifi.iot.enable'})
    assert(code==0 and trim(body)=='0','native IoT enable must stay disabled')
end
local FAILURE_IDS={other_reviewed_command=true,native_iot_zero=true,switch_enabled=true,pvid_2=true,pvid_6=true,
    gateway_ping=true,gateway_fdb=true,main_addresses=true,default_routes=true,vlan_2=true,vlan_3=true,
    vlan_4=true,vlan_591=true,pvid_0=true,pvid_1=true}
local function failure_command_id(io_adapter,args)
    if type(args)=='table' then
        if #args==3 and args[1]=='/bin/sh' and args[2]==BASE..'/scoped_vap.sh' then
            if args[3]=='ath08' then return 'scoped_vap_ath08' elseif args[3]=='ath18' then return 'scoped_vap_ath18' end
        elseif #args==4 and args[1]==BB and args[2]=='ifconfig' and args[4]=='up' then
            if args[3]=='ath08' then return 'vap_up_ath08' elseif args[3]=='ath18' then return 'vap_up_ath18' end
        end
    end
    local ok,id=pcall(function()return io_adapter.command_id and io_adapter.command_id(args)end)
    return ok and FAILURE_IDS[id] and id or 'other_reviewed_command'
end
function M:command(args)
    self:guard();local body,code=self.io.command(args)
    if self.command_failure==nil and type(code)=='number' and code==math.floor(code) and code>=1 and code<=255 then
        self.command_failure={schema=1,command_id=failure_command_id(self.io,args),exit_status=code}
    end
    assert(code==0,'fixed kernel command failed');self:guard();return body
end
function M:run(args) self:command(args);return true end
function M:read(path,limit) return self.io.read(path,limit) end
function M:index(name) return tonumber(trim(self:read('/sys/class/net/'..name..'/ifindex',128))) end
function M:bridge(name) return trim(self:read('/sys/class/net/'..name..'/bridge/bridge_id',128)) end
function M:master(name) return trim(self:read('/sys/class/net/'..name..'/master/bridge/bridge_id',128)) end
function M:ports(vid) return trim(self:command({SW,'dev','switch1','vlan',tostring(vid),'get','ports'})):gsub('%s+',' ') end
function M:pvid(port) return trim(self:command({SW,'dev','switch1','port',tostring(port),'get','pvid'})) end
function M:save()
    self:guard();assert(self.io.atomic(BASE..'/state.json',self.io.encode(self.state)))
end
function M:load_state()
    local raw=self:read(BASE..'/state.json')
    if raw then
        local s=self.io.decode(raw)
        assert(s.schema==1 and s.install_nonce==self.manifest.install_nonce and s.device_id==self.context.device_id
            and s.boot_id==self.context.boot_id,'foreign ownership journal')
        self.state=s
        -- A new lifecycle may reuse only the exact resources this installation
        -- already owns in this boot; indices are freshly verified below.
        self.state.epoch=self.context.epoch;self.state.generation=self.policy.generation
    else
        assert(not self:index('br-iot') and not self:index('eth1.30') and self:ports(30)=='','foreign private resources')
        self.state={schema=1,install_nonce=self.manifest.install_nonce,device_id=self.context.device_id,
            boot_id=self.context.boot_id,generation=self.policy.generation,epoch=self.context.epoch,rules={}}
    end
end
function M:clear_ready()
    -- Emergency operation: independent of the normal epoch/deadline guard.
    assert(self.io.uid()==0 and self.io.remove(BASE..'/ready.json'),'readiness clear failed');return true
end
function M:hold_iot_down()
    -- Never attach a VAP to LAN as a recovery action. A VAP is only touched
    -- after its current native type has been checked, including recreated VAPs.
    local failures=0
    for _,name in ipairs(VAPS) do
        local ok=pcall(function() if self:index(name) then
            local body,code=self.io.command({'/sbin/uci','-q','get','wireless.'..name..'.type'})
            assert(code==0 and trim(body)=='iot','IoT VAP type changed')
            local _,status=self.io.command({BB,'ifconfig',name,'down'})
            local flags=tonumber(trim(self:read('/sys/class/net/'..name..'/flags',128)))
            assert(status==0 and flags and flags%2==0,'IoT VAP hold failed')
        end end)
        if not ok then failures=failures+1 end
    end
    assert(failures==0,'one or more IoT VAP holds failed');return true
end
function M:baseline()
    -- One fresh read-only batch. Every child retains its own command bound;
    -- full authority guards surround the complete observation before any use.
    self:guard()
    local function command(args)
        assert(self.io.time()-self.started<90,'worker deadline')
        local body,code=self.io.command(args)
        if self.command_failure==nil and type(code)=='number' and code==math.floor(code) and code>=1 and code<=255 then
            self.command_failure={schema=1,command_id=failure_command_id(self.io,args),exit_status=code}
        end
        assert(code==0,'fixed kernel command failed')
        assert(self.io.time()-self.started<90,'worker deadline');return body
    end
    local s={bridge=self:bridge('br-lan'),addresses=command({IP,'addr','show','dev','br-lan'}),
        routes=command({IP,'route','show','default'}),members={},roles={},vlans={},pvids={}}
    assert(s.bridge,'main bridge absent')
    for _,name in ipairs(self.io.dir('/sys/class/net/br-lan/brif')) do
        if name~='ath08' and name~='ath18' then
            s.members[name]=assert(self:index(name));s.roles[name]=self.io.role(name)
        end
    end
    for _,vid in ipairs({2,3,4,591}) do
        s.vlans[tostring(vid)]=trim(command({SW,'dev','switch1','vlan',tostring(vid),'get','ports'})):gsub('%s+',' ')
    end
    for _,port in ipairs({0,1,2,6}) do
        s.pvids[tostring(port)]=trim(command({SW,'dev','switch1','port',tostring(port),'get','pvid'}))
    end
    self:guard();return s
end
local function address_projection(value)
    -- A recognized full native reload may recreate the main bridge index;
    -- all actual addresses, flags and link properties still must match.
    return value:gsub('^%d+: br%-lan:','br-lan:',1)
end
function M:accept_completed_native_rebase(actual)
    local event=self.context.completed_event
    if self.context.allow_main_ifindex_rebase~=true or type(event)~='table' or event.schema~=1
        or event.device_id~=self.context.device_id or event.boot_id~=self.context.boot_id
        or not hex(event.completion_nonce,32) or event.pending~=true
        or (event.event~='wifi' and event.event~='network') then return false end
    if self.state.main_rebased_from_event
        and self.state.main_rebased_from_event.completion_nonce==event.completion_nonce then return false end
    local fresh=self.io.decode(assert(self:read(BASE..'/pending.json',4096),'native completion missing'))
    if not equal(fresh,event) then return false end
    local old=self.state.main_baseline
    if old.bridge~=actual.bridge or old.routes~=actual.routes
        or address_projection(old.addresses)~=address_projection(actual.addresses)
        or not equal(old.roles,actual.roles) or not equal(old.vlans,actual.vlans)
        or not equal(old.pvids,actual.pvids) then return false end
    for name,index in pairs(old.members) do
        if not actual.members[name] then return false end
        if event.event=='wifi' and old.roles[name].kind~='wireless' and actual.members[name]~=index then return false end
    end
    for name in pairs(actual.members) do if not old.members[name] then return false end end
    self:guard();self.io.pause();self:guard()
    if not equal(actual,self:baseline()) then return false end
    -- Rebind only after a known completed native operation, never to explain
    -- a mutation made by this adapter or an unrecognized external change.
    self.state.main_baseline=actual;self.state.main_rebased_from_event=copy(event);self:save()
    return true
end
-- This branch admits only a positively qualified cold, pre-active guest or Wi-Fi result.
-- Existing wireless/network rebase semantics and fixed-index roles are unchanged.
function M:accept_completed_cold_guest_rebase(actual)
    local event=self.context.completed_event;local old=self.state.main_baseline
    if self.context.allow_main_cold_guest_rebase~=true or type(event)~='table' or event.schema~=1
        or event.device_id~=self.context.device_id or event.boot_id~=self.context.boot_id
        or (event.event~='guest' and event.event~='wifi') or event.pending~=true or not hex(event.completion_nonce,32)
        or self.state.main_rebased_from_cold_guest_event~=nil or self.context.activation_lease~=nil
        or self.state.network_section~=nil or self.state.network_section_intent~=nil
        or self.state.vap_creation~=nil or self.state.vap_refresh_intent~=nil
        or type(self.state.rules)~='table' or next(self.state.rules)~=nil
        or type(old)~='table' or type(self.io.cold_guest_evidence)~='function' then return false end
    local function tagged(value)
        if type(value)~='string' then return false end
        local seen={};for token in value:gmatch('%S+') do
            if not ({['0t']=true,['1t']=true,['2t']=true,['6t']=true})[token] or seen[token] then return false end
            seen[token]=true
        end
        return value==trim(value) and not value:find('%s%s')
    end
    local added
    local function uevent(value,wanted)
        if type(value)~='string' then return false end
        local count=0;for line in value:gmatch('[^\n]+') do
            local kind=line:match('^DEVTYPE=(.+)$');if kind then count=count+1;if kind~=wanted then return false end end
        end;return count==1
    end
    local function origin(row,index,name)
        local spec=({['ath02.1']={'ath02','wifi0','phy0'},['ath12.1']={'ath12','wifi2','phy2'},
            ['ath22.1']={'ath22','wifi1','phy1'}})[name]
        if type(row)~='table' or not spec or row.parent~=spec[1] or row.device~=spec[2] or row.phy~=spec[3]
            or tonumber(row.index)~=index or not integer(tonumber(row.parent_index))
            or tonumber(row.parent_index)<1 or row.iflink~=row.parent_index or row.lower_index~=row.parent_index
            or row.type~='1' or row.parent_type~='1' or row.address~=row.parent_address
            or type(row.address)~='string' or not row.address:match('^%x%x:%x%x:%x%x:%x%x:%x%x:%x%x$')
            or row.parent_phy~=row.phy or not uevent(row.uevent,'vlan') or not uevent(row.parent_uevent,'wlan')
            or not equal(row.config,{type='backhaul',mode='ap',device=row.device,network='backhaul',wds='1',disabled='0',vapname=row.parent})
            or type(row.vlan)~='string' then return false end
        local vids,devices=0,0
        for vid in row.vlan:gmatch('VID:%s*(%d+)') do vids=vids+1;if vid~='1' then return false end end
        for device in row.vlan:gmatch('Device:%s*(%S+)') do devices=devices+1;if device~=row.parent then return false end end
        return vids==1 and devices==1
    end
    local function section(row,kind,name,fields)
        if type(row)~='table' or row['.type']~=kind or row['.name']~=name then return false end
        for key,value in pairs(fields) do if row[key]~=value then return false end end
        for key in pairs(row) do if key:sub(1,1)~='.' and fields[key]==nil then return false end end;return true
    end
    local function evidence(waiting)
        self:guard();local proof=self.io.cold_guest_evidence();self:guard()
        if type(proof)~='table' or not equal(proof.pending,event) or proof.parent_finished~=true
            or (event.event=='wifi' and not (proof.completion_parent_finished==true
                and proof.completion_parent_status=='finished' or waiting==true
                and proof.completion_parent_status=='live' and proof.completion_parent_finished==false))
            or proof.ready_absent~=true
            or type(proof.events)~='table' or proof.events.schema~=1 or proof.events.device_id~=self.context.device_id
            or proof.events.boot_id~=self.context.boot_id or type(proof.events.entries)~='table' or next(proof.events.entries)~=nil
            or type(proof.firewall)~='table' or proof.firewall.schema~=1 or proof.firewall.event~='firewall'
            or proof.firewall.finished~=true or proof.firewall.device_id~=self.context.device_id
            or proof.firewall.boot_id~=self.context.boot_id or type(proof.boot_parent)~='table'
            or proof.boot_parent.schema~=1 or proof.boot_parent.device_id~=self.context.device_id
            or proof.boot_parent.boot_id~=self.context.boot_id
            or (proof.boot_parent.loaded_before~='unset' and proof.boot_parent.loaded_before~='0') then return nil end
        if proof.firewall.source_event=='cold_boot' then
            if event.event~='guest' then return nil end
            if proof.firewall.source_pid~=proof.boot_parent.pid or proof.firewall.source_start~=proof.boot_parent.start then return nil end
        elseif proof.firewall.source_event==event.event then
            if proof.firewall.completion_nonce~=event.completion_nonce or proof.firewall.parent_pid~=event.parent_pid
                or proof.firewall.parent_start~=event.parent_start or not integer(event.parent_pid) or event.parent_pid<=1
                or event.parent_pid>4194304 or not integer(event.parent_start) or event.parent_start<=0 then return nil end
        else return nil end
        for _,name in ipairs(VAPS) do if proof.vaps_absent[name]~=true then return nil end end
        if not waiting then
            for name,index in pairs(added) do if not origin(proof.children[name],index,name) then return nil end end
        end
        local s=self.state;local bridge=self:index('br-iot');local vlan=self:index('eth1.30')
        if s.bridge_index then
            if bridge~=s.bridge_index or self:bridge('br-iot')~=s.private_bridge_id then return nil end
            self:verify_owned_bridge_mac()
            for _,name in ipairs(self.io.dir('/sys/class/net/br-iot/brif')) do if name~='eth1.30' then return nil end end
            local addresses=self:command({IP,'addr','show','dev','br-iot'})
            if addresses:find('inet ',1,true) or addresses:find('inet6 ',1,true) then return nil end
        elseif proof.private_absent.bridge~=true or bridge~=nil then return nil end
        if s.vlan_index then
            local shape=self:read('/proc/net/vlan/eth1.30',4096) or ''
            if vlan~=s.vlan_index or tonumber(shape:match('VID:%s*(%d+)'))~=30
                or shape:match('Device:%s*(%S+)')~='eth1' or not s.bridge_index
                or self:master('eth1.30')~=s.private_bridge_id then return nil end
        elseif proof.private_absent.vlan~=true or vlan~=nil then return nil end
        local ports=self:ports(30)
        if ports~='' and not (ports=='2t 6t' and s.switch_owned==true and s.tagged_ports=='2t 6t') then return nil end
        local expected={device='switch1',vlan='30',vid='30',ports='2t 6t'}
        if proof.load_section~=false then
            if not s.load_section or not section(proof.load_section,'switch_vlan','deco_iot',expected) then return nil end
        elseif s.load_section~=nil and s.load_section_intent~=true then return nil end
        if s.load_section then
            if s.load_section.name~='deco_iot' or s.load_section.type~='switch_vlan' then return nil end
            for key,value in pairs(expected) do if s.load_section[key]~=value then return nil end end
        end
        if proof.network_section~=false then return nil end
        for _,binary in ipairs({'/usr/sbin/iptables','/usr/sbin/ip6tables'}) do for _,rule in ipairs(RULES) do
            self:guard();local _,code=self.io.command(argv(binary,'-C',rule));self:guard();if code~=1 then return nil end
        end end
        return proof
    end
    -- Only a positively live Wi-Fi completion actor may be awaited. Every
    -- observation rechecks the cold pair and guards under the existing budget.
    if event.event=='wifi' then
        local waited,fresh=pcall(function()
            while true do
                local safe,proof=pcall(evidence,true)
                if not safe or not proof then return nil end
                if proof.completion_parent_finished==true then return self:baseline() end
                self:guard();self.io.pause();self:guard()
            end
        end)
        if not waited or not fresh then return false end
        actual=fresh
    end
    if old.bridge~=actual.bridge or old.routes~=actual.routes or old.addresses~=actual.addresses
        or not equal(old.pvids,actual.pvids) or not tagged(old.vlans['591']) or not tagged(actual.vlans['591']) then return false end
    for _,vid in ipairs({'2','3','4'}) do if old.vlans[vid]~=actual.vlans[vid] then return false end end
    local projection=copy(actual);projection.members=copy(old.members);projection.roles=copy(old.roles)
    projection.vlans['591']=old.vlans['591'];if not equal(projection,old) then return false end
    for name,index in pairs(old.members) do
        if actual.members[name]~=index or not equal(old.roles[name],actual.roles[name]) then return false end
    end
    for name in pairs(old.roles) do if old.members[name]==nil then return false end end
    added={};local recognized={['ath02.1']=true,['ath12.1']=true,['ath22.1']=true}
    for name,index in pairs(actual.members) do
        if old.members[name]==nil then
            if not recognized[name] or not integer(index) or index<1
                or not equal(actual.roles[name],{kind='fixed_index',index=index}) then return false end
            added[name]=index
        end
    end
    for name in pairs(actual.roles) do if actual.members[name]==nil then return false end end
    -- Kernel traffic counters are not device identity. Mask only the five
    -- fixed decimal counters, retaining all header, mapping and unknown bytes.
    local function stable(proof)
        local result=copy(proof)
        local labels={'         total frames received','          total bytes received',
            '      Broadcast/Multicast Rcvd','      total frames transmitted','       total bytes transmitted'}
        for name in pairs(added) do
            local counts={};local valid=true
            local value=result.children[name].vlan:gsub('([^\n]*)\n',function(line)
                for i,label in ipairs(labels) do
                    if line:sub(1,#label)==label then
                        counts[i]=(counts[i] or 0)+1
                        if counts[i]~=1 or not line:match('^'..label..' +%d+$') then valid=false end
                        return label..' <counter>\n'
                    end
                end
                return line..'\n'
            end)
            for i in ipairs(labels) do if counts[i]~=1 then valid=false end end
            if not valid then return nil end
            result.children[name].vlan=value
        end
        return result
    end
    local good,first=pcall(evidence);if not good or not first then return false end
    self:guard();self.io.pause();self:guard()
    if not equal(actual,self:baseline()) then return false end
    local valid,second=pcall(evidence)
    if not valid or not second then return false end
    local a,b=stable(first),stable(second);if not a or not b or not equal(a,b) then return false end
    self.state.main_baseline=copy(actual);self.state.main_rebased_from_cold_guest_event=copy(event);self:save()
    return true
end
function M:verify_main_and_switch_baseline()
    self:guard()
    assert(self.context.mode=='AP' and self.context.wired_port==2 and self.context.wired_p2_live==true
        and self.context.install_committed==true and self.context.all_three_generation_committed==true
        and self.context.firmware_verified==true,'unsupported installation context')
    assert(trim(self:command({SW,'dev','switch1','get','enable_vlan'}))=='1','switch mode changed')
    assert(self:pvid(2)=='4' and self:pvid(6)=='1','fixed PVID changed')
    local link=tonumber(trim(self:read('/proc/rtk_gsw/phylink',128)))
    assert(link and math.floor(link/4)%2==1,'wired P2 not live')
    -- Early cold boot may have no gateway neighbor yet. One fixed LAN probe
    -- requests ARP/FDB learning; its ICMP reply is not the path attestation.
    self:guard()
    local _,probe_status=self.io.command({BB,'ping','-c','1','-W','1','@GATEWAY_IPV4@'})
    assert(probe_status==0 or probe_status==1,'fixed gateway probe unavailable')
    self:guard()
    -- A live port alone is not evidence that it carries the gateway.
    local gateway_mac
    for line in (self:read('/proc/net/arp',8192) or ''):gmatch('[^\n]+') do
        local address,mac=line:match('^(%S+)%s+%S+%s+%S+%s+(%S+)')
        if address=='@GATEWAY_IPV4@' then gateway_mac=mac end
    end
    assert(gateway_mac and gateway_mac:match('^%x%x:%x%x:%x%x:%x%x:%x%x:%x%x$'),'gateway neighbor unavailable')
    local uplink_port=tonumber(trim(self:read('/sys/class/net/eth1.4/brport/port_no',128)))
    assert(uplink_port and uplink_port>=1 and uplink_port<=32,'uplink bridge port unavailable')
    local shape=self:read('/proc/net/vlan/eth1.4',4096) or ''
    assert(tonumber(shape:match('VID:%s*(%d+)'))==4 and shape:match('Device:%s*(%S+)')=='eth1','uplink VLAN identity changed')
    local learned=false
    for line in self:command({BR,'showmacs','br-lan'}):gmatch('[^\n]+') do
        local port,mac,local_flag=line:match('^%s*(%d+)%s+(%S+)%s+(%S+)')
        if mac==gateway_mac and tonumber(port)==uplink_port and local_flag=='no' then learned=true end
    end
    assert(learned and self:master('eth1.4')==self:bridge('br-lan'),'wired gateway path changed')
    local actual=self:baseline()
    if self.state.main_baseline then
        assert(equal(actual,self.state.main_baseline) or self:accept_completed_native_rebase(actual)
            or self:accept_completed_cold_guest_rebase(actual),'main baseline changed')
    else
        if self.first_cold then
            self:revalidate_first_cold(self.first_cold)
            assert(equal(actual,self.first_cold.observation.baseline),'first cold baseline changed before save')
        end
        self.state.main_baseline=actual;self:save()
    end
    return true
end
-- Pin a bridge MAC explicitly: Linux otherwise recalculates its bridge ID
-- when ports join/leave. The trusted Ethernet parent is never modified.
local function bridge_mac(value)
    return type(value)=='string' and value:match('^%x%x:%x%x:%x%x:%x%x:%x%x:%x%x$')
        and value==value:lower() and value~='00:00:00:00:00:00'
        and tonumber(value:sub(1,2),16)%2==0
end
function M:trusted_bridge_mac()
    local mac=trim(self:read('/sys/class/net/eth1/address',128))
    local index=self:index('eth1')
    assert(bridge_mac(mac) and integer(index) and index>=1,'trusted Ethernet MAC unavailable')
    return mac,index
end
function M:verify_owned_bridge_mac()
    local s=self.state;local mac,parent=self:trusted_bridge_mac()
    assert(s.bridge_mac==mac and s.bridge_parent_index==parent and not s.bridge_mac_pending,
        'private bridge MAC ownership missing or changed')
    assert(self:index('br-iot')==s.bridge_index
        and trim(self:read('/sys/class/net/br-iot/address',128))==mac
        and trim(self:read('/sys/class/net/br-iot/addr_assign_type',128))=='3'
        and s.private_bridge_id=='8000.'..mac:gsub(':','')
        and self:bridge('br-iot')==s.private_bridge_id,'explicit private bridge MAC changed')
    return true
end
function M:ensure_owned_private_bridge()
    local s=self.state
    if self:index('br-iot') then
        assert(s.bridge_index==self:index('br-iot') and s.private_bridge_id==self:bridge('br-iot'),'foreign private bridge')
        self:verify_owned_bridge_mac()
    else
        assert(not s.bridge_index,'owned bridge disappeared')
        local mac,parent=self:trusted_bridge_mac()
        s.bridge_mac=mac;s.bridge_parent_index=parent;s.bridge_mac_pending=true
        s.bridge_intent=true;self:save();self:run({BR,'addbr','br-iot'})
        s.bridge_index=assert(self:index('br-iot'));s.private_bridge_id=assert(self:bridge('br-iot'));self:save()
        self:run({BB,'ifconfig','br-iot','hw','ether',mac})
        assert(trim(self:read('/sys/class/net/br-iot/address',128))==mac
            and trim(self:read('/sys/class/net/br-iot/addr_assign_type',128))=='3'
            and self:bridge('br-iot')=='8000.'..mac:gsub(':',''),'explicit private bridge MAC pin failed')
        s.private_bridge_id=self:bridge('br-iot');s.bridge_mac_pending=nil;self:save()
        self:verify_owned_bridge_mac()
    end
    self:guard();self.io.write('/proc/sys/net/ipv6/conf/br-iot/disable_ipv6','1\n')
    self.io.write('/proc/sys/net/ipv4/conf/br-iot/arp_ignore','1\n')
    self:run({BR,'setfd','br-iot','0'});return true
end
function M:ensure_owned_vlan30_device()
    local s=self.state
    if self:index('eth1.30') then assert(s.vlan_index==self:index('eth1.30'),'foreign VLAN device')
    else
        assert(not s.vlan_index,'owned VLAN device disappeared')
        s.vlan_intent=true;self:save();self:run({BB,'vconfig','add','eth1','30'})
        s.vlan_index=assert(self:index('eth1.30'));self:save()
    end
    local shape=self:read('/proc/net/vlan/eth1.30',4096) or ''
    assert(tonumber(shape:match('VID:%s*(%d+)'))==30 and shape:match('Device:%s*(%S+)')=='eth1','VLAN shape changed')
    local master=self:master('eth1.30')
    assert(not master or master==s.private_bridge_id,'foreign VLAN master')
    self:guard();self.io.write('/proc/sys/net/ipv6/conf/eth1.30/disable_ipv6','1\n')
    if not master then self:run({BR,'addif','br-iot','eth1.30'}) end
    self:verify_owned_bridge_mac()
    self:run({BB,'ifconfig','eth1.30','mtu','1500','up'})
    self:run({BB,'ifconfig','br-iot','mtu','1500','up'});return true
end
function M:ensure_owned_tagged_p2_cpu6()
    local s=self.state;local current=self:ports(30)
    assert(current=='' or (s.switch_owned==true and current=='2t 6t'),'foreign VLAN30 membership')
    if current=='' then s.switch_intent=true;self:save();self:run({SW,'dev','switch1','vlan','30','set','ports','2t 6t'}) end
    s.switch_owned=true;s.tagged_ports='2t 6t';self:save()
    -- The native full-table loader must preserve this separately owned entry.
    assert(self.hooks.register_switch_load(self)==true,'owned switch load registration failed')
    self:save();return true
end
function M:rule_present(binary,rule)
    self:guard();local _,code=self.io.command(argv(binary,'-C',rule))
    assert(code==0 or code==1,'firewall check failed');return code==0
end
function M:ensure_owned_firewall_rules()
    for _,binary in ipairs({'/usr/sbin/iptables','/usr/sbin/ip6tables'}) do for i,rule in ipairs(RULES) do
        local key=binary..':'..i;local present=self:rule_present(binary,rule)
        if present then assert(self.state.rules[key]==true,'foreign matching firewall rule')
        else
            self.state.rules[key]=true;self:save();self:run(argv(binary,'-I',rule))
        end
    end end;return true
end
function M:verify_private_path()
    self:verify_owned_bridge_mac()
    local s=self.state
    assert(self:index('br-iot')==s.bridge_index and self:bridge('br-iot')==s.private_bridge_id
        and self:index('eth1.30')==s.vlan_index and self:master('eth1.30')==s.private_bridge_id
        and self:ports(30)=='2t 6t','private path changed')
    for _,name in ipairs({'br-iot','eth1.30'}) do
        local flags=tonumber(trim(self:read('/sys/class/net/'..name..'/flags',128)))
        assert(flags and flags%2==1,'private link is down')
    end
    for _,name in ipairs(self.io.dir('/sys/class/net/br-iot/brif')) do
        assert(name=='eth1.30' or name=='ath08' or name=='ath18','foreign private member')
    end
    local addresses=self:command({IP,'addr','show','dev','br-iot'})
    assert(not addresses:find('inet ',1,true) and not addresses:find('inet6 ',1,true),'private bridge has local address')
    for _,binary in ipairs({'/usr/sbin/iptables','/usr/sbin/ip6tables'}) do for _,rule in ipairs(RULES) do
        assert(self:rule_present(binary,rule),'own firewall rule missing')
    end end
    assert(self.hooks.verify_registered_network(self)==true,'private network registration changed')
    return true
end
function M:publish_ready()
    self:verify_private_path();self:verify_main_unchanged()
    local s=self.state
    local r={schema=1,verified=true,install_nonce=s.install_nonce,device_id=s.device_id,boot_id=s.boot_id,
        generation=s.generation,epoch=s.epoch,native_iot_disabled=true,writer_guard=true,
        private_path=true,firewall_rules=true,network_registered=true,all_three_generation_committed=true,
        bridge_index=s.bridge_index,vlan_index=s.vlan_index,private_bridge_id=s.private_bridge_id,tagged_ports='2t 6t'}
    self:guard();assert(self.io.atomic(BASE..'/ready.json',self.io.encode(r)));return true
end
function M:verify_iot_vaps_private()
    self:verify_private_path()
    self.state.vaps={}
    for _,name in ipairs(VAPS) do
        local index=self:index(name);local enabled=self.hooks.band_enabled(self,name)
        assert(type(enabled)=='boolean','explicit native band state required')
        if enabled then
            assert(index and self:master(name)==self.state.private_bridge_id,'IoT VAP is not private')
            local flags=tonumber(trim(self:read('/sys/class/net/'..name..'/flags',128)))
            assert(flags and flags%2==1,'IoT VAP not active');self.state.vaps[name]={ifindex=index}
        elseif index then
            local flags=tonumber(trim(self:read('/sys/class/net/'..name..'/flags',128)))
            assert(flags and flags%2==0,'disabled IoT band active')
        end
    end
    self:save();return true
end
function M:verify_main_unchanged()
    assert(self.state.main_baseline and equal(self:baseline(),self.state.main_baseline),'main network changed');return true
end
for _,method in ipairs(HOOKS) do
    local name=method
    M[name]=function(self) self:guard();assert(self.hooks[name](self)==true,'reviewed hook failed: '..name);self:guard();return true end
end
M.BASE=BASE
return M
