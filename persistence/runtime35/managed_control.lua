-- Own fixed policy protocol. Module loading performs no I/O or worker load.
local CHUNK_COUNT,CHUNK_MODE,CHUNK_NONCE=select('#',...),...
local M={}
local ORDER={"@MAIN_DEVICE_ID@",
 "@BEDROOM_DEVICE_ID@","@CELLAR_DEVICE_ID@"}
local ROLES={[ORDER[1]]="AP",[ORDER[2]]="RE",[ORDER[3]]="RE"}
local function hex(s,n) return type(s)=="string" and #s==n and not s:find("[^0-9a-f]") end
local function whole(n,minimum) return type(n)=="number" and n==math.floor(n) and n>=(minimum or 0) and n<=2147483647 end
local function boot(s)
 return type(s)=="string" and #s==36 and s:match("^%x%x%x%x%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%-%x%x%x%x%x%x%x%x%x%x%x%x$")~=nil
end
local RECEIPT={schema=true,kind=true,action=true,phase=true,device_id=true,boot_id=true,install_nonce=true,
 transaction=true,request_nonce=true,generation=true,enabled=true,vlan_id=true,main_untagged=true,scope=true,
 native_iot_saved_disabled=true,durable_policy_saved=true,installation_verified=true,held=true,ready=true,role=true}
local function committed(r)
 if type(r)~="table" then return false end
 for key in pairs(r) do if not RECEIPT[key] then return false end end
 return r.schema==1 and r.kind=="deco_iot_policy_receipt" and r.action=="commit" and r.phase=="committed"
  and ROLES[r.device_id]~=nil and r.role==ROLES[r.device_id] and boot(r.boot_id)
  and hex(r.install_nonce,32) and hex(r.transaction,32) and hex(r.request_nonce,32)
  and whole(r.generation,1) and type(r.enabled)=="boolean" and r.vlan_id==30 and r.main_untagged==true
  and r.scope=="all_three_wired" and r.native_iot_saved_disabled==true and r.durable_policy_saved==true
  and r.installation_verified==true and r.held==true and r.ready==false
end
function M.verify_attestation(manifest,policy)
 if type(manifest)~="table" or type(policy)~="table" or manifest.committed~=true
  or manifest.all_three_generation_committed~=true or manifest.native_iot_saved_disabled~=true
  or not hex(manifest.install_nonce,32) or not ROLES[manifest.device_id]
  or policy.valid~=true or policy.schema~=1 or type(policy.enabled)~="boolean"
  or policy.vlan_id~=30 or policy.main_untagged~=true or policy.scope~="all_three_wired"
  or not whole(policy.generation,1) or manifest.generation~=policy.generation then return false end
 local list=manifest.fleet_attestation
 if type(list)~="table" or #list~=3 then return false end
 local seen,nonce,own={},{},false
 local transaction
 for key in pairs(list) do if type(key)~="number" or key~=math.floor(key) or key<1 or key>3 then return false end end
 for _,r in ipairs(list) do
  if not committed(r) or seen[r.device_id] or nonce[r.request_nonce]
   or r.generation~=policy.generation or r.enabled~=policy.enabled then return false end
  if transaction and r.transaction~=transaction then return false end
  transaction=r.transaction;seen[r.device_id]=true;nonce[r.request_nonce]=true
  if r.device_id==manifest.device_id then
   if r.install_nonce~=manifest.install_nonce then return false end
   own=true
  end
 end
 for _,id in ipairs(ORDER) do if not seen[id] then return false end end
 return own
end
local BASE,PERSIST='/tmp/deco-iot-managed','/tp_data/user_data/deco-iot-vlan'
local function copy(value)
 if type(value)~='table' then return value end
 local result={};for k,v in pairs(value) do result[k]=copy(v) end;return result
end
local function equal(a,b,ignore_ram)
 if type(a)~=type(b) then return false end
 if type(a)~='table' then return a==b end
 for k,v in pairs(a) do if not(ignore_ram and (k=='boot_id' or k=='ram_guards_installed')) and not equal(v,b[k],false) then return false end end
 for k in pairs(b) do if not(ignore_ram and (k=='boot_id' or k=='ram_guards_installed')) and a[k]==nil then return false end end
 return true
end
function M.same_installation_metadata(ram,durable)
 return type(ram)=='table' and type(durable)=='table' and ram.ram_guards_installed==true
  and durable.ram_guards_installed==nil and equal(ram,durable,true)
end
function M.same_immutable_installation(previous,next_manifest)
 if type(previous)~='table' or type(next_manifest)~='table' then return false end
 for _,key in ipairs({'schema','device_id','install_nonce','files','targets','hook_sha1','committed',
  'native_iot_saved_disabled','ui_role','ui_boot','ui_files'}) do
  if not equal(previous[key],next_manifest[key]) then return false end
 end
 return true
end
function M.policy_hold_adapter(quiesce,callback)
 local adapter=quiesce.native_adapter();adapter.preserve_complete=true
 adapter.on_locked=function() return callback()==true end
 return adapter
end
local function trim(s) return s and s:match('^%s*(.-)%s*$') end
local LEASE_FIELDS={schema=true,nonce=true,device_id=true,boot_id=true,install_nonce=true,
 transaction=true,generation=true,enabled=true,deadline=true,pid=true,start=true,state=true}
function M.valid_activation(lease)
 if type(lease)~='table'then return false end
 for key in pairs(lease)do if not LEASE_FIELDS[key]then return false end end
 return lease.schema==1 and lease.state=='running'and hex(lease.nonce,32)and ROLES[lease.device_id]~=nil
  and boot(lease.boot_id)and hex(lease.install_nonce,32)and hex(lease.transaction,32)
  and whole(lease.generation,1)and type(lease.enabled)=='boolean'and whole(lease.pid,2)
  and type(lease.start)=='string'and lease.start:match('^[1-9][0-9]*$')~=nil
  and type(lease.deadline)=='number'and lease.deadline>0 and lease.deadline<math.huge
end
function M.valid_activation_result(value,lease)
 return type(value)=='table'and value.schema==1 and value.kind=='deco_iot_activation_result'
  and M.valid_activation(lease)and equal(value.lease,lease)and type(value.completed)=='boolean'
  and(value.completed~=true or(type(value.response)=='table'and value.response.schema==1
   and value.response.kind=='deco_iot_managed_runtime'and value.response.completed==true
   and value.response.activation_nonce==lease.nonce and value.response.activation_transaction==lease.transaction
   and value.response.device_id==lease.device_id and value.response.boot_id==lease.boot_id
   and value.response.generation==lease.generation and value.response.active==lease.enabled
   and value.response.ready==lease.enabled and value.response.fail_closed==not lease.enabled
   and type(value.observed)=='table'and value.observed.active==lease.enabled
   and value.observed.ready==lease.enabled and value.observed.held==not lease.enabled))
end
function M.sanitize_activation_error(reason)
 local text=type(reason)=='string'and reason or''
 if text:find('activation cancelled or expired',1,true)then return'activation_cancelled_or_expired'end
 if text:find('activation runtime source changed',1,true)or text:find('activation runtime source unverified',1,true)then return'activation_source_check_failed'end
 if text:find('activation policy or journal changed',1,true)then return'activation_binding_changed'end
 if text:find('activation worker/fresh observation incomplete',1,true)then return'activation_runtime_not_verified'end
 return'unclassified_error'
end
function M.spawn_activation(nx,process,context,request,parent_lock,nonce,now,publish)
  assert(hex(nonce,32)and ROLES[context.device_id],'fixed activation spawn identity');local gate_read,gate_write=nx.pipe();assert(gate_read and gate_write)
  local ready_read,ready_write=nx.pipe();assert(ready_read and ready_write)
  local pid=nx.fork();if not pid then pcall(gate_read.close,gate_read);pcall(gate_write.close,gate_write);pcall(ready_read.close,ready_read);pcall(ready_write.close,ready_write);error('activation fork failed')end;local lease
  if pid==0 then
   pcall(function()
    assert(gate_write:close());assert(ready_read:close());assert(parent_lock:close())
    assert(nx.setsid()==nx.getpid());assert(nx.setenv('DECO_IOT_OWN_COMMAND_SESSION'))
    assert(nx.getenv('DECO_IOT_OWN_COMMAND_SESSION')==nil)
    local null=assert(nx.open('/dev/null','w+'))
    assert(nx.dup(null,nx.stdin));assert(nx.dup(null,nx.stdout));assert(nx.dup(null,nx.stderr))
    local fd=assert(tonumber(tostring(null):match('^nixio file (%d+)$')));if fd>2 then assert(null:close())end
    assert(ready_write:write('R')==1);assert(ready_write:close())
    assert(gate_read:read(1)=='G');assert(gate_read:close())
    nx.execp('/usr/bin/lua',BASE..'/managed_control.lua','activate-job',nonce)
   end);os.exit(127)
  end
  local ok,why=pcall(function()
   local original=assert(process(pid));assert(original.state~='Z','activation child disappeared')
   assert(gate_read:close());assert(ready_write:close())
   assert(nx.poll({{fd=ready_read,events=nx.poll_flags('in')}},1000)==1,'activation detach timeout')
   assert(ready_read:read(1)=='R');assert(ready_read:close())
   local actor=assert(process(pid));assert(actor.start==original.start and actor.state~='Z'and actor.group==pid and actor.session==pid,'activation child not detached')
   lease={schema=1,nonce=nonce,device_id=context.device_id,boot_id=context.boot_id,
    install_nonce=context.manifest.install_nonce,transaction=request.transaction,generation=request.generation,
    enabled=request.enabled,deadline=now()+105,pid=pid,start=actor.start,state='running'}
   assert(M.valid_activation(lease));assert(publish(lease))
  end)
  if not ok then pcall(gate_write.close,gate_write);pcall(ready_read.close,ready_read);error(why)end
  return lease,gate_write
 end

local function native()
 local nx,fs,json=require('nixio'),require('nixio.fs'),require('luci.json')
 local policy_module=assert(loadfile(BASE..'/declarative_policy.lua'))()
 local a={}
 function a.read(path,limit)
  local f=io.open(path,'rb');if not f then return nil end
  local body,why=f:read((limit or 65536)+1);assert(f:close())
  if body==nil and why==nil then body='' end
  assert(type(body)=='string' and #body<=(limit or 65536),'bounded control read failed');return body
 end
 function a.nonce()
  local value=trim(assert(a.read('/proc/sys/kernel/random/uuid',128))):gsub('%-','')
  assert(hex(value,32),'control nonce unavailable');return value
 end
 function a.time()return assert(tonumber((a.read('/proc/uptime',128)or''):match('^[%d.]+')))end
 function a.sleep()assert(nx.nanosleep(0,200000000))end
 function a.process(pid)
  local dir,errno=fs.stat('/proc/'..pid)
  if not dir then return nil,errno==2 end
  local raw=a.read('/proc/'..pid..'/stat',4096)
  if not raw then return nil,false end
  local tail=raw:match('^%d+ %b() (.+)$');if not tail then return nil,false end
  local fields={};for word in tail:gmatch('%S+')do fields[#fields+1]=word end
  if not fields[20]or not fields[20]:match('^[1-9][0-9]*$')then return nil,false end
  return{pid=pid,start=fields[20],state=fields[1],group=tonumber(fields[3]),session=tonumber(fields[4])},true
 end
 local nonce=a.nonce()
 local bounded=assert(loadfile(BASE..'/bounded_command.lua'))().new({base=BASE,nonce=nonce})
 function a.command(argv) return bounded:command(argv) end
 local function private(path)
  assert(not fs.readlink(path),'private directory link refused')
  local s=assert(fs.stat(path));assert(s.type=='dir' and s.uid==0 and s.gid==0 and s.modestr=='rwx------','private control directory required')
 end
 local function atomic(path,body)
  private(path:match('^(.*)/[^/]+$'));assert(not fs.readlink(path),'control target link refused')
  local old=fs.stat(path)
  if old then assert(old.type=='reg' and old.uid==0 and old.gid==0 and old.nlink==1,'foreign control target') end
  local next_path=path..'.next-'..nonce
  local f=assert(nx.open(next_path,nx.open_flags('wronly','creat','excl'),'rw-------'),'exclusive control write failed')
  local done=0
  while done<#body do local n=assert(f:write(body,done));assert(n>0 and n<=#body-done);done=done+n end
  assert(f:sync());assert(f:close());assert(a.read(next_path)==body,'control exact temporary write failed')
  if old then
   local now=assert(fs.stat(path));assert(now.dev==old.dev and now.ino==old.ino,'control target replaced')
  else assert(not fs.stat(path),'control target appeared') end
  assert(os.rename(next_path,path),'control atomic rename failed');assert(a.read(path)==body,'control exact write failed')
  return true
 end
 local function owned_json(path,limit)
  assert(not fs.readlink(path),'activation record symlink refused')
  local st,errno=fs.stat(path)
  if not st then assert(errno==2,'activation record absence unknown');return nil end
  assert(st.type=='reg'and st.uid==0 and st.gid==0 and st.nlink==1
   and st.modestr=='rw-------'and st.size<=limit,'activation record ownership differs')
  local body=assert(a.read(path,limit));local after=assert(fs.stat(path))
  assert(after.dev==st.dev and after.ino==st.ino and after.size==st.size,'activation record changed')
  return json.decode(body)
 end
 function a.lease()return owned_json(BASE..'/activation-lease.json',2048)end
 function a.activation_result(lease)
  assert(M.valid_activation(lease),'fixed activation binding required')
  local result=owned_json(BASE..'/activation-'..lease.nonce..'-result.json',16384)
  if result then assert(M.valid_activation_result(result,lease),'activation result differs')end
  return result
 end
 function a.actor_gone(lease)
  assert(M.valid_activation(lease),'activation actor binding required')
  local actor,known=a.process(lease.pid)
  return known and(not actor or actor.start~=lease.start or actor.state=='Z')
 end
 function a.self_actor(lease)
  local actor,known=a.process(nx.getpid())
  return known and actor and actor.pid==lease.pid and actor.start==lease.start and actor.state~='Z'
   and actor.group==lease.pid and actor.session==lease.pid
 end
 local function remove_owned(path)
  assert(not fs.readlink(path),'activation revoke link refused')
  local st,errno=fs.stat(path)
  if not st then assert(errno==2,'activation revoke absence unknown');return true end
  assert(st.type=='reg'and st.uid==0 and st.gid==0 and st.nlink==1,'activation revoke inode differs')
  assert(os.remove(path),'activation revoke failed');return true
 end
 function a.cancel_activation(state)
  local current=a.lease()
  if current then
   assert(state and equal(current,state.activation),'foreign activation lease preserved')
   assert(remove_owned(BASE..'/activation-lease.json'))
  end
  assert(remove_owned(BASE..'/epoch'));assert(remove_owned(BASE..'/ready.json'));return true
 end
 function a.finish_activation(lease)
  local current=a.lease()
  if current then assert(equal(current,lease),'foreign completion lease preserved');return remove_owned(BASE..'/activation-lease.json')end
  return true
 end
 function a.publish_activation(lease,value)
  assert(M.valid_activation_result(value,lease),'fixed activation result required')
  local path=BASE..'/activation-'..lease.nonce..'-result.json'
  assert(not fs.stat(path)and not fs.readlink(path),'activation result already exists')
  return atomic(path,json.encode(value))
 end
 function a.launch_activation(context,request,parent_lock)
  assert(a.lease()==nil,'activation lease already present')
  return M.spawn_activation(nx,a.process,context,request,parent_lock,a.nonce(),a.time,function(lease)
   return atomic(BASE..'/activation-lease.json',json.encode(lease))
  end)
 end
 function a.release_activation(gate)
  local ok,count=pcall(gate.write,gate,'G');local closed=gate:close()
  assert(ok and count==1 and closed,'activation gate release failed');return true
 end
 function a.cancel_gate(gate)return gate:close()==true end
 local function open_lock(path,seconds)
  assert(not fs.readlink(path),'control lock link refused')
  local f=assert(nx.open(path,'a'),'control lock open failed')
  local info,st=assert(f:stat()),assert(fs.stat(path))
  assert(info.type=='reg' and info.uid==0 and info.gid==0 and info.nlink==1 and info.ino==st.ino and info.dev==st.dev,'control lock identity changed')
  local function now() return assert(tonumber((a.read('/proc/uptime',128) or ''):match('^[%d.]+'))) end
  local until_time=now()+(seconds or 0)
  repeat
   if f:lock('tlock') then return f end
   if now()>=until_time then f:close();error('control lock busy') end
   nx.nanosleep(0,50000000)
  until false
 end
 function a.lock(fleet) private(BASE);return open_lock(BASE..(fleet and '/fleet-control.lock' or '/control.lock'),0) end
 function a.unlock(fd) return fd:close()==true end
 function a.context()
  assert(nx.getuid()==0 and nx.getgid()==0,'root required');private(BASE);private(PERSIST)
  local id=trim(assert(a.read('/tmp/sync-cached-DEV_ID',128)))
  local boot_id=trim(assert(a.read('/proc/sys/kernel/random/boot_id',128)))
  local manifest=json.decode(assert(a.read(BASE..'/installation.json',32768)))
  local durable=json.decode(assert(a.read(PERSIST..'/installation.json',32768)))
  assert(type(manifest)=='table' and type(durable)=='table' and manifest.device_id==id
   and manifest.boot_id==boot_id and manifest.committed==true and M.same_installation_metadata(manifest,durable),'installation metadata mismatch')
  local install=assert(loadfile(BASE..'/runtime_install.lua'))().new(manifest)
  assert(install:identity() and install:verify_targets(),'native installation verification failed')
  local uci=require('luci.model.uci').cursor()
  local role=require('luci.model.sync').get_role()
  local policy=policy_module.read(uci:get_all('deco_iot_vlan','iot'))
  assert(ROLES[id]==role and uci:get('sysmode','sysmode','mode')=='AP','fixed mesh role/mode changed')
  assert(policy.valid and policy.schema==1 and uci:get('iot_wifi','iot','enable')=='0','fixed saved policy/native IoT0 invalid')
  return {device_id=id,boot_id=boot_id,role=role,manifest=manifest,policy=policy,installation_verified=true}
 end
 function a.journal()
  local raw=a.read(BASE..'/control.json',32768)
  if not raw then return nil end
  local value=json.decode(raw);assert(type(value)=='table','malformed policy transaction journal');return value
 end
 function a.save_journal(state) return atomic(BASE..'/control.json',json.encode(state)) end
 function a.set_manifest(manifest)
  local previous=a.context().manifest
  assert(M.same_immutable_installation(previous,manifest),'immutable installation metadata changed')
  local durable=copy(manifest);durable.boot_id=nil;durable.ram_guards_installed=nil
  assert(atomic(PERSIST..'/installation.json',json.encode(durable)))
  assert(atomic(BASE..'/installation.json',json.encode(manifest)))
  return true
 end
 function a.verify_saved(policy)
  local body,status=a.command({'/usr/bin/lua',BASE..'/policy_readback.lua',a.nonce()})
  assert(status==0,'saved policy projection process failed')
  local projection=json.decode(body)
  assert(type(projection)=='table' and projection.schema==1 and projection.native_iot_enable=='0'
   and equal(projection.options,policy_module.options(policy)),'durable policy/native IoT0 readback mismatch')
  for key in pairs(projection) do assert(key=='schema' or key=='options' or key=='native_iot_enable','unexpected saved projection field') end
  return true
 end
 function a.save_policy(policy)
  local uci=require('luci.model.uci').cursor()
  assert(uci:set('iot_wifi','iot','enable','0'),'native IoT0 set failed')
  assert(uci:tset('deco_iot_vlan','iot',policy_module.options(policy)),'fixed policy set failed')
  assert(uci:rawcommit('iot_wifi') and uci:rawcommit('deco_iot_vlan'),'fixed policy commit failed')
  local _,code=a.command({'/sbin/saveconfig','user-config'});assert(code==0,'native save process failed')
  return a.verify_saved(policy)
 end
 function a.hold(callback)
  -- Native write ordering is CONFIG_LOCK -> worker.lock. Never invert it.
  local config=open_lock('/var/run/config.lock',2)
  local ok,why=pcall(function()
   local quiesce=assert(loadfile(BASE..'/native_quiesce.lua'))()
   local adapter=M.policy_hold_adapter(quiesce,callback)
   assert(quiesce.run('network',adapter),'fixed policy quiesce failed')
  end)
  local closed=config:close();assert(ok and closed,'fixed policy hold/update failed');return true
 end
 function a.observe()
  local facts=assert(loadfile(BASE..'/observe_owned_state.lua'))().collect('ready')
  local ready=assert(loadfile(BASE..'/hook_decision.lua'))().evaluate('ready',facts)==true
   and M.verify_attestation(facts.installation,facts.policy)
  local row=require('luci.model.uci').cursor():get_all('iot_wifi','iot')
  local active,held,enabled_count=ready,true,0
  for _,item in ipairs({{'ath08','enable_2g'},{'ath18','enable_5g'}}) do
   assert(type(row)=='table' and (row[item[2]]=='0' or row[item[2]]=='1'),'explicit native band state required')
   local index=a.read('/sys/class/net/'..item[1]..'/ifindex',128)
   local flags=index and tonumber(trim(a.read('/sys/class/net/'..item[1]..'/flags',128))) or nil
   local up=flags and flags%2==1 or false
   if index and not flags then active=false;held=false end
   if up then held=false end
   if facts.policy.enabled and row[item[2]]=='1' then
    enabled_count=enabled_count+1
    active=active and up and trim(a.read('/sys/class/net/'..item[1]..'/master/bridge/bridge_id',128))==facts.resources.private_bridge_id
   elseif up then active=false end
  end
  return {ready=ready,active=active and enabled_count>0,held=held}
 end
 function a.reconcile(lease) return assert(loadfile(BASE..'/worker.lua'))().reconcile(lease) end
 function a.verify_runtime(context)
  local install=assert(loadfile(BASE..'/runtime_install.lua'))().new(context.manifest)
  for _,name in ipairs(install.FILES)do assert(install.io.hash(BASE..'/'..name)==context.manifest.files[name].sha1,'activation runtime source changed')end
  return true
 end
 function a.rpc(id,request)
  assert(ROLES[id] and id~=ORDER[1],'fixed satellite target required')
  local bus=assert(require('ubus').connect(nil,30),'native sync bus unavailable')
  local ok,response=pcall(bus.call,bus,'sync','request',M.peer_request(id,request))
  bus:close();assert(ok,'native fixed peer request failed')
  assert(type(response)=='table' and response.success==1 and type(response.data)=='table'
   and response.data.error_code==0 and type(response.data.result)=='table','native fixed peer response unavailable')
  return response.data.result
 end
 return a
end
local CHANGE_FIELDS={schema=true,action=true,device_id=true,boot_id=true,transaction=true,request_nonce=true,
 generation=true,expected_generation=true,enabled=true,step=true,attestations=true}
local function request_valid(request)
 assert(type(request)=='table' and request.schema==1 and ROLES[request.device_id] and hex(request.request_nonce,32),'fixed policy request invalid')
 for key in pairs(request) do assert(CHANGE_FIELDS[key],'unknown fixed policy field') end
 local action=request.action
 assert(action=='status' or action=='prepare' or action=='commit' or action=='abort' or action=='disable','unsupported fixed policy action')
 if action=='status' then
  for key in pairs(request) do assert(key=='schema' or key=='action' or key=='device_id' or key=='request_nonce','status accepts no policy changes') end
 else
  assert(boot(request.boot_id) and hex(request.transaction,32) and whole(request.generation,1)
   and type(request.enabled)=='boolean','bound policy change required')
  if action=='prepare' then assert(whole(request.expected_generation,1) and request.generation==request.expected_generation+1,'next policy generation required')
  else assert(request.expected_generation==nil,'unexpected previous generation') end
  if action=='commit' then assert(request.step=='record' or request.step=='activate','fixed commit step required')
   if request.step=='record' then assert(request.attestations==nil,'record accepts no activation proof') end
  else assert(request.step==nil and request.attestations==nil,'unexpected commit proof') end
  if action=='disable' then assert(request.enabled==false,'disable cannot enable') end
 end
 return true
end
function M.peer_request(id,request)
 request_valid(request)
 assert(ROLES[id]=='RE' and request.device_id==id,'exact satellite request binding required')
 return {opcode=request.action=='status' and 16393 or 16392,target_id=id,data={params={deco_iot_vlan=copy(request)}}}
end
function M.new(adapter) return setmetatable({io=adapter or native()},{__index=M}) end
local PHASES={preparing=true,prepared=true,committed=true,activating=true,active=true,disabled=true,aborted=true,error=true}
local function journal_valid(state,context)
 if state==nil then return true end
 assert(type(state)=='table' and state.schema==1 and state.device_id==context.device_id and state.boot_id==context.boot_id
  and state.install_nonce==context.manifest.install_nonce and hex(state.transaction,32) and whole(state.generation,1)
  and whole(state.previous_generation,1) and type(state.enabled)=='boolean' and PHASES[state.phase],'foreign policy transaction journal')
 if state.activation~=nil then
  local lease=state.activation
  assert(M.valid_activation(lease)and lease.device_id==context.device_id and lease.boot_id==context.boot_id
   and lease.install_nonce==context.manifest.install_nonce and lease.transaction==state.transaction
   and lease.generation==state.generation and lease.enabled==state.enabled,'foreign activation journal')
 end
 return true
end
local function receipt(context,request,phase,held,ready,saved)
 local enabled=request.enabled;if enabled==nil then enabled=context.policy.enabled end
 return {schema=1,kind='deco_iot_policy_receipt',action=request.action,phase=phase,device_id=context.device_id,
  boot_id=context.boot_id,role=context.role,install_nonce=context.manifest.install_nonce,transaction=request.transaction,
  request_nonce=request.request_nonce,generation=request.generation or context.policy.generation,
  enabled=enabled,vlan_id=30,main_untagged=true,scope='all_three_wired',
  native_iot_saved_disabled=true,durable_policy_saved=saved==true,installation_verified=true,held=held,ready=ready}
end
function M:process(request)
 request_valid(request)
 local a=self.io;local lock=a.lock(false)
 local context,state,mutating,activation_gate
 local ok,value=pcall(function()
  context=a.context();assert(context.installation_verified and context.device_id==request.device_id
   and context.role==ROLES[request.device_id],'policy receiver identity mismatch')
  if request.action=='status' then
   local observed=a.observe();state=a.journal();journal_valid(state,context)
   local job,job_state
   if state and state.activation then
    job=a.activation_result(state.activation)
    if state.phase=='aborted'or state.phase=='error'then job_state='cancelled'
    elseif job and job.completed then
     assert(M.valid_activation_result(job,state.activation),'activation final result differs')
     assert(context.policy.generation==state.generation and context.policy.enabled==state.enabled
      and M.verify_attestation(context.manifest,context.policy),'activation desired state changed')
     observed=a.observe()
     assert(observed.active==state.enabled and observed.ready==state.enabled and observed.held==not state.enabled,
      'activation fresh observation failed')
     if state.phase=='activating'then
      state.phase=state.enabled and'active'or'disabled';assert(a.save_journal(state))
     end
     assert(state.phase==(state.enabled and'active'or'disabled'),'activation phase changed')
     assert(a.finish_activation(state.activation));job_state='done'
    elseif job then job_state='failed'
    else job_state=a.actor_gone(state.activation)and'unknown'or'pending'end
   end
   local phase=state and state.phase or (observed.ready and 'active' or 'held')
   if phase=='active' and not observed.active then phase='degraded' end
   local response=receipt(context,request,phase,observed.held,observed.ready,false)
   response.active=observed.active;response.runtime_state_observed=true
   if state then response.pending_transaction=state.transaction;response.pending_generation=state.generation end
   if state and state.activation then
    response.activation_nonce=state.activation.nonce;response.activation_transaction=state.activation.transaction
    response.activation_state=job_state;response.activation_completed=job_state=='done'
   end
   response.all_three_generation_committed=M.verify_attestation(context.manifest,context.policy)
   return response
  end
  assert(context.boot_id==request.boot_id,'policy receiver boot changed')
  state=a.journal()
  journal_valid(state,context)
  if request.action=='prepare' then
   assert(context.policy.generation==request.expected_generation,'stale policy generation')
   if state and state.transaction~=request.transaction then
    assert(state.phase=='active' or state.phase=='disabled' or state.phase=='aborted','another policy transaction pending')
   end
   if state and state.activation then assert(a.actor_gone(state.activation),'prior activation actor still live or unknown')end
   mutating=true
   assert(a.cancel_activation(state),'prior activation revoke failed')
   state={schema=1,device_id=context.device_id,boot_id=context.boot_id,install_nonce=context.manifest.install_nonce,
    transaction=request.transaction,generation=request.generation,enabled=request.enabled,previous_generation=context.policy.generation,phase='preparing'}
   assert(a.save_journal(state))
   mutating=true
   assert(a.hold(function()
    local manifest=copy(context.manifest);manifest.all_three_generation_committed=false;manifest.fleet_attestation=nil
    assert(a.set_manifest(manifest));assert(a.save_policy(context.policy));state.phase='prepared';return a.save_journal(state)
   end))
   return receipt(context,request,'prepared',true,false,false)
  end
  assert(state and state.transaction==request.transaction and state.generation==request.generation
   and (state.enabled==request.enabled or request.action=='disable'),'policy transaction binding mismatch')
  if request.action=='abort' or request.action=='disable' then
   mutating=true
   assert(a.cancel_activation(state),'activation cancellation failed')
   assert(a.hold(function()
    local manifest=copy(context.manifest);manifest.all_three_generation_committed=false;manifest.fleet_attestation=nil
    assert(a.set_manifest(manifest))
    local policy=copy(context.policy);policy.enabled=false
    assert(a.save_policy(policy));state.phase='aborted';return a.save_journal(state)
   end))
   context=a.context();local actual_request=copy(request);actual_request.generation=context.policy.generation;actual_request.enabled=false
   local response=receipt(context,actual_request,'aborted',true,false,true);response.target_generation=request.generation;return response
  end
  if request.step=='record' then
   assert(state.phase=='prepared' or state.phase=='committed','policy commit phase invalid')
   local policy=copy(context.policy);policy.generation=request.generation;policy.enabled=request.enabled
   mutating=true
   assert(a.hold(function()
    assert(a.save_policy(policy))
    local manifest=copy(context.manifest);manifest.generation=policy.generation;manifest.all_three_generation_committed=false;manifest.fleet_attestation=nil
    assert(a.set_manifest(manifest));state.phase='committed';return a.save_journal(state)
   end))
   context=a.context();return receipt(context,request,'committed',true,false,true)
  end
  assert(state.phase=='committed'or state.phase=='activating'or state.phase=='active'or state.phase=='disabled','policy activation phase invalid')
  assert(context.policy.generation==request.generation and context.policy.enabled==request.enabled,'committed local policy changed')
  local manifest=copy(context.manifest);manifest.all_three_generation_committed=true;manifest.fleet_attestation=request.attestations
  assert(M.verify_attestation(manifest,context.policy),'all-three committed receipt proof invalid')
  if state.activation then
   -- A repeated request only reports this exact original actor; it never
   -- starts a second worker or extends the immutable activation deadline.
   assert(M.valid_activation(state.activation),'activation binding absent')
   local observed=a.observe()
   local response=receipt(context,request,'activating',observed.held,observed.ready,true)
   response.activation_nonce=state.activation.nonce;response.activation_accepted=true
   return response
  end
  mutating=true
  assert(a.hold(function()assert(a.set_manifest(manifest));state.phase='activating';return a.save_journal(state)end))
  local lease,gate=a.launch_activation(context,request,lock);activation_gate=gate;state.activation=lease
  assert(a.save_journal(state))
  local response=receipt(context,request,'activating',true,false,true)
  response.activation_nonce=lease.nonce;response.activation_accepted=true;return response
 end)
 if not ok and mutating then
  -- Best-effort local cancellation never retries an ambiguous flash save.
  pcall(function()assert(a.cancel_activation(state));a.hold(function()
   local now=a.context();assert(now.device_id==request.device_id and now.boot_id==request.boot_id)
   local manifest=copy(now.manifest);manifest.all_three_generation_committed=false;manifest.fleet_attestation=nil
   assert(a.set_manifest(manifest));state.phase='error';state.error='fixed_policy_operation_failed'
   return a.save_journal(state)
  end) end)
 end
 local closed=a.unlock(lock)
 if activation_gate then
  if ok and closed then assert(a.release_activation(activation_gate),'activation gate failed after unlock')
  else pcall(a.cancel_gate,activation_gate)end
 end
 assert(ok and closed,'fixed local policy operation failed');return value
end
function M.handle(request) return M.new():process(request) end
function M.activation_idle(adapter)
 local a=adapter or native();local state=a.journal()
 if a.lease()~=nil then return false end
 return not state or not state.activation or a.actor_gone(state.activation)==true
end
function M.run_activation(nonce,adapter)
 assert(hex(nonce,32),'fixed activation nonce required')
 local a=adapter or native();local lease=assert(a.lease(),'activation lease revoked')
 assert(M.valid_activation(lease)and lease.nonce==nonce,'fixed activation lease required')
 assert(a.self_actor(lease),'activation process changed before any result write')
 local result={schema=1,kind='deco_iot_activation_result',lease=copy(lease),completed=false}
 local function bound()
  assert(equal(a.lease(),lease)and a.time()<lease.deadline,'activation cancelled or expired')
  local context=a.context();local state=a.journal();journal_valid(state,context)
  assert(state and state.phase=='activating'and equal(state.activation,lease)
   and context.device_id==lease.device_id and context.boot_id==lease.boot_id
   and context.manifest.install_nonce==lease.install_nonce and context.policy.generation==lease.generation
   and context.policy.enabled==lease.enabled and M.verify_attestation(context.manifest,context.policy),
   'activation policy or journal changed')
  return context
 end
 local ok,why=pcall(function()
  local context=bound();assert(a.verify_runtime(context),'activation runtime source unverified')
  assert(a.self_actor(lease),'activation process changed')
  bound();result.response=a.reconcile(lease);bound()
  result.observed=a.observe();result.completed=true
  assert(M.valid_activation_result(result,lease),'activation worker/fresh observation incomplete')
 end)
 if not ok then result.completed=false;result.error='fixed_async_activation_failed';result.private_reason=M.sanitize_activation_error(why)end
 -- Results from a cancelled actor cannot update the control journal. A new
 -- prepare is blocked until this exact process has exited, preventing a stale
 -- worker's emergency hold/result from overlapping a new managed generation.
 local context=a.context()
 if context.device_id==lease.device_id and context.boot_id==lease.boot_id
  and context.policy.generation==lease.generation then assert(a.publish_activation(lease,result))end
 return result
end
function M.wrap(native_dispatch,handler)
 assert(type(native_dispatch)=='function','native wireless dispatch required')
 handler=handler or M.handle
 return function(request)
  local params=type(request)=='table' and request.params or nil
  if type(params)~='table' or params.deco_iot_vlan==nil then return native_dispatch(request) end
  local ok,value=pcall(function()
   assert(request.form=='wlan','fixed wireless form required')
   for key in pairs(params) do assert(key=='deco_iot_vlan','mixed native/custom WiFi write refused') end
   local own=params.deco_iot_vlan;request_valid(own)
   assert(request.operation==(own.action=='status' and 'read' or 'write'),'fixed wireless operation mismatch')
   return handler(own)
  end)
  if not ok then return {error_code=1,msg='fixed_iot_vlan_request_refused'} end
  return {error_code=0,result=value}
 end
end
local function response_valid(response,request,known)
 assert(type(response)=='table' and response.schema==1 and response.kind=='deco_iot_policy_receipt'
  and response.action==request.action and response.device_id==request.device_id and response.role==ROLES[request.device_id]
  and response.request_nonce==request.request_nonce and boot(response.boot_id) and hex(response.install_nonce,32)
  and response.installation_verified==true and response.native_iot_saved_disabled==true
  and response.vlan_id==30 and response.main_untagged==true and response.scope=='all_three_wired'
  and whole(response.generation,1) and type(response.enabled)=='boolean'
  and type(response.held)=='boolean' and type(response.ready)=='boolean','fixed peer receipt invalid')
 if known then assert(response.boot_id==known.boot_id and response.install_nonce==known.install_nonce,'peer boot/installation changed') end
 if request.action~='status' then
  assert(response.transaction==request.transaction and response.boot_id==request.boot_id,'peer transaction changed')
  if request.action=='abort' or request.action=='disable' then
   assert(response.phase=='aborted' and response.target_generation==request.generation and response.enabled==false
    and response.held==true and response.ready==false and response.durable_policy_saved==true,'peer abort not verified')
  else
   assert(response.generation==request.generation and response.enabled==request.enabled,'peer desired policy changed')
   if request.action=='prepare' then assert(response.phase=='prepared' and response.held and not response.ready,'peer prepare not held')
   elseif request.step=='record' then assert(committed(response),'peer durable commit not verified')
   else assert(response.phase=='activating'and response.activation_accepted==true
    and hex(response.activation_nonce,32)and response.durable_policy_saved==true,'peer activation launch not verified')end
  end
 else
  assert(type(response.active)=='boolean' and response.runtime_state_observed==true,'fresh peer runtime status unavailable')
 end
 return response
end
function M.coordinate(request,adapter)
 assert(type(request)=='table','fixed fleet request required')
 for key in pairs(request) do assert(key=='action' or key=='enabled' or key=='expected_generation','unknown fleet control field') end
 assert(request.action=='status' or request.action=='configure' or request.action=='disable','unsupported fixed fleet action')
 if request.action=='status' then assert(request.enabled==nil and request.expected_generation==nil,'status cannot configure')
 else
  assert(type(request.enabled)=='boolean' and whole(request.expected_generation,1),'fleet desired policy/generation required')
  if request.action=='disable' then assert(request.enabled==false,'disable cannot enable') end
 end
 local a=adapter or native();local lock=a.lock(true);local known,commits,completed={}, {}, {}
 local deadline=a.time()+240;local operation_deadline=deadline-45
 local transaction,generation
 local function call(id,action,step,proof)
  assert(a.time()<(action=='abort'and deadline or operation_deadline),'fixed fleet deadline')
  local r={schema=1,action=action,device_id=id,request_nonce=a.nonce()}
  if action~='status' then
   r.boot_id=known[id].boot_id;r.transaction=transaction;r.generation=generation;r.enabled=request.enabled
   if action=='prepare' then r.expected_generation=request.expected_generation end
   if action=='commit' then r.step=step;r.attestations=proof end
  end
  local response=id==ORDER[1] and M.new(a):process(r) or a.rpc(id,r)
  return response_valid(response,r,known[id])
 end
 local ok,value=pcall(function()
  local local_context=a.context();assert(local_context.device_id==ORDER[1] and local_context.role=='AP','fleet coordinator must be the main AP')
  for _,id in ipairs(ORDER) do
   known[id]=call(id,'status')
   if request.action~='status' then assert(known[id].generation==request.expected_generation,'fleet generations differ') end
  end
  if request.action=='status' then return {schema=1,kind='deco_iot_fleet_status',completed=true,nodes=known,observed=true} end
  assert(request.expected_generation<2147483647,'fleet generation exhausted')
  generation=request.expected_generation+1;transaction=a.nonce()
  for _,id in ipairs(ORDER) do call(id,'prepare');completed[id]='prepared' end
  for _,id in ipairs(ORDER) do commits[#commits+1]=call(id,'commit','record');completed[id]='committed' end
  local results,launches={},{}
  for _,id in ipairs(ORDER)do launches[id]=call(id,'commit','activate',commits);completed[id]='activating'end
  local waiting=true
  repeat
   waiting=false
   for _,id in ipairs(ORDER)do if not results[id]then
    local observed=call(id,'status')
    assert(observed.generation==generation and observed.enabled==request.enabled
     and observed.all_three_generation_committed==true and observed.activation_transaction==transaction
     and observed.activation_nonce==launches[id].activation_nonce,'fleet activation status binding differs')
    if observed.activation_completed==true then
     assert(observed.activation_state=='done'and observed.active==request.enabled and observed.ready==request.enabled
      and observed.held==not request.enabled,'fleet final runtime verification failed')
     results[id]=observed;completed[id]=observed.phase
    else
     assert(observed.activation_state=='pending','fleet activation failed or outcome unknown')
     waiting=true
    end
   end end
   if waiting then assert(a.time()<operation_deadline,'fixed fleet activation deadline');a.sleep()end
  until not waiting
  return {schema=1,kind='deco_iot_fleet_operation',completed=true,transaction=transaction,generation=generation,
   enabled=request.enabled,vlan_id=30,main_untagged=true,scope='all_three_wired',nodes=results,reboot_verified=false}
 end)
 if not ok and transaction then
  local aborts={}
  for _,id in ipairs(ORDER) do
   local success,result=pcall(call,id,'abort')
   aborts[id]={verified=success,held=success and result.held==true or false,unknown=not success}
  end
  value={schema=1,kind='deco_iot_fleet_operation',completed=false,transaction=transaction,generation=generation,
   enabled=request.enabled,aborts=aborts,error='fixed_fleet_operation_failed',distributed_rollback_proven=false}
 elseif not ok then
  value={schema=1,kind='deco_iot_fleet_operation',completed=false,error='fleet_preconditions_failed',changes_started=false}
 end
 local closed=a.unlock(lock);assert(closed,'fleet control lock close failed');return value
end
M.ORDER=ORDER;M.ROLES=ROLES;M.committed_receipt=committed;M.valid_request=request_valid
M.valid_response=response_valid
if arg and arg[0]==BASE..'/managed_control.lua'and CHUNK_COUNT>0 then
 if CHUNK_COUNT~=2 or CHUNK_MODE~='activate-job'or not hex(CHUNK_NONCE,32)
  or #arg~=2 or arg[1]~=CHUNK_MODE or arg[2]~=CHUNK_NONCE then os.exit(2)end
 local ok,value=pcall(M.run_activation,CHUNK_NONCE);os.exit(ok and value.completed and 0 or 1)
end
return M
