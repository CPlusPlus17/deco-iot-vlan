-- Read-only metadata route for the native Deco VLAN status page.
-- Install together with its web assets; this file does not change networking.
module("luci.controller.admin.vlan_status", package.seeall)

local controller = require "luci.model.controller"
local uci = require "luci.model.uci"

local function read_status()
    local cursor = uci.cursor()
    local guest_configured = cursor:get("wifi", "guest") ~= nil
    local iot_configured = cursor:get("iot_wifi", "iot") ~= nil
    local vlan_id = tonumber(cursor:get("wifi", "guest", "vlan_id"))

    -- Zero is the stock unset sentinel. Missing/invalid IDs remain absent,
    -- which the page displays as not configured; no value is written back.
    if not vlan_id or vlan_id ~= vlan_id or vlan_id < 1 or vlan_id > 4094
            or vlan_id % 1 ~= 0 then
        vlan_id = nil
    end

    return {
        guest = {
            configured = guest_configured,
            enabled = cursor:get("wifi", "guest", "enable") == "1",
            vlan_id = vlan_id,
            vlan_enabled = cursor:get("wifi", "guest", "vlan_enable") == "1"
        },
        iot = {
            configured = iot_configured,
            vlan_supported = false
        },
        scope = "guest_global",
        read_only = true
    }
end

-- Own fixed native-authenticated fleet UI. No browser-selected paths or peers.
local BASE='/tmp/deco-iot-managed'
local NODES={
 {name='Main',id='@MAIN_DEVICE_ID@'},
 {name='Satellite 1',id='@BEDROOM_DEVICE_ID@'},
 {name='Satellite 2',id='@CELLAR_DEVICE_ID@'}}
local STABLE={held=true,active=true,disabled=true,aborted=true,degraded=true}
local PHASES={held=true,preparing=true,prepared=true,committed=true,activating=true,
 active=true,disabled=true,aborted=true,error=true,degraded=true}
local function integer(n) return type(n)=='number' and n>=1 and n<=2147483647 and n==math.floor(n) end
local function backend()
 return assert(loadfile(BASE..'/managed_control.lua'))()
end
local function fleet_projection(report)
 assert(type(report)=='table' and report.schema==1 and report.kind=='deco_iot_fleet_status'
  and report.completed==true and report.observed==true and type(report.nodes)=='table','fleet status unavailable')
 local rows,seen={},0
 for key in pairs(report.nodes)do
  local own=false;for _,n in ipairs(NODES)do own=own or key==n.id end
  assert(own,'unexpected fleet node');seen=seen+1
 end
 assert(seen==3,'three fresh fleet statuses required')
 local generation,enabled,aligned,stable=nil,nil,true,true
 for i,n in ipairs(NODES)do
  local r=assert(report.nodes[n.id])
  assert(r.schema==1 and r.kind=='deco_iot_policy_receipt' and r.action=='status'
   and r.device_id==n.id and r.installation_verified==true and r.native_iot_saved_disabled==true
   and r.vlan_id==30 and r.main_untagged==true and r.scope=='all_three_wired'
   and r.runtime_state_observed==true and integer(r.generation) and type(r.enabled)=='boolean'
   and type(r.active)=='boolean' and type(r.ready)=='boolean' and type(r.held)=='boolean'
   and type(r.all_three_generation_committed)=='boolean' and PHASES[r.phase],'invalid fresh fleet status')
  assert(not(r.active and (not r.ready or r.held or not r.enabled)),'contradictory fleet runtime')
  local status=r.active and r.ready and 'active' or (r.held and 'held' or 'degraded')
  if not STABLE[r.phase]then status='pending';stable=false end
  rows[i]={name=n.name,generation=r.generation,desired_enabled=r.enabled,status=status,
   active=r.active,ready=r.ready,held=r.held,attested=r.all_three_generation_committed,phase=r.phase}
  if i==1 then generation,enabled=r.generation,r.enabled
  elseif generation~=r.generation or enabled~=r.enabled then aligned=false end
 end
 local safe=aligned and stable and generation<2147483647
 local result={schema=2,kind='deco_iot_ui_status',backend_verified=true,read_only=true,
  target={vlan_id=30,main_untagged=true,expected_nodes=3},fleet={observed=true,nodes=rows,aligned=aligned},
  configuration={attested=rows[1].attested and rows[2].attested and rows[3].attested},
  persistence={reboot_verified=false},verification={packet_tagging='not_measured',internet='not_measured',isolation='not_measured'},
  capabilities={enable=safe,disable=safe}}
 if aligned then result.generation=generation;result.desired_enabled=enabled end
 return result
end

-- Fixed asynchronous native-auth UI job. Only the root-owned controller file
-- itself is executable; browser data never supplies code, paths or peers.
local UI_CONTROLLER='/usr/lib/lua/luci/controller/admin/vlan_status.lua'
local function ui_read(path,limit)
 local f=assert(io.open(path,'rb'));local s=f:read((limit or 32768)+1);assert(f:close())
 assert(type(s)=='string' and #s<=(limit or 32768),'fixed UI job read bound');return s
end
local function ui_hash(path)
 local s=require('luci.model.subprocess').call_output({'/bin/busybox','timeout','-t','2','-s','KILL','/bin/busybox','sha1sum',path})
 local h,p;if type(s)=='string' then h,p=s:match('^(%x+)  (/.+)\n$')end
 assert(h and #h==40 and p==path,'UI source digest unavailable');return h
end
local function ui_verified()
 local nx,fs,json=require('nixio'),require('nixio.fs'),require('luci.json')
 assert(nx.getuid()==0 and nx.getgid()==0,'root required')
 local d=assert(fs.stat(BASE));assert(d.type=='dir' and d.uid==0 and d.gid==0 and d.modestr=='rwx------' and not fs.readlink(BASE))
 local m=json.decode(ui_read(BASE..'/installation.json'))
 local boot=ui_read('/proc/sys/kernel/random/boot_id',128):match('^%s*(.-)%s*$')
 assert(m.device_id==NODES[1].id and m.boot_id==boot and m.ui_role=='main' and m.committed==true
  and m.ram_guards_installed==true and m.native_iot_saved_disabled==true,'fixed main UI installation required')
 assert(ui_hash('/tp_data/user_data/deco-iot-vlan/ui-boot-manifest.json')==m.ui_boot.manifest.sha1,'UI boot metadata changed')
 local u=json.decode(ui_read('/tp_data/user_data/deco-iot-vlan/ui-boot-manifest.json'))
 local asset=assert(u.assets[UI_CONTROLLER:sub(2)])
 assert(ui_hash(UI_CONTROLLER)==asset.sha1 and #ui_read(UI_CONTROLLER,131072)==asset.bytes,'UI controller source changed')
 assert(ui_hash(BASE..'/managed_control.lua')==m.files['managed_control.lua'].sha1,'native coordinator source changed')
 return m,boot,asset.sha1
end
local function ui_atomic(path,value)
 local nx,json=require('nixio'),require('luci.json');local temp=path..'.next-'..nx.getpid()
 local f=assert(nx.open(temp,nx.open_flags('wronly','creat','excl'),'rw-------'));local body=json.encode(value);assert(#body<=32768)
 local offset=0;while offset<#body do local n=assert(f:write(body,offset));assert(n>0 and n<=#body-offset);offset=offset+n end
 assert(f:sync());assert(f:close());assert(ui_read(temp)==body);assert(os.rename(temp,path));return true
end
local function ui_nonce(value)return type(value)=='string' and #value==32 and not value:find('[^0-9a-f]')end
local function ui_result(nonce,boot)
 assert(ui_nonce(nonce),'fixed job nonce required')
 local value=require('luci.json').decode(ui_read(BASE..'/ui-fleet-'..nonce..'-result.json'))
 assert(type(value)=='table' and value.schema==1 and value.kind=='deco_managed_fleet_job' and value.nonce==nonce
  and value.device_id==NODES[1].id and value.boot_id==boot and (value.state=='pending' or value.state=='done'),'UI job result binding')
 return value
end
local function run_owned_job(PLAN,MODE)
-- Own fixed async coordinator test. Host prepends immutable PLAN and MODE.
local BASE='/tmp/deco-iot-managed'
local nx,fs,json,sp=require('nixio'),require('nixio.fs'),require('luci.json'),require('luci.model.subprocess')
local MAIN='@MAIN_DEVICE_ID@'
local function read(path,limit)
 local f=assert(io.open(path,'rb'));local s=f:read((limit or 32768)+1);assert(f:close())
 assert(type(s)=='string' and #s<=(limit or 32768),'fixed job read bound');return s
end
local function trim(s)return s:match('^%s*(.-)%s*$')end
local function now()return assert(tonumber(read('/proc/uptime',128):match('^[%d.]+')))end
local function hash(path)
 local s=sp.call_output({'/bin/busybox','timeout','-t','2','-s','KILL','/bin/busybox','sha1sum',path})
 local h,p=type(s)=='string' and s:match('^(%x+)  (/.+)\n$')
 -- Lua logical operators collapse multiple returns; parse explicitly.
 if type(s)=='string' then h,p=s:match('^(%x+)  (/.+)\n$') end
 assert(h and #h==40 and p==path,'fixed job source digest unavailable');return h
end
local function process(pid)
 local f=io.open('/proc/'..pid..'/stat','rb');if not f then return nil end
 local s=f:read(4097);assert(f:close());assert(type(s)=='string' and #s<=4096)
 local rest=s:match('^%d+ %(.+%) (.*)$');assert(rest);local fields={};for t in rest:gmatch('%S+') do fields[#fields+1]=t end
 return {pid=pid,start=assert(tonumber(fields[20])),state=fields[1]}
end
local function atomic(path,value)
 assert(not fs.readlink(path));local temp=path..'.next-'..nx.getpid()
 local f=assert(nx.open(temp,nx.open_flags('wronly','creat','excl'),'rw-------'))
 local body=json.encode(value);assert(#body<=32768);local offset=0
 while offset<#body do local n=assert(f:write(body,offset));assert(n>0 and n<=#body-offset);offset=offset+n end
 assert(f:sync());assert(f:close());assert(read(temp)==body);assert(os.rename(temp,path));return true
end
local function context()
 assert(nx.getuid()==0 and nx.getgid()==0 and PLAN.device_id==MAIN and #PLAN.nonce==32
  and not PLAN.nonce:find('[^0-9a-f]'),'fixed main job context')
 assert(trim(read('/tmp/sync-cached-DEV_ID',128))==MAIN
  and trim(read('/proc/sys/kernel/random/boot_id',128))==PLAN.nodes[MAIN].boot_id,'main job identity changed')
 local d=assert(fs.stat(BASE));assert(d.type=='dir' and d.uid==0 and d.gid==0 and d.modestr=='rwx------' and not fs.readlink(BASE))
 local m=json.decode(read(BASE..'/installation.json'))
 assert(m.device_id==MAIN and m.boot_id==PLAN.nodes[MAIN].boot_id and m.install_nonce==PLAN.nodes[MAIN].install_nonce
  and m.committed==true and m.native_iot_saved_disabled==true and m.ram_guards_installed==true,'main job installation changed')
 assert(hash(BASE..'/runtime_install.lua')==PLAN.runtime_install_sha1,'fixed installer source changed')
 local install=assert(loadfile(BASE..'/runtime_install.lua'))().new(m)
 for _,name in ipairs(install.FILES) do
  assert(PLAN.files[name] and m.files[name].sha1==PLAN.files[name] and hash(BASE..'/'..name)==PLAN.files[name],
   'fixed runtime source changed')
 end
 assert(install:identity() and install:verify_targets(),'main job bindings changed')
 return m
end
local prefix=BASE..'/ui-fleet-'..PLAN.nonce
local result_path=prefix..'-result.json'
if MODE=='launch' then
 context()
 assert(not fs.stat(result_path) and not fs.readlink(result_path),'job result already exists')
 assert(hash(UI_CONTROLLER)==PLAN.controller_sha1,'fixed controller source changed')
 local rd,wr=nx.pipe();assert(rd and wr)
 local detached_read,detached_write=nx.pipe();assert(detached_read and detached_write)
 atomic(result_path,{schema=1,kind='deco_managed_fleet_job',nonce=PLAN.nonce,device_id=MAIN,
  boot_id=PLAN.nodes[MAIN].boot_id,action=PLAN.request.action,state='pending',completed=false})
 local pid=assert(nx.fork())
 if pid==0 then
  pcall(function()
   assert(wr:close());assert(detached_read:close());assert(nx.setsid()==nx.getpid())
   assert(nx.setenv('DECO_IOT_OWN_COMMAND_SESSION'));assert(nx.getenv('DECO_IOT_OWN_COMMAND_SESSION')==nil)
   assert(rd:read(1)=='G');assert(rd:close())
   assert(detached_write:write('R')==1);assert(detached_write:close())
   local f=assert(nx.open('/dev/null','w+'));assert(nx.dup(f,nx.stdin));assert(nx.dup(f,nx.stdout));assert(nx.dup(f,nx.stderr))
   local number=assert(tonumber(tostring(f):match('^nixio file (%d+)$')));if number>2 then assert(f:close()) end
   nx.execp('/usr/bin/lua',UI_CONTROLLER,'fleet-job',PLAN.nonce)
  end);os.exit(127)
 end
 assert(rd:close());assert(detached_write:close());local actor=assert(process(pid));assert(actor.state~='Z')
 atomic(prefix..'-actor.json',{schema=1,nonce=PLAN.nonce,device_id=MAIN,boot_id=PLAN.nodes[MAIN].boot_id,
  pid=pid,start=actor.start,deadline=now()+290})
 assert(wr:write('G')==1);assert(wr:close())
 assert(detached_read:read(1)=='R');assert(detached_read:close())
 return {schema=1,kind='deco_managed_fleet_launch',nonce=PLAN.nonce,device_id=MAIN,
  boot_id=PLAN.nodes[MAIN].boot_id,pid=pid,start=actor.start,result_path=result_path,launched=true}
end
assert(MODE=='run','fixed own job mode')
local result={schema=1,kind='deco_managed_fleet_job',nonce=PLAN.nonce,device_id=MAIN,
 boot_id=PLAN.nodes[MAIN].boot_id,action=PLAN.request.action,state='done',completed=false}
local ok,why=pcall(function()
 context()
 local actor=json.decode(read(prefix..'-actor.json'));local own=assert(process(nx.getpid()))
 assert(actor.nonce==PLAN.nonce and actor.pid==own.pid and actor.start==own.start and actor.boot_id==PLAN.nodes[MAIN].boot_id)
 local control=assert(loadfile(BASE..'/managed_control.lua'))();local adapter=control.new().io
 local rpc,nonce=adapter.rpc,adapter.nonce
 function adapter.rpc(id,request)
  assert(now()<actor.deadline,'fixed fleet job deadline')
  local value=rpc(id,request);local expected=assert(PLAN.nodes[id])
  assert(value.device_id==id and value.boot_id==expected.boot_id and value.install_nonce==expected.install_nonce,
   'peer installation/boot changed');return value
 end
 function adapter.nonce() assert(now()<actor.deadline,'fixed fleet job deadline');return nonce() end
 result.response=control.coordinate(PLAN.request,adapter)
 result.completed=type(result.response)=='table' and result.response.completed==true
end)
if not ok then result.error='fixed_managed_job_failed';result.private_reason=tostring(why):sub(1,384) end
atomic(result_path,result)
os.exit(result.completed and 0 or 1)

end

local function ui_status()
 local status=fleet_projection(backend().coordinate({action='status'}))
 local fs=require('nixio.fs')
 status.maintenance=fs.stat(BASE..'/ui-maintenance.json')~=nil or not not fs.readlink(BASE..'/ui-maintenance.json')
 if status.maintenance then status.capabilities.enable=false;status.capabilities.disable=false end
 return status
end

local function ui_job(params)
 assert(type(params)=='table' and ui_nonce(params.nonce),'fixed job poll required')
 for key in pairs(params)do assert(key=='nonce','job accepts no arbitrary inputs')end
 local _,boot=ui_verified();local value=ui_result(params.nonce,boot)
 if value.state=='pending'then return {schema=3,kind='deco_iot_ui_job',nonce=params.nonce,state='pending',completed=false,outcome='pending'}end
 local report=value.response
 if value.completed~=true or type(report)~='table' or report.completed~=true then
  return {schema=3,kind='deco_iot_ui_job',nonce=params.nonce,state='done',completed=false,outcome='unverified',refresh_required=true}
 end
 assert(report.kind=='deco_iot_fleet_operation' and report.vlan_id==30 and report.main_untagged==true
  and report.scope=='all_three_wired' and integer(report.generation) and type(report.enabled)=='boolean','fixed fleet completion invalid')
 local status=fleet_projection({schema=1,kind='deco_iot_fleet_status',observed=true,completed=true,nodes=report.nodes})
 assert(status.generation==report.generation and status.desired_enabled==report.enabled and status.configuration.attested==true)
 for _,r in ipairs(status.fleet.nodes)do assert(r.active==report.enabled and r.ready==report.enabled and r.held==not report.enabled)end
 return {schema=3,kind='deco_iot_ui_job',nonce=params.nonce,state='done',completed=true,outcome='observed',status=status,refresh_required=false}
end
local function ui_apply(params)
 assert(type(params)=='table','fixed policy input required')
 for key in pairs(params)do assert(key=='enabled' or key=='expected_generation','unsupported policy input')end
 assert(type(params.enabled)=='boolean' and integer(params.expected_generation) and params.expected_generation<2147483647)
 local m,boot,source_hash=ui_verified();local nx,fs,json=require('nixio'),require('nixio.fs'),require('luci.json')
 assert(not fs.stat(BASE..'/ui-maintenance.json')and not fs.readlink(BASE..'/ui-maintenance.json'),'UI maintenance active')
 assert(not fs.readlink(BASE..'/ui-fleet.lock'));local lock=assert(nx.open(BASE..'/ui-fleet.lock','a'))
 local good,value=pcall(function()
  assert(lock:lock('tlock'),'UI job launch busy')
  assert(not fs.stat(BASE..'/ui-maintenance.json')and not fs.readlink(BASE..'/ui-maintenance.json'),'UI maintenance active')
  local f=io.open(BASE..'/ui-fleet-current.json','rb')
  if f then
   local body=f:read(32769);assert(f:close());assert(type(body)=='string'and #body<=32768)
   local old=json.decode(body);assert(old.device_id==m.device_id and old.boot_id==boot and ui_nonce(old.nonce),'foreign UI job preserved')
   local previous=ui_result(old.nonce,boot)
   if previous.state=='pending'then return {schema=3,kind='deco_iot_ui_job',nonce=old.nonce,state='pending',completed=false,outcome='pending_existing'}end
  end
  -- Fresh native receipts pin each peer's current boot and installation before
  -- the detached coordinator's own generation CAS runs.
  local observed=backend().coordinate({action='status'});local status=fleet_projection(observed)
  assert(status.generation==params.expected_generation and status.fleet.aligned,'fresh fleet generation changed')
  local nonce=ui_read('/proc/sys/kernel/random/uuid',128):gsub('%-',''):gsub('%s','');assert(ui_nonce(nonce))
  local plan={nonce=nonce,device_id=m.device_id,controller_sha1=source_hash,request={action=params.enabled and 'configure' or 'disable',
   enabled=params.enabled,expected_generation=params.expected_generation},nodes={},files={},runtime_install_sha1=m.files['runtime_install.lua'].sha1}
  for _,n in ipairs(NODES)do local r=assert(observed.nodes[n.id]);plan.nodes[n.id]={boot_id=r.boot_id,install_nonce=r.install_nonce}end
  for name,row in pairs(m.files)do plan.files[name]=row.sha1 end
  local path=BASE..'/ui-fleet-'..nonce..'-request.json';assert(not fs.stat(path)and not fs.readlink(path));assert(ui_atomic(path,plan))
  -- Publish ownership BEFORE the child can mutate. An interrupted response
  -- therefore cannot cause a second blind start from another browser request.
  assert(ui_atomic(BASE..'/ui-fleet-current.json',{schema=1,device_id=m.device_id,boot_id=boot,nonce=nonce}))
  local result=run_owned_job(plan,'launch');assert(result.launched==true)
  return {schema=3,kind='deco_iot_ui_job',nonce=nonce,state='pending',completed=false,outcome='pending'}
 end)
 local closed=lock:close();assert(good and closed,'fixed UI launch unverified');return value
end

local function managed_dispatch(request)
 assert(type(request)=='table' and (request.form=='iot_status' or request.form=='iot_apply' or request.form=='iot_job'),'fixed IoT form required')
 for key in pairs(request)do assert(key=='form' or key=='operation' or key=='params' or key=='config_version','unexpected IoT request field')end
 if request.form=='iot_status'then
  assert(request.operation=='read' and (request.params==nil or (type(request.params)=='table' and next(request.params)==nil)),
   'status cannot change policy');return ui_status()
 end
 if request.form=='iot_job'then assert(request.operation=='read','job poll is read only');return ui_job(request.params)end
 assert(request.operation=='write','policy form requires write');return ui_apply(request.params)
end

local callbacks={status={read={cb=read_status}}}
function dispatch(request)
 if type(request)=='table' and (request.form=='iot_status' or request.form=='iot_apply' or request.form=='iot_job')then
  local ok,result=pcall(managed_dispatch,request)
  if not ok then return {success=false,errorcode='fixed_iot_vlan_request_unverified'}end
  return {success=true,data=result}
 end
 return controller.dispatch(callbacks,request)
end

function _index()
    return controller._index(dispatch)
end

function index()
    local page = entry({"admin", "vlan_status"}, call("_index"))
    page.leaf = true
    page.sysauth = true
end

if arg and arg[0]==UI_CONTROLLER then
 local ok=pcall(function()
  assert(#arg==2 and arg[1]=='fleet-job' and ui_nonce(arg[2]),'fixed controller job invocation')
  local m,boot,source_hash=ui_verified()
  local path=BASE..'/ui-fleet-'..arg[2]..'-request.json';local fs=require('nixio.fs')
  assert(not fs.readlink(path));local st=assert(fs.stat(path))
  assert(st.type=='reg'and st.uid==0 and st.gid==0 and st.nlink==1 and st.modestr=='rw-------')
  local plan=require('luci.json').decode(ui_read(path));assert(plan.nonce==arg[2]and plan.device_id==m.device_id
   and plan.nodes[m.device_id].boot_id==boot and plan.nodes[m.device_id].install_nonce==m.install_nonce
   and plan.controller_sha1==source_hash,'controller job request binding')
  for key in pairs(plan)do assert(key=='nonce'or key=='device_id'or key=='controller_sha1'or key=='request'
   or key=='nodes'or key=='files'or key=='runtime_install_sha1','unknown fixed job plan field')end
  assert(type(plan.request)=='table'and (plan.request.action=='configure'or plan.request.action=='disable')
   and type(plan.request.enabled)=='boolean'and integer(plan.request.expected_generation))
  run_owned_job(plan,'run')
 end)
 os.exit(ok and 0 or 1)
end
