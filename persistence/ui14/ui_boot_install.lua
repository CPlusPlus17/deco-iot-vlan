-- Own fixed MAIN-only read-only UI boot installer. No network/configuration
-- changes or arbitrary assets/paths. Native child binds MUST be installed last.
local M={}
local BASE,PERSIST='/tmp/deco-iot-managed','/tp_data/user_data/deco-iot-vlan'
local MAIN='@MAIN_DEVICE_ID@'
local LEGACY='/tmp/deco-native-ui-00000000000000000000000000000000'
local UI=BASE..'/ui'
local CACHE='/tmp/luci-indexcache'
local FIXED={
 ['usr/lib/lua/luci/controller/admin/vlan_status.lua']='admin/vlan_status.lua',
 ['www/webpages/locale/en_US/lan.js']='lan.js'}
for _,name in ipairs({'models','modules','navigator','navigator.ap'}) do FIXED['www/webpages/config/'..name..'.json']=name..'.json' end
for _,name in ipairs({'guestVlan','iotVlan'}) do for _,file in ipairs({'controllers.js','models.js','view.html'}) do
 FIXED['www/webpages/modules/advanced/network/'..name..'/'..file]='network/'..name..'/'..file
end end
local BINDS={{'admin','/usr/lib/lua/luci/controller/admin'},
 {'network','/www/webpages/modules/advanced/network'}, {'lan.js','/www/webpages/locale/en_US/lan.js'},
 {'modules.json','/www/webpages/config/modules.json'},{'models.json','/www/webpages/config/models.json'},
 {'navigator.json','/www/webpages/config/navigator.json'},{'navigator.ap.json','/www/webpages/config/navigator.ap.json'}}
local TREES={admin='/usr/lib/lua/luci/controller/admin',network='/www/webpages/modules/advanced/network'}
local function hex(v,n) return type(v)=='string' and #v==n and not v:find('[^0-9a-f]') end
local function meta(v) return type(v)=='table' and hex(v.sha1,40) and hex(v.sha256,64)
 and type(v.bytes)=='number' and v.bytes>=1 and v.bytes<=131072 and v.bytes==math.floor(v.bytes) end
local function safe(v) return type(v)=='string' and #v<=160 and v:match('^[%w_.%/-]+$')
 and not v:find('..',1,true) and v:sub(1,1)~='/' and v:sub(-1)~='/' end
local function native(manifest)
 local install=assert(loadfile(BASE..'/runtime_install.lua'))().new(manifest)
 local fs=require('nixio.fs');local a=install.io
 a.dir=fs.dir;a.remove=os.remove
 return a
end
local function count(t) local n=0;for _ in pairs(t) do n=n+1 end;return n end
function M.validate(installation,manifest)
 assert(installation.device_id==MAIN and installation.ui_role=='main' and type(installation.ui_boot)=='table',
  'main UI installation scope required')
 assert(meta(installation.ui_boot.module) and meta(installation.ui_boot.manifest),'UI bootstrap metadata required')
 local u=manifest
 assert(type(u)=='table' and u.schema==1 and u.kind=='deco_main_readonly_ui_boot' and u.role=='main' and u.device_id==MAIN
  and u.package_manifest_sha256=='b1ae6552aa58d69334137748f055f655b86726a7206548f0603438256679ab3e', 'reviewed read-only UI manifest required')
 assert(type(u.assets)=='table' and count(u.assets)==12,'fixed UI asset set required')
 for path in pairs(FIXED) do
  assert(meta(u.assets[path]) and (u.assets[path].stock_sha1==nil or hex(u.assets[path].stock_sha1,40)),
   'UI asset metadata invalid')
 end
 assert(type(u.stock_trees)=='table' and count(u.stock_trees)==2,'fixed stock tree set required')
 for name in pairs(TREES) do
  local tree=u.stock_trees[name];assert(type(tree)=='table' and count(tree)>=1 and count(tree)<=128,'stock UI tree bound')
  for relative,row in pairs(tree) do
   assert(safe(relative) and type(row)=='table' and (row.type=='dir' or row.type=='reg'),'stock tree path invalid')
   if row.type=='reg' then assert(meta(row),'stock tree metadata invalid') end
  end
 end
 assert(u.cache and u.cache.stock and u.cache.installed and u.cache.stock.bytes==16411
  and u.cache.stock.sha1=='a64a38e0eec035ff957659e7950a47bd92fd043a'
  and u.cache.stock.sha256=='ce8fde4a2533d621b87c0d4ffde177b2d62818545fc10c3cd2665a278b0501c9'
  and u.cache.installed.bytes==17534 and u.cache.installed.sha1=='84b27c89fa6fa92384f90997743dfa737e3437f7'
  and u.cache.installed.sha256=='2b92a47a81b66de702daf0215319b1004f8b46b78a9bf5bac79f2b4f3c6d8d4b',
  'trusted route cache metadata changed')
 return u
end
local function mounts(a)
 local out,tmp={},nil
 for line in assert(a.read('/proc/self/mountinfo',131072)):gmatch('[^\r\n]+') do
  local f={};for v in line:gmatch('%S+') do f[#f+1]=v end
  assert(#f>=10,'mountinfo shape')
  out[f[5]]=out[f[5]] or {};table.insert(out[f[5]],{root=f[4],device=f[3]})
  if f[5]=='/tmp' then assert(not tmp,'stacked RAM mount');tmp=f[3] end
 end
 return out,assert(tmp,'RAM mount absent')
end
local function owned(rows,tmp,source) return rows and #rows==1 and rows[1].device==tmp and rows[1].root==source:sub(5) end
local function verify_file(a,path,row)
 assert(not a.readlink(path),'UI file link refused')
 local s=assert(a.stat(path),'UI file absent')
 assert(s.type=='reg' and s.uid==0 and s.gid==0 and s.nlink==1,'UI file owner/type changed')
 local body=assert(a.read(path,131072));assert(#body==row.bytes and a.hash(path)==row.sha1,'UI file bytes changed')
 return body
end
local function verify_assets(a,u,prefix)
 for relative in pairs(FIXED) do verify_file(a,prefix and (prefix..'/'..FIXED[relative]) or ('/'..relative),u.assets[relative]) end
end
local function tree(a,path,expected)
 local seen={};local function walk(dir,relative)
  assert(not a.readlink(dir),'stock UI directory link refused')
  local d=assert(a.stat(dir));assert(d.type=='dir' and d.uid==0 and d.gid==0,'stock UI directory owner/type')
  for name in a.dir(dir) do if name~='.' and name~='..' then
   assert(name:match('^[%w_.%-]+$') and not name:find('..',1,true),'UI tree name invalid')
   local rel=relative=='' and name or relative..'/'..name
   local row=assert(expected[rel],'unexpected stock UI entry');assert(not seen[rel]);seen[rel]=true
   local target=dir..'/'..name;assert(not a.readlink(target),'stock UI link refused')
   if row.type=='dir' then walk(target,rel) else verify_file(a,target,row) end
  end end
 end
 walk(path,'');assert(count(seen)==count(expected),'stock UI tree entry missing')
end
local function cache_kind(a,u,allow_unknown)
 local s=a.stat(CACHE);if not s then assert(not a.readlink(CACHE));return 'absent' end
 assert(s.type=='reg' and s.uid==0 and s.gid==0 and s.nlink==1 and not a.readlink(CACHE),'cache owner/type changed')
 local body=assert(a.read(CACHE,32768));local digest=a.hash(CACHE)
 for _,name in ipairs({'stock','installed'}) do
  if #body==u.cache[name].bytes and digest==u.cache[name].sha1 then return name,body end
 end
 if allow_unknown then return 'unverified_preserved',body end
 error('unknown route cache preserved')
end
local function run(a,args) local _,code=a.command(args);assert(code==0,'fixed UI utility failed') end
local function journal(a,m)
 local raw=a.read(BASE..'/ui-bindings.json',32768);if not raw then return nil end
 local j=a.decode(raw);assert(type(j)=='table' and j.schema==1 and j.device_id==MAIN
  and j.install_nonce==m.install_nonce and j.boot_id==a.read('/proc/sys/kernel/random/boot_id',128):match('^%s*(.-)%s*$'),
  'foreign UI ownership journal')
 return j
end
function M.prepare(installation,cold,adapter)
 assert(type(cold)=='boolean','fixed UI boot phase required')
 local a=adapter or native(installation)
 assert(a.uid()==0,'root required')
 local raw=verify_file(a,PERSIST..'/ui-boot-manifest.json',installation.ui_boot.manifest)
 local u=M.validate(installation,a.decode(raw))
 verify_file(a,PERSIST..'/ui_boot_install.lua',installation.ui_boot.module)
 for path,row in pairs(u.assets) do verify_file(a,PERSIST..'/ui-assets/'..path,row) end
 local records,tmp=mounts(a);local any=false
 for _,bind in ipairs(BINDS) do any=any or records[bind[2]]~=nil end
 if any then
  local source
  for _,bind in ipairs(BINDS) do
   local current=records[bind[2]]
   local here=owned(current,tmp,LEGACY..'/'..bind[1]) and LEGACY or (owned(current,tmp,UI..'/'..bind[1]) and UI or nil)
   assert(here and (not source or source==here),'partial/foreign UI mounts preserved');source=here
  end
  verify_assets(a,u,nil);verify_assets(a,u,source)
  local kind,cache=cache_kind(a,u,true)
  if source==LEGACY then assert(kind=='installed','existing UI route cache must remain exact')
  else
   local j=assert(journal(a,installation),'owned UI journal missing')
   assert(j.completed==true and j.source==UI,'owned UI source state changed')
  end
  return {installed=true,reused=true,source=source,mount_count=7,cache_preserved=true,
   cache_verified=kind=='installed' and a.read(CACHE,32768)==cache,cache_status=kind,read_only=true}
 end
 assert(cold,'new UI parent binds require cold pre-HTTP installation')
 local kind,cache=cache_kind(a,u);assert(kind=='absent' or kind=='stock','cold route index is unexpected')
 assert(not a.stat(UI) and not a.readlink(UI),'existing UI source directory preserved')
 for name,path in pairs(TREES) do tree(a,path,u.stock_trees[name]) end
 for relative,row in pairs(u.assets) do
  if row.stock_sha1 then assert(a.hash('/'..relative)==row.stock_sha1,'stock UI config changed')
  else assert(not a.stat('/'..relative) and not a.readlink('/'..relative),'foreign new UI file preserved') end
 end
 local boot=assert(a.read('/proc/sys/kernel/random/boot_id',128)):match('^%s*(.-)%s*$')
 local j={schema=1,device_id=MAIN,install_nonce=installation.install_nonce,boot_id=boot,source=UI,bindings={},completed=false,created=true}
 assert(a.atomic(BASE..'/ui-bindings.json',a.encode(j)))
 a.mkdir(UI)
 for name,path in pairs(TREES) do run(a,{'/bin/busybox','cp','-a',path,UI..'/'..name});tree(a,UI..'/'..name,u.stock_trees[name]) end
 for _,name in ipairs({'guestVlan','iotVlan'}) do a.mkdir(UI..'/network/'..name);assert(a.chmod(UI..'/network/'..name,'rwxr-xr-x')) end
 for relative,destination in pairs(FIXED) do
  local body=verify_file(a,PERSIST..'/ui-assets/'..relative,u.assets[relative])
  assert(a.write(UI..'/'..destination,body,'rw-r--r--'));verify_file(a,UI..'/'..destination,u.assets[relative])
 end
 if cache then assert(a.write(UI..'/stock-index.bin',cache));assert(a.hash(UI..'/stock-index.bin')==u.cache.stock.sha1) end
 for _,bind in ipairs(BINDS) do
  local target=bind[2];local fresh=mounts(a);assert(not fresh[target],'UI target mounted during staging')
  j.bindings[target]={source=UI..'/'..bind[1],intent=true};assert(a.atomic(BASE..'/ui-bindings.json',a.encode(j)))
  run(a,{'/bin/busybox','mount','--bind',UI..'/'..bind[1],target})
  local now,device=mounts(a);assert(owned(now[target],device,UI..'/'..bind[1]),'UI bind ownership mismatch')
  j.bindings[target].intent=false;assert(a.atomic(BASE..'/ui-bindings.json',a.encode(j)))
 end
 verify_assets(a,u,nil)
 if cache then
  assert(cache_kind(a,u)=='stock' and a.read(CACHE,32768)==cache,'route index changed before invalidation')
  assert(a.remove(CACHE),'trusted stock index invalidation failed')
 end
 j.completed=true;j.stock_index_invalidated=cache~=nil;assert(a.atomic(BASE..'/ui-bindings.json',a.encode(j)))
 return {installed=true,reused=false,source=UI,mount_count=7,stock_index_invalidated=cache~=nil,read_only=true}
end
function M.remove(installation,adapter)
 local a=adapter or native(installation);assert(a.uid()==0)
 local j=journal(a,installation)
 if not j then return {removed=false,preexisting_ui_preserved=true} end
 assert(j.created==true and j.source==UI,'preexisting UI preserved')
 local raw=verify_file(a,PERSIST..'/ui-boot-manifest.json',installation.ui_boot.manifest)
 local u=M.validate(installation,a.decode(raw));local kind,cache=cache_kind(a,u)
 -- Native mobile-wireless child must be removed by native installer first.
 local records,tmp=mounts(a)
 assert(not records['/usr/lib/lua/luci/controller/admin/mobile_app/wireless.lua'],'native UI child bind remains')
 for i=#BINDS,1,-1 do
  local bind=BINDS[i];local rows=records[bind[2]]
  if rows then
   assert(j.bindings[bind[2]] and owned(rows,tmp,UI..'/'..bind[1]),'foreign UI mount preserved')
   run(a,{'/bin/busybox','umount',bind[2]})
   local now=mounts(a);assert(not now[bind[2]],'UI mount remains')
  end
 end
 if kind=='installed' then
  assert(cache_kind(a,u)=='installed' and a.read(CACHE,32768)==cache,'route index changed during UI removal')
  assert(a.remove(CACHE),'owned route invalidation failed')
 end
 if kind~='stock' and j.stock_index_invalidated and a.stat(UI..'/stock-index.bin') then
  local original=verify_file(a,UI..'/stock-index.bin',u.cache.stock)
  assert(not a.stat(CACHE),'route index appeared during UI removal')
  assert(a.write(CACHE,original));assert(cache_kind(a,u)=='stock','stock route restore failed')
 end
 j.removed=true;j.completed=false;assert(a.atomic(BASE..'/ui-bindings.json',a.encode(j)))
 return {removed=true,preexisting_ui_preserved=false,mount_count=0}
end
M.FIXED,M.BINDS=FIXED,BINDS
return M
