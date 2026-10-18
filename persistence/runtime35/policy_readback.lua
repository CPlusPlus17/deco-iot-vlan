-- Own read-only projection of native user-config. Never import decoded config.
local M={}
local BASE='/tmp/deco-iot-managed'
local OPTIONS={schema=true,enabled=true,vlan_id=true,main_untagged=true,generation=true,scope=true}
local TARGETS={'iot_wifi','deco_iot_vlan','firewall'}
local function tags_valid(tags)
 if tags==nil then tags={iot_wifi='iot_wifi',deco_iot_vlan='deco_iot_vlan',firewall='firewall'}end
 assert(type(tags)=='table','exact native package tags required')
 local count=0;for key in pairs(tags)do assert(key=='iot_wifi'or key=='deco_iot_vlan'or key=='firewall','unknown native package tag');count=count+1 end
 assert(count==3,'three native package tags required')
 for _,base in ipairs(TARGETS)do
  local value=tags[base];assert(type(value)=='string'and #value<=64,'bounded native package tag required')
  if value~=base then
   local suffix=value:match('^'..base..'_(%d+)$')
   assert(suffix and #suffix<=10,'native selected package tag is not a fixed numeric version')
  end
 end
 return tags
end
local function package_name(name,tags)
 for _,base in ipairs(TARGETS)do
  if name==tags[base]then return base end
  assert(name~=base and not name:match('^'..base..'_%d'),'unexpected selected package version or alias')
 end
 return name
end
function M.native_package_tags()
 local config=require('luci.sys.config');local tags={}
 for _,base in ipairs(TARGETS)do tags[base]=config.get_subcfg(base)end
 return tags_valid(tags)
end
local function project(xml,original,installation,allow_absent,tags)
 tags=tags_valid(tags)
 assert(type(xml)=='string' and #xml<=2097152 and not xml:find('%z'),'bounded saved profile required')
 local header='<?xml version="1.0" encoding="utf-8"?>'
 assert(xml:sub(1,#header)==header,'native XML header required')
 local stack,packages,policy,selected={},{},{},{}
 local cursor,root_closed,package_count=#header+1,false,0
 while true do
  local left,right,tag=xml:find('<([^>]*)>',cursor)
  if not left then assert(xml:sub(cursor):match('^%s*$'),'trailing XML text');break end
  assert(not root_closed and left-cursor<=65536,'saved profile structure invalid')
  local text=xml:sub(cursor,left-1);local top=stack[#stack]
  if top then
   if top.capture then top.value=(top.value or '')..text end
   if #stack<=3 and (#stack==1 or (#stack>=2 and (stack[2].package=='deco_iot_vlan' or stack[2].package=='iot_wifi'
    or (installation and stack[2].package=='firewall')))) then
    assert(text:match('^%s*$'),'unexpected saved target text')
   end
  else assert(text:match('^%s*$'),'XML outside root') end
  local closing=tag:match('^/([%w_.:%-]+)$')
  local empty=tag:match('^([%w_.:%-]+)/$')
  if empty then
   empty=package_name(empty,tags)
   assert(#stack==1 and top.name=='config' and empty~='deco_iot_vlan' and empty~='iot_wifi'
    and not (installation and empty=='firewall'),
    'empty saved target/nonpackage refused');top.children=top.children+1;package_count=package_count+1
  elseif closing then
   assert(top and top.name==closing,'saved profile closing tag mismatch')
   if top.capture then
    assert(top.children==0 and not selected[top.capture],'duplicate/nested saved option')
    selected[top.capture]=top.value or ''
   end
   stack[#stack]=nil
   if #stack==0 then root_closed=true end
  else
   local name,section=tag:match('^([%w_.:%-]+) name="([^"]*)"$')
   if not name then name=tag:match('^([%w_.:%-]+)$') end
   assert(name and #stack<12,'unsupported saved XML tag')
   if top then top.children=top.children+1 end
   local item={name=name,section=section,children=0}
   local depth=#stack+1
   if depth==1 then assert(name=='config' and not section,'native config root required')
   elseif depth==2 then
    name=package_name(name,tags);item.package=name
    package_count=package_count+1
    assert(not section,'package attribute refused')
    assert(not original or name~='deco_iot_vlan','original profile already contains managed policy')
    if name=='deco_iot_vlan' or name=='iot_wifi' or (installation and name=='firewall') then
     assert(not packages[name],'duplicate saved target package');packages[name]=true
    end
   elseif depth==3 and stack[2].package=='deco_iot_vlan' then
    assert(name=='policy' and section=='iot' and not policy.section,'unexpected saved policy section');policy.section=true
   elseif depth==3 and stack[2].package=='iot_wifi' and name=='iot' and section=='iot' then
    assert(not policy.native_section,'duplicate saved native IoT section');policy.native_section=true
   elseif installation and depth==3 and stack[2].package=='firewall' and section=='deco_iot_managed' then
    assert(name=='include' and not policy.include_section,'saved owned firewall section invalid');policy.include_section=true
   elseif depth==4 and stack[2].package=='deco_iot_vlan' then
    assert(OPTIONS[name] and not section,'unexpected saved policy option');item.capture='policy_'..name
   elseif depth==4 and stack[2].package=='iot_wifi' and stack[3].name=='iot' and stack[3].section=='iot' and name=='enable' then
    assert(not section,'saved native enable attribute refused');item.capture='native_iot_enable'
   elseif installation and depth==4 and stack[2].package=='firewall' and stack[3].section=='deco_iot_managed' then
    assert(name=='path' and not section,'unexpected saved owned firewall option');item.capture='include_path'
   end
   stack[#stack+1]=item
  end
  cursor=right+1
 end
 assert(root_closed and #stack==0,'saved config XML incomplete')
 if original and allow_absent and not packages.iot_wifi then
  assert(not policy.native_section and selected.native_iot_enable==nil,'absent original IoT contradiction')
  return {schema=1,native_iot_present=false,native_iot_enable='absent',xml_header='native_utf8',root='config',
   package='iot_wifi',section_type='absent',section_name='absent',managed_policy_present=false,package_count=package_count}
 end
 assert(packages.iot_wifi and policy.native_section,'saved native IoT section absent')
 if original then
  assert(not packages.deco_iot_vlan and (selected.native_iot_enable=='0' or selected.native_iot_enable=='1'),
   'original native IoT enable/shape invalid')
  local result={schema=1,native_iot_enable=selected.native_iot_enable,xml_header='native_utf8',root='config',
   package='iot_wifi',section_type='iot',section_name='iot',managed_policy_present=false,package_count=package_count}
  if allow_absent then result.native_iot_present=true end
  return result
 end
 assert(packages.deco_iot_vlan and policy.section,'saved managed policy section absent')
 local result={schema=1,options={},native_iot_enable=selected.native_iot_enable}
 for key in pairs(OPTIONS) do
  local value=selected['policy_'..key];assert(type(value)=='string' and #value<=32,'saved policy option missing')
  result.options[key]=value
 end
 local o=result.options;local number=tonumber(o.generation)
 assert(o.schema=='1' and (o.enabled=='0' or o.enabled=='1') and o.vlan_id=='30' and o.main_untagged=='1'
  and o.scope=='all_three_wired' and o.generation:match('^%d+$') and number and number>=1
  and number<=2147483647 and number==math.floor(number) and tostring(number)==o.generation
  and result.native_iot_enable=='0','saved fixed policy/native IoT0 mismatch')
 if installation then
  assert(packages.firewall and policy.include_section
   and selected.include_path=='/tp_data/user_data/deco-iot-vlan/boot_include.sh','saved fixed startup include mismatch')
  result.firewall_include={type='include',name='deco_iot_managed',path=selected.include_path}
 end
 return result
end
function M.project(xml) return project(xml,false,false,false) end
function M.original_projection(xml) return project(xml,true,false,false) end
function M.original_user_projection(xml) return project(xml,true,false,true) end
local function explicit_tags(tags)assert(type(tags)=='table','explicit exact native tags required');return tags_valid(tags)end
function M.project_native(xml,tags) return project(xml,false,false,false,explicit_tags(tags))end
function M.original_projection_native(xml,tags) return project(xml,true,false,false,explicit_tags(tags))end
function M.original_user_projection_native(xml,tags) return project(xml,true,false,true,explicit_tags(tags))end
local function project_firewall(xml,original,tags)
 tags=tags_valid(tags)
 assert(type(xml)=='string' and #xml<=2097152 and not xml:find('%z'),'bounded device profile required')
 local header='<?xml version="1.0" encoding="utf-8"?>'
 assert(xml:sub(1,#header)==header,'native device XML header required')
 local stack,packages,own={}, {},nil
 local cursor,closed,package_count=#header+1,false,0
 while true do
  local left,right,tag=xml:find('<([^>]*)>',cursor)
  if not left then assert(xml:sub(cursor):match('^%s*$'),'trailing device XML text');break end
  assert(not closed and left-cursor<=65536,'device XML structure invalid')
  local text=xml:sub(cursor,left-1);local top=stack[#stack]
  if top and top.capture then top.value=(top.value or '')..text
  elseif #stack<=3 and (#stack<2 or stack[2].package=='firewall')then assert(text:match('^%s*$'),'unexpected device target text')end
  local closing=tag:match('^/([%w_.:%-]+)$')
  local empty=tag:match('^([%w_.:%-]+)/$')
  if empty then
   empty=package_name(empty,tags)
   assert(#stack==1 and stack[1].name=='config'and empty~='deco_iot_vlan','unsupported empty device target')
   assert(not packages[empty],'duplicate device package');packages[empty]=true;package_count=package_count+1
  elseif closing then
   assert(top and top.name==closing,'device XML closing mismatch')
   if top.capture then assert(top.children==0 and own.path==nil,'duplicate/nested saved startup path');own.path=top.value or ''end
   stack[#stack]=nil;if #stack==0 then closed=true end
  else
   local name,section=tag:match('^([%w_.:%-]+) name="([^"]*)"$')
   if not name then name=tag:match('^([%w_.:%-]+)$')end
   assert(name and #stack<12,'unsupported device XML tag')
   if top then top.children=top.children+1 end
   local item={name=name,section=section,children=0};local depth=#stack+1
   if depth==1 then assert(name=='config'and not section,'native device config root required')
   elseif depth==2 then
    name=package_name(name,tags);item.package=name
    assert(not section and not packages[name],'duplicate/attributed device package')
    assert(name~='deco_iot_vlan','managed policy in device profile refused')
    packages[name]=true;package_count=package_count+1
   elseif depth==3 and stack[2].package=='firewall'and section=='deco_iot_managed'then
    assert(not original,'original device profile contains own startup section')
    assert(name=='include'and not own,'invalid duplicate own startup section');own={}
   elseif depth==4 and stack[2].package=='firewall'and stack[3].section=='deco_iot_managed'then
    assert(own and name=='path'and not section,'unexpected own startup option');item.capture=true
   end
   stack[#stack+1]=item
  end
  cursor=right+1
 end
 assert(closed and #stack==0,'device config XML incomplete')
 if original then
  return {schema=1,xml_header='native_utf8',root='config',profile='device-config',firewall_present=packages.firewall==true,
   own_firewall_include_present=false,managed_policy_present=false,package_count=package_count}
 end
 assert(packages.firewall and own and own.path=='/tp_data/user_data/deco-iot-vlan/boot_include.sh','saved device startup include mismatch')
 return {type='include',name='deco_iot_managed',path=own.path}
end
function M.original_device_projection(xml) return project_firewall(xml,true)end
function M.original_device_projection_native(xml,tags)return project_firewall(xml,true,explicit_tags(tags))end
function M.project_installation(user_xml,device_xml)
 local result=M.project(user_xml)
 result.firewall_include=project_firewall(device_xml,false)
 return result
end
function M.project_installation_native(user_xml,device_xml,tags)
 tags=explicit_tags(tags)
 local result=M.project_native(user_xml,tags)
 result.firewall_include=project_firewall(device_xml,false,tags)
 return result
end
function M.partition_classification()
 local config,mode=require('luci.sys.config'),require('luci.model.mode')
 local result={emmc_supported=mode.is_emmc_support(),packages={}}
 assert(result.emmc_supported==false,'fixed non-emmc profile layout required')
 for _,name in ipairs({'iot_wifi','deco_iot_vlan','firewall','wireless'})do
  local row={user=config.is_user_config(name),device=config.is_device_config(name),emmc=config.is_emmc_config(name)}
  for _,value in pairs(row)do assert(type(value)=='boolean','native profile eligibility type invalid')end
  local user=name=='iot_wifi'or name=='deco_iot_vlan'
  assert(row.user==user and row.device==not user and row.emmc==false,'fixed native profile partition changed')
  result.packages[name]=row
 end
 return result
end
function M.run_installation(nonce)
 assert(type(nonce)=='string'and #nonce==32 and not nonce:find('[^0-9a-f]'),'fixed installation readback nonce required')
 local nx,fs=require('nixio'),require('nixio.fs')
 assert(nx.getuid()==0 and nx.getgid()==0,'root required')
 local root=assert(fs.stat(BASE));assert(root.type=='dir'and root.uid==0 and root.gid==0
  and root.modestr=='rwx------'and not fs.readlink(BASE),'private runtime required')
 M.partition_classification()
 local directory=BASE..'/installation-readback-'..nonce
 assert(not fs.stat(directory)and not fs.readlink(directory)and fs.mkdir(directory),'exclusive installation readback directory unavailable')
 assert(fs.chmod(directory,'rwx------'))
 local files,bodies={},{}
 local ok,result=pcall(function()
  local command=assert(loadfile(BASE..'/bounded_command.lua'))().new({base=BASE,nonce=nonce})
  local mode=require('luci.model.uci').cursor('/etc/profile.d'):get('profile','global','trk_enc_file')or'false'
  assert(mode=='true'or mode=='false','native profile encryption mode invalid')
  local crypto=require('luci.model.crypto')
  for _,profile in ipairs({'user-config','device-config'})do
   M.partition_classification()
   local cry,xml=directory..'/'..profile..'.cry',directory..'/'..profile..'.xml'
   files[#files+1]=cry;files[#files+1]=xml
   local _,code=command:command({'/usr/bin/nvrammanager','-r',cry,'-p',profile});assert(code==0,'native partition read failed')
   local info=assert(fs.stat(cry));assert(info.type=='reg'and info.uid==0 and info.gid==0 and info.size>0 and info.size<=2097152)
   assert(fs.chmod(cry,'rw-------'))
   local algorithms=mode=='true'and {'dec_file_entry','dec_file_entry_prv','dec_file_entry_old'}or{'dec_file_entry_prv','dec_file_entry_old'}
   for _,name in ipairs(algorithms)do
    if fs.stat(xml)then assert(os.remove(xml))end
    local decoder=crypto[name];assert(type(decoder)=='function','native profile decoder unavailable')
    decoder(cry,xml)
    info=fs.stat(xml)
    if info then
     assert(info.type=='reg'and info.uid==0 and info.gid==0 and info.size>=0 and info.size<=2097152)
     assert(fs.chmod(xml,'rw-------'));local f=assert(io.open(xml,'rb'));local body,why=f:read(2097153);assert(f:close())
     if body==nil and why==nil then body=''end
     assert(os.remove(xml));assert(type(body)=='string'and #body<=2097152)
     if body:sub(1,6)=='<?xml 'then bodies[profile]=body;break end
    end
   end
   assert(bodies[profile],'native partition XML header unavailable')
  end
  return M.project_installation_native(bodies['user-config'],bodies['device-config'],M.native_package_tags())
 end)
 bodies=nil
 for _,path in ipairs(files)do if fs.stat(path)then assert(os.remove(path),'installation plaintext/cipher cleanup failed')end end
 assert(fs.rmdir(directory),'installation readback directory cleanup failed')
 assert(ok,'saved two-profile installation readback failed')
 return result
end
function M.run(nonce,installation)
 if installation==true then return M.run_installation(nonce)end
 assert(type(nonce)=='string' and #nonce==32 and not nonce:find('[^0-9a-f]'),'fixed readback nonce required')
 local nx,fs,json=require('nixio'),require('nixio.fs'),require('luci.json')
 assert(nx.getuid()==0 and nx.getgid()==0,'root required')
 local root=assert(fs.stat(BASE));assert(root.type=='dir' and root.uid==0 and root.gid==0
  and root.modestr=='rwx------' and not fs.readlink(BASE),'private runtime required')
 local directory=BASE..'/profile-readback-'..nonce
 assert(not fs.stat(directory) and fs.mkdir(directory),'exclusive readback directory unavailable')
 assert(fs.chmod(directory,'rwx------'))
 local cry,xml=directory..'/readback.cry',directory..'/readback.xml'
 local ok,value=pcall(function()
  local command=assert(loadfile(BASE..'/bounded_command.lua'))().new({base=BASE,nonce=nonce})
  local _,code=command:command({'/usr/bin/nvrammanager','-r',cry,'-p','user-config'})
  assert(code==0,'saved profile read failed')
  local info=assert(fs.stat(cry));assert(info.type=='reg' and info.size>0 and info.size<=2097152,'saved profile size invalid')
  assert(fs.chmod(cry,'rw-------'))
  local uci=require('luci.model.uci').cursor('/etc/profile.d')
  local mode=uci:get('profile','global','trk_enc_file') or 'false'
  assert(mode=='true' or mode=='false','native encryption mode invalid')
  local crypto=require('luci.model.crypto')
  local decrypt=mode=='true' and crypto.dec_file_entry or crypto.dec_file_entry_prv
  assert(type(decrypt)=='function','native decryptor unavailable');decrypt(cry,xml)
  info=assert(fs.stat(xml));assert(info.type=='reg' and info.size>0 and info.size<=2097152,'decoded profile size invalid')
  assert(fs.chmod(xml,'rw-------'))
  local file=assert(io.open(xml,'rb'));local body=file:read(2097153);assert(file:close())
  return M.project_native(body,M.native_package_tags())
 end)
 for _,path in ipairs({cry,xml}) do if fs.stat(path) then assert(os.remove(path),'private readback cleanup failed') end end
 assert(fs.rmdir(directory),'private readback directory cleanup failed')
 assert(ok,'saved fixed policy readback failed')
 return value
end
if arg and arg[0]==BASE..'/policy_readback.lua' then
 assert(#arg==1 or (#arg==2 and arg[2]=='installation'),'fixed readback invocation required')
 local value=M.run(arg[1],arg[2]=='installation');io.write(require('luci.json').encode(value),'\n')
end
return M
