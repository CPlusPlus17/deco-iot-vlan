-- Own fixed boot/RAM installer. No configuration save, firmware update or
-- interface operation is performed here. The host installer supplies the
-- three-node generation attestation after actual native profile verification.
local M={}
local PERSIST="/tp_data/user_data/deco-iot-vlan"
local BASE="/tmp/deco-iot-managed"
local NODES={["@MAIN_DEVICE_ID@"]=true,
    ["@BEDROOM_DEVICE_ID@"]=true,["@CELLAR_DEVICE_ID@"]=true}
local FILES={"bounded_command.lua","declarative_policy.lua","managed_cursor_guard.lua",
    "uci_guard_loader.lua","uci_model_wrapper.lua","lifecycle_plan.lua","kernel_platform.lua",
    "observe_owned_state.lua","hook_decision.lua","hook_query.lua","native_quiesce.lua",
    "event_state.lua","event_broker.lua","hook_action.lua","native_hooks.sh","native_adapter.lua",
    "scoped_vap.sh","scoped_create.lua","wifi_quiet.lua","hook_callbacks.lua","worker.lua","runtime_install.lua","boot_wait.lua",
    "managed_control.lua","mobile_wireless_wrapper.lua","policy_readback.lua","boot_entry.lua","boot_include.sh",
    "patches/wificommon.sh","patches/guest-eth.sh","patches/guest-vlan.sh","patches/network","patches/core.sh",
    "patches/wifi","patches/wifiupdate.sh"}
local TARGETS={
    {key="uci_model_wrapper.lua",path="/usr/lib/lua/luci/model/uci.lua",stock="stock/luci_model_uci.luac"},
    {key="patches/wificommon.sh",path="/lib/wifi/wificommon.sh"},
    {key="patches/guest-eth.sh",path="/lib/guest-eth/guest-eth.sh"},
    {key="patches/guest-vlan.sh",path="/lib/guest-eth/guest-vlan.sh"},
    {key="patches/network",path="/etc_ro/init.d/network",visible="/etc/init.d/network"},
    {key="patches/core.sh",path="/lib/firewall/core.sh"},
    {key="mobile_wireless_wrapper.lua",path="/usr/lib/lua/luci/controller/admin/mobile_app/wireless.lua",stock="stock/mobile_wireless.luac"},
    {key="patches/wifi",path="/sbin/wifi"},{key="patches/wifiupdate.sh",path="/lib/wifi/wifiupdate.sh"}}
local function trim(s) return s and s:match("^%s*(.-)%s*$") end
local function hex(s,n) return type(s)=="string" and #s==n and not s:find("[^0-9a-f]") end
-- Private exact-child SHA1 executor; no extra installed module or cold dependency.
local function fixed_hash_module()
-- Staged own helper, not an installed runtime module. The caller verifies the
-- staged source/inode before loading it. Only BusyBox's single-file SHA1 applet
-- is executable; EOF or a digest never substitutes for an exact child reap.
local M={}
local ERRORS={fixed_sha1_failed=true,fixed_sha1_cleanup_unknown=true}
function M.error_code(value)return type(value)=='string'and ERRORS[value]and value or'fixed_sha1_unclassified_error'end
local function check(value,code)
 if not value then ERRORS[code]=true;error(code,0)end;return value
end
local RAM='/tmp/deco-iot-managed'
local PERSIST='/tp_data/user_data/deco-iot-vlan'
local FIXED={['/proc/self/mountinfo']=true}
for _,path in ipairs({
 '/etc_ro/init.d/network','/lib/firewall/core.sh','/lib/guest-eth/guest-eth.sh',
 '/lib/guest-eth/guest-vlan.sh','/lib/wifi/wificommon.sh','/lib/wifi/wifiupdate.sh',
 '/sbin/wifi','/lib/wifi/hostapd.sh','/usr/lib/lua/luci/controller/admin/mobile_app/wireless.lua',
 '/usr/lib/lua/luci/model/uci.lua','/usr/lib/lua/luci/controller/admin/vlan_status.lua',
 '/www/webpages/config/models.json','/www/webpages/config/modules.json',
 '/www/webpages/config/navigator.ap.json','/www/webpages/config/navigator.json',
 '/www/webpages/locale/en_US/lan.js',
 '/www/webpages/modules/advanced/network/guestVlan/controllers.js',
 '/www/webpages/modules/advanced/network/guestVlan/models.js',
 '/www/webpages/modules/advanced/network/guestVlan/view.html',
 '/www/webpages/modules/advanced/network/iotVlan/controllers.js',
 '/www/webpages/modules/advanced/network/iotVlan/models.js',
 '/www/webpages/modules/advanced/network/iotVlan/view.html'})do FIXED[path]=true end
local function integer(v,lo,hi)return type(v)=='number'and v==math.floor(v)and v>=lo and v<=hi end
local function decimal(v)return type(v)=='string'and #v<=20 and v:match('^[1-9]%d*$')~=nil end
local function same(a,b)return a and b and a.type==b.type and a.dev==b.dev and a.ino==b.ino
 and a.uid==b.uid and a.gid==b.gid and a.nlink==b.nlink end
local function relative(s)
 if s==''or #s>512 or s:find('[^A-Za-z0-9_./%-]')or s:sub(1,1)=='/'or s:sub(-1)=='/'or s:find('//',1,true)then return false end
 for part in s:gmatch('[^/]+')do if part=='.'or part=='..'then return false end end;return true
end
function M.parse_stat(raw,pid)
 if type(raw)~='string'or #raw>4096 then return nil end
 local emitted,_,tail=raw:match('^(%d+) %((.*)%) (.*)$');if emitted~=tostring(pid)then return nil end
 local fields={};for word in (tail or''):gmatch('%S+')do fields[#fields+1]=word;if #fields>64 then return nil end end
 if #fields<20 or not decimal(fields[20])then return nil end
 local ppid,group,session=tonumber(fields[2]),tonumber(fields[3]),tonumber(fields[4])
 if not integer(ppid,0,4194304)or not integer(group,0,4194304)or not integer(session,0,4194304)
  or not fields[1]:match('^[RSDZTtXxKWPI]$')then return nil end
 return{pid=pid,start=fields[20],ppid=ppid,group=group,session=session,state=fields[1]}
end
function M.new(options)
 check(type(options)=='table'and type(options.nonce)=='string'and #options.nonce==32
  and not options.nonce:find('[^0-9a-f]'),'fixed_sha1_context')
 local nx,fs=options.nx or require('nixio'),options.fs or require('nixio.fs')
 local parent=nx.getpid();check(nx.getuid()==0 and integer(parent,2,4194304),'fixed_sha1_owner')
 local function read(path,limit,process)
  local f,_,errno=io.open(path,'rb')
  if not f then if process and(errno==2 or errno==3)then return nil end;error('fixed_sha1_read_open',0)end
  local ok,body,why,code=pcall(f.read,f,limit+1);local closed=f:close()
  check(ok and closed==true,'fixed_sha1_read_close')
  if body==nil and process and code==3 then return nil end
  check(type(body)=='string'and #body<=limit,'fixed_sha1_read_body');return body
 end
 local function process(pid)
  local raw=read('/proc/'..pid..'/stat',4096,true)
  if not raw then return nil end;return check(M.parse_stat(raw,pid),'fixed_sha1_process_parse')
 end
 local here=check(process(parent),'fixed_sha1_parent_absent')
 local sequence,tainted=0,false
 local metrics={schema=1,calls_started=0,calls_succeeded=0,calls_failed=0,children_forked=0,children_reaped=0,
  signals_sent=0,captures_created=0,captures_removed=0,cleanup_unknown=0}
 local function clock()
  local value=tonumber(read('/proc/uptime',128):match('^([%d.]+)'))
  return check(value and value>=0 and value<math.huge and value,'fixed_sha1_clock')
 end
 local function pause()local ok=nx.nanosleep(0,1000000);check(ok==true or ok==false,'fixed_sha1_sleep')end
 local function private_dir(path)
  check(not fs.readlink(path),'fixed_sha1_directory_link');local st=check(fs.stat(path),'fixed_sha1_directory_missing')
  check(st.type=='dir'and st.uid==0 and st.gid==0 and st.modestr=='rwx------','fixed_sha1_directory_owner');return st
 end
 local function allowed(path)
  if type(path)~='string'or #path>768 then return false end
  if FIXED[path]then return true end
  for _,base in ipairs({RAM,PERSIST})do if path:sub(1,#base+1)==base..'/'then return relative(path:sub(#base+2))end end
  local pid,fd,suffix=path:match('^/proc/(%d+)/fd/(%d+)/(.*)$')
  if pid==tostring(parent)and fd and #fd<=6 and tostring(tonumber(fd))==fd and relative(suffix)then
   local target=fs.readlink('/proc/'..pid..'/fd/'..fd)
   for _,base in ipairs({RAM,PERSIST})do
    if target==base or target==base..'/.ner-'..options.nonce then return true end
   end
  end
  local kind,part=path:match('^/tmp/deco%-ner%-'..options.nonce..'%-([a-z]+)%-(%d%d%d%d)%.bin$')
  return(kind=='lifecycle'or kind=='persist'or kind=='ram')and tonumber(part)>=1 and tonumber(part)<=32 or false
 end
 local object={}
 function object:snapshot()
  local copy={tainted=tainted};for k,v in pairs(metrics)do copy[k]=v end;return copy
 end
 function object:sha1(path)
  check(not tainted,'fixed_sha1_previous_failure');check(allowed(path),'fixed_sha1_path')
  local current=check(process(parent),'fixed_sha1_parent_absent');check(current.start==here.start,'fixed_sha1_parent_reused')
  local directory=private_dir(RAM);sequence=sequence+1;check(sequence<=65535,'fixed_sha1_sequence');metrics.calls_started=metrics.calls_started+1
  local capture_path=RAM..'/.fixed-sha1-'..options.nonce..'-'..parent..'-'..sequence..'.out'
  local capture,capstat,created,gate_read,gate_write,null,pid,child_start,reaped,close_failed
  local until_time=clock()+2
  local function close(which)
   local f
   if which=='read'then f=gate_read;gate_read=nil elseif which=='write'then f=gate_write;gate_write=nil
   elseif which=='null'then f=null;null=nil else f=capture;capture=nil end
   if f then local ok,value=pcall(f.close,f);if not ok or value~=true then close_failed=true;return false end end;return true
  end
  local function wait()
   local got,event,code=nx.waitpid(pid,'nohang')
   if got==false then return false end
   check(got==pid and(event=='exited'or event=='signaled')and integer(code,0,255),'fixed_sha1_wait_unknown')
   reaped=true;metrics.children_reaped=metrics.children_reaped+1;return{event=event,code=code}
  end
  local function child()
   local ok=pcall(function()
    check(nx.setsid()==nx.getpid(),'fixed_sha1_child_session');check(close('write'),'fixed_sha1_child_close')
    check(nx.dup(null,nx.stdin)and nx.dup(capture,nx.stdout)and nx.dup(capture,nx.stderr),'fixed_sha1_child_stdio')
    check(close('null')and close('capture'),'fixed_sha1_child_close')
    local go=gate_read:read(1);check(close('read'),'fixed_sha1_child_close');if go~='G'then return end
    nx.exec('/bin/busybox','sha1sum',path)
   end)
   -- No parent return path is reachable, including exec failure or revoked G.
   os.exit(127)
  end
  local ok,value=pcall(function()
   check(not fs.readlink(capture_path),'fixed_sha1_capture_link')
   capture=check(nx.open(capture_path,nx.open_flags('rdwr','creat','excl','nonblock')+32768,'rw-------'),'fixed_sha1_capture_open');created=true;metrics.captures_created=metrics.captures_created+1
   capstat=check(capture:stat(),'fixed_sha1_capture_stat')
   check(capstat.type=='reg'and capstat.uid==0 and capstat.gid==0 and capstat.nlink==1
    and capstat.modestr=='rw-------'and capstat.size==0 and same(capstat,fs.stat(capture_path)),'fixed_sha1_capture_owner')
   null=check(nx.open('/dev/null','r'),'fixed_sha1_null')
   local r,w=nx.pipe();check(r,'fixed_sha1_pipe');gate_read=r;check(w,'fixed_sha1_pipe');gate_write=w
   pid=nx.fork();check(integer(pid,0,4194304),'fixed_sha1_fork');if pid==0 then child()end
   metrics.children_forked=metrics.children_forked+1
   check(close('read')and close('null'),'fixed_sha1_parent_close')
   while true do
    local p=check(process(pid),'fixed_sha1_child_absent')
    if not child_start then child_start=p.start else check(child_start==p.start,'fixed_sha1_child_reused')end
    check(p.ppid==parent and p.state~='Z','fixed_sha1_child_identity')
    if p.group==pid and p.session==pid then break end
    check(clock()<until_time,'fixed_sha1_setup_deadline');pause()
   end
   check(gate_write:write('G')==1,'fixed_sha1_gate');check(close('write'),'fixed_sha1_gate_close')
   local result
   while not result do result=wait();if not result then check(clock()<until_time,'fixed_sha1_deadline');pause()end end
   check(result.event=='exited'and result.code==0,'fixed_sha1_exit')
   check(clock()<=until_time,'fixed_sha1_deadline')
   local after=check(capture:stat(),'fixed_sha1_output_stat')
   check(same(capstat,after)and after.modestr=='rw-------'and same(capstat,fs.stat(capture_path))and after.size<=1024
    and not fs.readlink(capture_path),'fixed_sha1_output_identity')
   check(capture:seek(0,'set')==0,'fixed_sha1_output_seek')
   local pieces,total={},0
   while true do local body=capture:read(1025-total);check(type(body)=='string','fixed_sha1_output_read')
    if #body==0 then break end;total=total+#body;check(total<=1024,'fixed_sha1_output_bound');pieces[#pieces+1]=body end
   local body=table.concat(pieces);local digest,emitted=body:match('^([0-9a-f]+)  (/.+)\n$')
   check(digest and #digest==40 and emitted==path and #body==after.size,'fixed_sha1_output_format')
   check(same(directory,private_dir(RAM)),'fixed_sha1_directory_changed');check(clock()<=until_time,'fixed_sha1_deadline');return digest
  end)
  -- Closing G before cleanup revokes a child which has not been released.
  local write_closed,read_closed,null_closed=close('write'),close('read'),close('null')
  local closed=write_closed and read_closed and null_closed and not close_failed
  local cleaned=true
  if pid and pid>0 and not reaped then
   local cleanup_ok=pcall(function()
    local result=wait()
    if not result then
     local observed,p=pcall(process,pid)
     if child_start and observed and p and p.start==child_start and p.ppid==parent then
      check(nx.kill(pid,9),'fixed_sha1_stop');metrics.signals_sent=metrics.signals_sent+1
     end
     -- A revoked gate can exit before start capture. Exact waitpid still
     -- proves ownership; never signal an unknown/reused/unreadable identity.
     local deadline=clock()+0.25
     repeat result=wait();if not result then check(clock()<deadline,'fixed_sha1_cleanup_deadline');pause()end until result
    end
   end)
   cleaned=cleanup_ok and reaped==true
  end
  local ending=capstat and fs.stat(capture_path)
  local owner_ok=capstat and capstat.type=='reg'and capstat.uid==0 and capstat.gid==0 and capstat.nlink==1
   and capstat.modestr=='rw-------'and same(capstat,ending)and ending.modestr=='rw-------'and not fs.readlink(capture_path)
  local capture_closed=close('capture')
  local removed=not created
  if owner_ok then removed=fs.unlink(capture_path)==true;if removed then metrics.captures_removed=metrics.captures_removed+1 end end
  if not ok or not closed or not cleaned or not capture_closed or not removed then
   tainted=not closed or not cleaned or not capture_closed or not removed
   metrics.calls_failed=metrics.calls_failed+1;if tainted then metrics.cleanup_unknown=metrics.cleanup_unknown+1 end
   if not cleaned then error('fixed_sha1_cleanup_unknown',0)end
   if not ok and ERRORS[value]then error(value,0)end
   error(not cleaned and'fixed_sha1_cleanup_unknown'or'fixed_sha1_failed',0)
  end
  metrics.calls_succeeded=metrics.calls_succeeded+1
  return value
 end
 return object
end
return M
end
local function native(manifest)
    local nx,fs,json=require("nixio"),require("nixio.fs"),require("luci.json")
    local a={decode=json.decode,encode=json.encode,uid=nx.getuid,stat=fs.stat,readlink=fs.readlink,chmod=fs.chmod}
    function a.read(path,limit)
        local f=io.open(path,"rb");if not f then return nil end
        local body=f:read(limit+1);local closed=f:close()
        if body==nil and closed then body="" end
        assert(closed and type(body)=="string" and #body<=limit,"bounded installation read")
        return body
    end
    function a.write(path,body,mode)
        local f=assert(nx.open(path,"w",mode or "rw-------"),"owned installation write unavailable")
        local done=0
        while done<#body do
            local n=assert(f:write(body,done));assert(n>0 and n<=#body-done);done=done+n
        end
        assert(f:sync());assert(f:close());assert(fs.chmod(path,mode or "rw-------"));return true
    end
    function a.atomic(path,body)
        assert(a.write(path..".next",body));assert(os.rename(path..".next",path));return true
    end
    function a.mkdir(path)
        assert(not fs.readlink(path),"installation directory link refused")
        local st=fs.stat(path)
        if not st then assert(fs.mkdir(path));assert(fs.chmod(path,"rwx------"));st=assert(fs.stat(path)) end
        assert(st.type=="dir" and st.uid==0 and st.gid==0 and st.modestr=="rwx------","private installation directory required")
        return true
    end
    local hasher,hash_boot
    local function hash_identity()
        local boot=trim(assert(a.read("/proc/sys/kernel/random/boot_id",128)))
        local device=trim(assert(a.read("/tmp/sync-cached-DEV_ID",128)))
        local path=BASE.."/installation.json";local st=fs.stat(path)
        assert(nx.getuid()==0 and st and not fs.readlink(path) and st.type=="reg" and st.uid==0 and st.gid==0
            and st.nlink==1 and st.modestr=="rw-------" and st.size<=32768,"installation hash context invalid")
        local ram=json.decode(assert(a.read(path,32768)))
        assert(type(boot)=="string" and #boot==36 and device==manifest.device_id and type(ram)=="table"
            and ram.device_id==device and ram.install_nonce==manifest.install_nonce and ram.boot_id==boot,
            "installation hash identity changed")
        if hash_boot then assert(hash_boot==boot,"installation hash boot changed")end
        return boot
    end
    function a.hash(path)
        local boot=hash_identity()
        if not hasher then
            local nonce=trim(assert(a.read("/proc/sys/kernel/random/uuid",128))):gsub("%-","")
            assert(hex(nonce,32),"installation hash nonce unavailable")
            hasher=fixed_hash_module().new({nonce=nonce});hash_boot=boot
        end
        local digest=hasher:sha1(path);assert(hash_identity()==boot,"installation hash identity changed")
        return digest
    end
    local runner
    function a.command(argv)
        if not runner then
            local nonce=trim(assert(a.read("/proc/sys/kernel/random/uuid",128))):gsub("%-","")
            assert(hex(nonce,32),"installation nonce unavailable")
            runner=assert(loadfile(BASE.."/bounded_command.lua"))().new({base=BASE,nonce=nonce})
        end
        return runner:command(argv)
    end
    return a
end
function M.validate(manifest)
    local m=manifest
    assert(type(m)=="table" and m.schema==1 and hex(m.install_nonce,32) and type(m.device_id)=="string"
        and NODES[m.device_id]==true
        and type(m.generation)=="number" and m.generation>=1 and m.generation<=2147483647 and m.generation==math.floor(m.generation)
        and type(m.committed)=="boolean" and type(m.all_three_generation_committed)=="boolean"
        and m.native_iot_saved_disabled==true,"fixed installation manifest invalid")
    assert(type(m.files)=="table" and type(m.targets)=="table" and type(m.hook_sha1)=="table","installation file manifest missing")
    local count=0;for _ in pairs(m.files) do count=count+1 end;assert(count==#FILES,"installation file allowlist changed")
    for _,name in ipairs(FILES) do
        local f=m.files[name]
        assert(type(f)=="table" and hex(f.sha1,40) and hex(f.sha256,64) and type(f.bytes)=="number"
            and f.bytes==math.floor(f.bytes) and f.bytes>=1 and f.bytes<=131072,"installation file metadata invalid")
    end
    count=0;for _ in pairs(m.targets) do count=count+1 end;assert(count==#TARGETS,"native target allowlist changed")
    count=0;for _ in pairs(m.hook_sha1) do count=count+1 end;assert(count==#TARGETS,"hook hash allowlist changed")
    for _,target in ipairs(TARGETS) do
        local t=m.targets[target.path];local visible=target.visible or target.path
        assert(type(t)=="table" and hex(t.stock_sha1,40) and t.source==target.key
            and t.patched_sha1==m.files[target.key].sha1 and m.hook_sha1[visible]==t.patched_sha1,
            "native target metadata invalid")
    end
    return m
end
function M.new(manifest,adapter)
    local checked=M.validate(manifest)
    return setmetatable({manifest=checked,io=adapter or native(checked)},{__index=M})
end
function M:stage()
    local a,m=self.io,self.manifest
    assert(a.uid()==0,"root required")
    -- Both bases must be real root-owned private directories. The separate
    -- host preflight resolves the parent filesystem's UID1000 ownership.
    local existed=a.stat(BASE)~=nil
    a.mkdir(PERSIST);a.mkdir(BASE)
    local boot=trim(assert(a.read("/proc/sys/kernel/random/boot_id",128)))
    assert(#boot==36,"boot identity unavailable")
    local old=a.read(BASE.."/installation.json",32768)
    if old then
        local installed=a.decode(old)
        assert(installed.install_nonce==m.install_nonce and installed.device_id==m.device_id and installed.boot_id==boot,
            "foreign RAM installation")
    else
        assert(not existed,"unclaimed pre-existing RAM directory")
        local ram={};for k,v in pairs(m) do ram[k]=v end;ram.boot_id=boot
        assert(a.atomic(BASE.."/installation.json",a.encode(ram)))
    end
    a.mkdir(BASE.."/patches");a.mkdir(BASE.."/stock")
    for _,name in ipairs(FILES) do
        local f=m.files[name];local source=PERSIST.."/"..name;local target=BASE.."/"..name
        assert(not a.readlink(source) and a.hash(source)==f.sha1,"persistent source hash changed")
        local body=assert(a.read(source,131072));assert(#body==f.bytes,"persistent source size changed")
        assert(not a.readlink(target),"RAM source link refused")
        if a.stat(target) then
            assert(a.hash(target)==f.sha1,"foreign or stale RAM source")
        else
            assert(a.write(target,body));assert(a.hash(target)==f.sha1,"RAM source readback changed")
        end
    end
    return true
end
function M:identity()
    local a,m=self.io,self.manifest
    local id,code=a.command({"/sbin/getfirm","DEV_ID"})
    assert(code==0 and trim(id)==m.device_id,"persistent installation on wrong node")
    local model,model_code=a.command({"/sbin/getfirm","MODEL"})
    local hardware,hw_code=a.command({"/sbin/getfirm","HARDVERSION"})
    assert(model_code==0 and trim(model)=="XE75Pro" and hw_code==0 and trim(hardware)=="3.0","unsupported hardware")
    local version=assert(a.read("/fw_data/soft-version",4096))
    assert(version:find("1.5.0 Build 20260603 Rel. 15804",1,true),"unsupported firmware")
    return true
end
function M:install_targets()
    local a,m=self.io,self.manifest
    self:identity()
    local raw=a.read(BASE.."/bindings.json",16384)
    local journal=raw and a.decode(raw) or {schema=1,device_id=m.device_id,install_nonce=m.install_nonce,bindings={}}
    assert(journal.schema==1 and journal.device_id==m.device_id and journal.install_nonce==m.install_nonce
        and type(journal.bindings)=="table","foreign binding journal")
    local mounts=assert(a.read("/proc/self/mountinfo",65536))
    local records={};local tmp
    for line in mounts:gmatch("[^\r\n]+") do
        local fields={};for field in line:gmatch("%S+") do fields[#fields+1]=field end
        if fields[5]=="/tmp" then assert(not tmp,"ambiguous RAM mount");tmp=fields end
        records[fields[5]]=records[fields[5]] or {};table.insert(records[fields[5]],fields)
    end
    assert(tmp,"RAM mount unavailable")
    for _,t in ipairs(TARGETS) do
        local expected=m.targets[t.path];local source=BASE.."/"..t.key
        local existing=records[t.path] or {};local owned=journal.bindings[t.path]
        if #existing>0 then
            assert(#existing==1 and owned and owned.source==source and owned.sha1==expected.patched_sha1
                and existing[1][3]==tmp[3] and existing[1][4]==source:sub(5),"foreign native bind")
            assert(a.hash(t.path)==expected.patched_sha1,"installed native bind bytes changed")
        else
            assert(not owned and not a.readlink(t.path) and a.hash(t.path)==expected.stock_sha1,"native stock target changed")
            local info=assert(a.stat(t.path));assert(info.type=="reg" and info.uid==0 and info.gid==0,"native target ownership")
            if t.stock then
                local original=BASE.."/"..t.stock
                assert(not a.readlink(original),"saved stock source link refused")
                if a.stat(original) then assert(a.hash(original)==expected.stock_sha1,"saved stock UCI differs")
                else assert(a.write(original,assert(a.read(t.path,131072))));assert(a.hash(original)==expected.stock_sha1) end
            end
            -- Preserve native executable/read permission bits on the mounted
            -- inode; in particular network's rc.common entry must remain executable.
            assert(a.chmod(source,info.modestr),"native patch mode changed")
            journal.bindings[t.path]={source=source,sha1=expected.patched_sha1,stock_sha1=expected.stock_sha1,intent=true}
            assert(a.atomic(BASE.."/bindings.json",a.encode(journal)))
            local _,status=a.command({"/bin/busybox","mount","--bind",source,t.path})
            assert(status==0 and a.hash(t.path)==expected.patched_sha1,"native bind installation failed")
            journal.bindings[t.path].intent=false;assert(a.atomic(BASE.."/bindings.json",a.encode(journal)))
        end
    end
    return true
end
function M:verify_targets()
    local a,m=self.io,self.manifest
    for _,target in ipairs(TARGETS) do
        assert(a.hash(target.path)==m.targets[target.path].patched_sha1,"native installed target changed")
    end
    return true
end
function M:remove_targets()
    local a,m=self.io,self.manifest
    local raw=assert(a.read(BASE.."/bindings.json",16384),"binding ownership journal unavailable")
    local journal=a.decode(raw)
    assert(journal.device_id==m.device_id and journal.install_nonce==m.install_nonce,"foreign binding removal")
    for i=#TARGETS,1,-1 do
        local t=TARGETS[i];local owned=journal.bindings[t.path]
        if owned then
            assert(owned.source==BASE.."/"..t.key and owned.sha1==m.targets[t.path].patched_sha1,"foreign binding record")
            local mounts=assert(a.read("/proc/self/mountinfo",65536));local tmp,record
            for line in mounts:gmatch("[^\r\n]+") do
                local f={};for item in line:gmatch("%S+") do f[#f+1]=item end
                if f[5]=="/tmp" then assert(not tmp);tmp=f end
                if f[5]==t.path then assert(not record,"stacked native bind");record=f end
            end
            if record then
                assert(tmp and record[3]==tmp[3] and record[4]==owned.source:sub(5)
                    and a.hash(t.path)==owned.sha1,"binding removal ownership changed")
                local _,status=a.command({"/bin/busybox","umount",t.path})
                assert(status==0,"native own bind removal failed")
            end
            assert(a.hash(t.path)==owned.stock_sha1,"native original not restored")
            journal.bindings[t.path]=nil;assert(a.atomic(BASE.."/bindings.json",a.encode(journal)))
        end
    end
    return true
end
M.FILES=FILES;M.TARGETS=TARGETS;M.BASE=BASE;M.PERSIST=PERSIST
return M
