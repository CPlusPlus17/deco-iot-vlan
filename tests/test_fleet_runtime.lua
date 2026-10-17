package.path = "runtime/?.lua;" .. package.path
-- Own-source-only virtual kernel tests. Never contacts a device.
local f=assert(io.open(arg[1],"rb"))
local runtime=f:read("*a");f:close()
local scenario=assert(arg[2])
local BASE="/tmp/deco-fleet-0123456789abcdef0123456789abcdef"
local NONCE="0123456789abcdef0123456789abcdef"
local clock=1000
local files,dirs,stored={},{["/tmp"]=true},{}
local store_id=0
local current_pid=10
local processes={[10]={name="luci",ppid=1,start=100,state="R"}}
local nextpid=100
local children={}
local interfaces={
 ["br-lan"]={index=18,bridge="main",address="main"},
 ["eth1"]={index=2},["eth1.2"]={index=3,master="br-lan"},
 ["eth1.3"]={index=4,master="br-lan"},["eth1.4"]={index=5,master="br-lan"},
 ["ath0"]={index=6,master="br-lan"},["ath1"]={index=7,master="br-lan"},["ath2"]={index=8,master="br-lan"},
 ["ath08"]={index=9,master="br-lan"},["ath18"]={index=10,master="br-lan"}}
local vlans={[2]="0 6t",[3]="1 6t",[4]="2 6t",[30]="",[500]="6t"}
local pvids={[0]="2",[1]="3",[2]="4",[6]="1"}
local firewall={}
local nextif=1000
local mutations=0
local vap_mutations=0
local attribute_writes=0
local kernel_locks={}
local lock_attempts={}
local killed={}
local plan={device_id=string.rep("A",40),boot_id="01234567-0123-0123-0123-0123456789ab",management_ipv4="192.168.68.1",gateway="192.168.68.254",uplink_bridge_port=5,uplink_vlan_device="eth1.4",tagged_ports="2t 6t",test_client_mac="02:11:22:33:44:55",deadline=1120,old_vlans={["2"]="0 6t",["3"]="1 6t",["4"]="2 6t",["500"]="6t"},old_pvids={["0"]="2",["1"]="3",["2"]="4",["6"]="1"}}
local failed=false
local watchdog_pid
local abort_parent=false
local function copy(t)
 if type(t)~="table" then return t end
 local out={};for k,v in pairs(t) do out[k]=copy(v) end;return out
end
local json={encode=function(t) store_id=store_id+1;local id="json"..store_id;stored[id]=copy(t);return id end,
 decode=function(id) assert(stored[id],"bad virtual JSON");return copy(stored[id]) end}
local function text_stat(pid,p)
 local a={p.state,tostring(p.ppid)}
 for i=3,22 do a[i]="0" end
 a[20]=tostring(p.start)
 return pid.." ("..p.name..") "..table.concat(a," ")
end
local function raw_read(path)
 if path=="/tmp/sync-cached-DEV_ID" then return plan.device_id.."\n" end
 if path=="/proc/sys/kernel/random/boot_id" then return plan.boot_id.."\n" end
 if path=="/etc/config/sysmode" then return "config config 'sysmode'\n option mode 'AP'\n" end
 if path=="/proc/uptime" then return tostring(clock).." 0\n" end
 if path=="/proc/rtk_gsw/phylink" then return scenario=="uplink_linkdown" and "1\n" or "5\n" end
 if path=="/proc/rtk_gsw/linkspeed" then return "port:0 speed:1000\nport:1 speed:0\nport:2 speed:2500\n" end
 if path=="/proc/net/arp" then return "IP address HW type Flags HW address Mask Device\n192.168.68.254 0x1 0x2 aa:bb:cc:dd:ee:ff * br-lan\n" end
 local pid=tonumber(path:match("^/proc/(%d+)/stat$"))
 if pid then return processes[pid] and text_stat(pid,processes[pid]) or nil end
 if path=="/proc/net/vlan/eth1.30" then return interfaces["eth1.30"] and "VID: 30 Device: eth1\n" or nil end
 local name,attr=path:match("^/sys/class/net/([^/]+)/(.+)$")
 if name then
  local i=interfaces[name];if not i then return nil end
  if attr=="ifindex" then return tostring(i.index).."\n" end
  if attr=="bridge/bridge_id" then return i.bridge and i.bridge.."\n" or nil end
  if attr=="master/bridge/bridge_id" then return i.master and interfaces[i.master].bridge.."\n" or nil end
  if attr=="brport/port_no" then return name=="eth1.4" and "0x5\n" or "0x6\n" end
  if attr=="brport/hairpin_mode" then return i.master and "0\n" or nil end
 end
 return files[path]
end
io.open=function(path,mode)
 if mode=="rb" then
  local data=raw_read(path)
  if not data then return nil end
  return {read=function() return data end,close=function() return true end}
 end
 assert(mode=="wb","unexpected mode");files[path]=""
 return {write=function(_,body)
  if path:find("/brport/",1,true) then attribute_writes=attribute_writes+1 end
  if scenario=="owner_partial_write_failure" and path=="/tmp/deco-iot-trial-active/owner" then files[path]=NONCE:sub(1,9);error("partial owner write failed") end
  if scenario=="owner_write_failure" and path=="/tmp/deco-iot-trial-active/owner" then error("owner write failed") end
  if scenario=="foreign_owner_write_failure" and path=="/tmp/deco-iot-trial-active/owner" then files[path]="foreign";error("foreign owner") end
  if scenario=="save_after_bridge" and path==BASE.."/state.next" and interfaces["br-iot"] and not failed then failed=true;error("save failure") end
  if scenario=="save_after_vlan" and path==BASE.."/state.next" and interfaces["eth1.30"] and not failed then failed=true;error("save failure") end
  if scenario=="persistent_save_after_bridge" and path:sub(1,#BASE)==BASE and interfaces["br-iot"] then error("disk full") end
  if scenario=="save_on_vlan_fork" and path==BASE.."/state.next" and not failed then
   for _,child in pairs(children) do
    if child.argv[2]=="vconfig" and child.argv[3]=="add" then failed=true;error("journal failure with live child") end
   end
  end
  files[path]=body;return true
 end,close=function() return true end}
end
os.rename=function(a,b) assert(files[a]);files[b]=files[a];files[a]=nil;return true end
os.remove=function(path) local existed=files[path]~=nil;files[path]=nil;return existed end
local function iterator(values)
 local i=0;return function() i=i+1;return values[i] end
end
local fs={mkdir=function(path) if dirs[path] then return nil end;dirs[path]=true;return true end,
 rmdir=function(path)
  for p in pairs(files) do if p:sub(1,#path+1)==path.."/" then return nil end end
  dirs[path]=nil;return true
 end,
 dir=function(path)
  local values={".",".."}
  if path=="/proc" then for pid in pairs(processes) do values[#values+1]=tostring(pid) end
  elseif path=="/sys/class/net/br-iot/brif" or path=="/sys/class/net/br-lan/brif" then
   local target=path:match("/([^/]+)/brif$")
   for name,i in pairs(interfaces) do if i.master==target then values[#values+1]=name end end
  else error("unexpected directory") end
  return iterator(values)
 end}
fs.stat=function(path) return dirs[path] or files[path] and {} or nil end
local function rulekey(argv)
 local t={argv[1]};for i=3,#argv do t[#t+1]=argv[i] end
 return table.concat(t," ")
end
local function execute(argv)
 if scenario=="manual_live_actor" and killed[77] and argv[1]~="/usr/sbin/ip" then assert(not processes[77] and not processes[78],"undo raced live owned process") end
 if argv[1]=="/sbin/swconfig" then
  assert(argv[2]=="dev" and argv[3]=="switch1")
  if argv[4]=="get" then assert(argv[5]=="enable_vlan");return "1\n",0 end
  if argv[4]=="port" then assert(argv[6]=="get" and argv[7]=="pvid");return pvids[tonumber(argv[5])].."\n",0 end
  assert(argv[4]=="vlan")
  local vid=tonumber(argv[5]);assert(vlans[vid]~=nil)
  if argv[6]=="get" then assert(argv[7]=="ports");return vlans[vid].."\n",0 end
  assert(vid==30 and argv[6]=="set" and argv[7]=="ports" and #argv==8)
  assert(argv[8]=="" or argv[8]=="2t 6t");vlans[30]=argv[8];mutations=mutations+1;return "",0
 end
 if argv[1]=="/usr/sbin/ip" then
  if argv[2]=="addr" then return "inet 192.168.68.1/20\n",0 end
  return "default via 192.168.68.254 dev br-lan\n",0
 end
 if argv[1]=="/usr/sbin/wlanconfig" then
  local header="ADDR AID CHAN TXRATE RXRATE RSSI MINRSSI MAXRSSI IDLE TXSEQ RXSEQ CAPS XCAPS ACAPS ERP STATE MAXRATE(DOT11) HTCAPS VHTCAPS ASSOCTIME IEs MODE RXNSS TXNSS PSMODE\n"
  local mac="02:11:22:33:44:55"
  if scenario=="alien_rejected" or scenario=="alien_after_stage" then mac="02:aa:bb:cc:dd:ee" end
  if scenario=="clients" then return "ADDR HEADER\n",0 end
  local present=(scenario=="alien_after_stage" and files[BASE.."/state.json"]~=nil and argv[2]=="ath18") or scenario=="duplicate_rejected" or ((scenario=="pinned_allowed" or scenario=="alien_rejected") and argv[2]=="ath18")
  if not present then return header,0 end
  return header..mac.." 1 36 1201M 1201M -45 -60 -20 0 0 0 EPS 0 0 0 1 0 0 0 00:01:02 RSN IEEE80211_MODE_11AXA_HE160 2 2 0\n"..
    " LM NR BRP BRA BRT\n RSSI is combined over chains in dBm\n Minimum Tx Power : 0\n Maximum Tx Power : 0\n HT Capability : Yes\n VHT Capability : Yes\n MU capable : No\n SNR : 47\n Operating band : 5GHz\n Current Operating class : 129\n Supported Operating classes : 115 118 121 124 125 128 129 130\n Supported Rates : 12 18 24\n Max STA phymode : IEEE80211_MODE_11AXA_HE160\n",0
 end
 if argv[1]:find("tables",1,true) then
  if argv[2]=="-S" then return "",0 end
  local key=rulekey(argv)
  if argv[2]=="-C" then return "",firewall[key] and 0 or 1 end
  if argv[2]=="-I" then firewall[key]=true elseif argv[2]=="-D" then firewall[key]=nil else error("firewall action") end
  mutations=mutations+1;return "",0
 end
 if argv[1]=="/usr/sbin/brctl" then
  if argv[2]=="showmacs" then
   local shifted=scenario=="shifted_uplink_unconfirmed"
   return "port no mac addr is local ageing timer\n"..(shifted and "13" or "5").." aa:bb:cc:dd:ee:ff no 0.01\n",0
  end
  if argv[2]=="addbr" then assert(not interfaces[argv[3]]);nextif=nextif+1;interfaces[argv[3]]={index=nextif,bridge="private"}
  elseif argv[2]=="delbr" then assert(interfaces[argv[3]]);interfaces[argv[3]]=nil
  elseif argv[2]=="addif" then assert(not interfaces[argv[4]].master);interfaces[argv[4]].master=argv[3]
  elseif argv[2]=="delif" then assert(interfaces[argv[4]].master==argv[3]);interfaces[argv[4]].master=nil
  elseif argv[2]~="setfd" then error("bridge action") end
  mutations=mutations+1
  if argv[4]=="ath08" or argv[4]=="ath18" then vap_mutations=vap_mutations+1 end
  if scenario=="move_second" and argv[2]=="addif" and argv[3]=="br-iot" and argv[4]=="ath18" then return "",1 end
  return "",0
 end
 if argv[1]=="/bin/busybox" then
  if argv[2]=="sleep" then
   if tonumber(argv[3])>1 and scenario=="watchdog_sleep_failure" then return "",1 end
   clock=clock+tonumber(argv[3]);return "",0
  elseif argv[2]=="vconfig" then
   if argv[3]=="add" then nextif=nextif+1;interfaces["eth1.30"]={index=nextif}
   else assert(argv[3]=="rem");interfaces["eth1.30"]=nil end
   mutations=mutations+1;return "",0
  elseif argv[2]=="ifconfig" or argv[2]=="chmod" then return "",0 end
 end
 error("unexpected command "..table.concat(argv," "))
end
local nx={getuid=function() return 0 end,getpid=function() return current_pid end,
 nanosleep=function(_,n) clock=clock+n/1e9 end,
 kill=function(pid,signal)
  assert(pid>1)
  killed[pid]=signal
  if signal==19 then processes[pid].state="T" else processes[pid]=nil;children[pid]=nil;for path,owner in pairs(kernel_locks) do if owner==pid then kernel_locks[path]=nil end end end
  return true
 end,
 waitpid=function(pid,mode)
  local child=children[pid]
  if not child then return pid,"signaled",9 end
  if scenario=="hang_bridge_command" and child.argv[2]=="addbr" and mode=="nohang" then return 0 end
  local _,code=execute(child.argv);children[pid]=nil;processes[pid]=nil
  return pid,"exited",code
 end}
local sp={call_output=execute,call=function(argv) local _,code=execute(argv);return code end,
 exec=function(argv)
  nextpid=nextpid+1;local pid=nextpid
  processes[pid]={name=argv[1]:match("([^/]+)$"),ppid=current_pid,start=clock*100,state="R"}
  if argv[1]=="/usr/bin/lua" then watchdog_pid=pid;files[BASE.."/watchdog-ready"]=tostring(pid);return pid end
  children[pid]={argv=argv};return pid
 end}
-- Vendor nixio__check_mode accepts nine permission characters or octal
-- DIGITS (600), unlike POSIX's decimal bitfield integer (384).
local function native_permissions(value)
 if type(value)=="string" and #value==9 then
  return value:match("^[r-][w-][xsS-][r-][w-][xsS-][r-][w-][xtT-]$")~=nil
 end
 local number=tonumber(value)
 if not number then return false end
 number=number>=0 and math.floor(number) or math.ceil(number)
 local digits={math.floor((number%10000)/1000),math.floor((number%1000)/100),math.floor((number%100)/10),number%10}
 for _,digit in ipairs(digits) do if digit<0 or digit>7 then return false end end
 return true
end
nx.open=function(path,mode,permissions)
 assert(mode=="w" and native_permissions(permissions),"native nixio permission argument invalid")
 if not files[path] then
  if scenario=="persistent_save_after_bridge" and interfaces["br-iot"] then return nil end
  files[path]=""
 end
 lock_attempts[path]=(lock_attempts[path] or 0)+1
 if scenario=="stale_memory_actor" and path==BASE.."/phase-lock" and lock_attempts[path]==2 then
  local state=json.decode(files[BASE.."/state.json"])
  processes[77]={name="luci",ppid=1,start=500,state="R"}
  processes[78]={name="brctl",ppid=77,start=501,state="R"}
  state.actor={pid=77,name="luci",start=500};state.mutation_in_progress=true
  state.active_child={pid=78,name="luci",exec_name="brctl",start=501}
  files[BASE.."/state.json"]=json.encode(state);kernel_locks[path]=77
 end
 local owner=current_pid
 return {lock=function() if kernel_locks[path] and kernel_locks[path]~=owner then return nil end;kernel_locks[path]=owner;return true end,
 close=function() if kernel_locks[path]==owner then kernel_locks[path]=nil end;return true end}
end
if scenario=="native_permissions" then
 assert(not pcall(nx.open,BASE.."/bad-permissions","w",384),"decimal bits accepted as native permissions")
 assert(nx.open(BASE.."/octal-permissions","w",600):close(),"octal digits rejected")
 assert(nx.open(BASE.."/string-permissions","w","rw-------"):close(),"native permission string rejected")
 assert(not files[BASE.."/bad-permissions"],"invalid permissions created a file")
 print("PASS "..scenario);return
end
package.preload["nixio"]=function() return nx end
package.preload["nixio.fs"]=function() return fs end
package.preload["luci.json"]=function() return json end
package.preload["luci.model.subprocess"]=function() return sp end
local function invoke(mode,custom)
 local header="local MODE="..string.format("%q",mode).."\nlocal BASE="..string.format("%q",BASE).."\nlocal NONCE="..string.format("%q",NONCE).."\nlocal PLAN=require('luci.json').decode("..string.format("%q",json.encode(custom or plan))..")\nlocal RUNTIME_SOURCE="..string.format("%q",runtime).."\n"
 return assert(loadstring(header..runtime))()
end
local function clean()
 assert(interfaces["ath08"].master=="br-lan" and interfaces["ath18"].master=="br-lan","VAPs not restored")
 assert(not interfaces["br-iot"] and not interfaces["eth1.30"] and vlans[30]=="","resources remain")
 assert(not next(firewall) and pvids[6]=="1" and pvids[2]=="4","baseline changed")
 assert(not dirs["/tmp/deco-iot-trial-active"],"reservation remains")
 assert(not next(kernel_locks),"live lock leaked")
 for _,child in pairs(children) do assert(not child.argv[1]:find("swconfig",1,true) and child.argv[2]~="addbr" and child.argv[2]~="vconfig","live mutator leaked") end
end
if scenario=="cpu_zero" then pvids[6]="0" end
if scenario=="vlan_used" then vlans[30]="1t 6t" end
if scenario=="sat1_500" then vlans[500]="0t 1t 2t 6t";plan.old_vlans["500"]=vlans[500] end
if scenario=="sat2_guest" then vlans[500]="";plan.old_vlans["500"]="" end
if scenario=="no_state_rollback" then
 local result=invoke("rollback");assert(result.rolled_back and result.private_bridge_removed and result.vlan_device_removed);clean()
else
 local ok,result=pcall(invoke,"stage")
 assert(ok,"stage errored outside bounded phase handler: "..tostring(result))
 local rejected={cpu_zero=true,vlan_used=true,clients=true,alien_rejected=true,duplicate_rejected=true,shifted_uplink_unconfirmed=true,uplink_linkdown=true}
 local stage_failures={save_after_bridge=true,save_after_vlan=true,persistent_save_after_bridge=true,save_on_vlan_fork=true,hang_bridge_command=true,owner_write_failure=true,owner_partial_write_failure=true,foreign_owner_write_failure=true}
 if rejected[scenario] then assert(not result.staged and mutations==0,"preflight mutated dataplane")
 elseif stage_failures[scenario] then
  assert(result.phase=="failed","expected stage failure")
  if scenario=="foreign_owner_write_failure" then assert(not result.rollback.rolled_back and files["/tmp/deco-iot-trial-active/owner"]=="foreign","foreign owner modified")
  else assert(result.rollback.rolled_back,"stage failure not restored");clean() end
 else
  assert(result.phase=="staged" and result.staged and not result.active,"stage failed: "..tostring(result.phase))
  assert(vap_mutations==0 and attribute_writes==0 and interfaces["ath08"].master=="br-lan" and interfaces["ath18"].master=="br-lan","stage moved VAP")
  local initial_deadline=result.deadline
  if scenario=="stage_only" or scenario=="stage_timer" then
   if scenario=="stage_timer" then current_pid=watchdog_pid end
   local back=invoke(scenario=="stage_timer" and "watchdog" or "rollback")
   assert(back.rolled_back and vap_mutations==0 and attribute_writes==0);clean()
   local expected_origin=scenario=="stage_timer" and "watchdog" or "rollback"
   assert(back.rollback_initiated_by==expected_origin,"incorrect cleanup origin")
   local status=invoke("status")
   assert(status.fresh_verified and status.rollback_initiated_by==expected_origin,"cleanup origin/freshness not preserved")
  elseif scenario=="stale_memory_actor" then
   local failure=invoke("activate");assert(failure.phase=="failed" and failure.rollback.rolled_back,"concurrent actor recovery failed")
   assert(killed[77]==9 and killed[78]==9,"actor/exec child not stopped");clean()
  elseif scenario=="status_changed" then
   vlans[30]="";assert(not pcall(invoke,"status"),"stale status accepted");vlans[30]="2t 6t"
   assert(invoke("rollback").rolled_back);clean()
  elseif scenario=="expired_activation" or scenario=="expired_status" or scenario=="near_deadline_activation" then
   clock=plan.deadline+(scenario=="near_deadline_activation" and -29 or 1)
   assert(not pcall(invoke,scenario=="expired_status" and "status" or "activate"),"expired or insufficient phase accepted")
   assert(invoke("rollback").rolled_back);clean()
  elseif scenario=="rollback_busy" then
   processes[88]={name="lua",ppid=1,start=777,state="R"};kernel_locks[BASE.."/rollback-lock"]=88
   local busy=invoke("rollback");assert(busy.busy and not busy.rolled_back and interfaces["br-iot"],"busy rollback changed resources")
   nx.kill(88,9);assert(invoke("rollback").rolled_back);clean()
  elseif scenario=="changed_identity" or scenario=="changed_boot" then
   local changed=copy(plan)
   if scenario=="changed_identity" then changed.device_id=string.rep("B",40) else changed.boot_id="ffffffff-ffff-ffff-ffff-ffffffffffff" end
   assert(not pcall(invoke,"activate",changed),"wrong identity or boot accepted")
   assert(invoke("rollback").rolled_back);clean()
  elseif scenario=="changed_plan" then
   local changed=copy(plan);changed.deadline=changed.deadline+30
   local changed_ok,changed_result=pcall(invoke,"activate",changed)
   assert(not changed_ok or (changed_result.phase=="failed" and not changed_result.active),"extended deadline accepted")
   assert(invoke("rollback").rolled_back);clean()
  else
   current_pid=20;processes[20]={name="luci",ppid=1,start=500,state="R"}
   local active=invoke("activate")
   if scenario=="move_second" or scenario=="alien_after_stage" then assert(active.phase=="failed" and active.rollback.rolled_back,"partial move not restored");clean()
   else
    assert(active.phase=="active" and active.active and active.deadline==initial_deadline,"activation failed or extended deadline")
    assert(interfaces["ath08"].master=="br-iot" and interfaces["ath18"].master=="br-iot")
    if scenario=="manual_live_actor" or scenario=="child_exec_dead_actor" or scenario=="child_pid_reused" or scenario=="watchdog_live_actor" then
     local state=json.decode(files[BASE.."/state.json"])
     state.actor={pid=77,name="luci",start=500};state.mutation_in_progress=true
     state.active_child={pid=78,name="luci",exec_name="brctl",start=501}
     if scenario=="manual_live_actor" or scenario=="watchdog_live_actor" then processes[77]={name="luci",ppid=1,start=500,state="R"} end
     processes[78]={name="brctl",ppid=(scenario=="manual_live_actor" or scenario=="watchdog_live_actor") and 77 or 1,start=scenario=="child_pid_reused" and 999 or 501,state="R"}
     files[BASE.."/state.json"]=json.encode(state)
     if scenario=="watchdog_live_actor" then current_pid=watchdog_pid;kernel_locks[BASE.."/phase-lock"]=77 end
     local back=invoke(scenario=="watchdog_live_actor" and "watchdog" or "rollback");assert(back.rolled_back,"manual recovery failed")
     if scenario=="child_pid_reused" then assert(not killed[78],"reused PID killed") else assert(killed[78]==9,"exec child not stopped") end
     if scenario=="manual_live_actor" or scenario=="watchdog_live_actor" then assert(killed[77]==9,"live actor not stopped") end
    else
     if scenario=="stale_rollback_lock" then files[BASE.."/rollback-lock"]="corrupt legacy contents";kernel_locks[BASE.."/rollback-lock"]=nil end
     current_pid=watchdog_pid
     assert(invoke("watchdog").rolled_back,"watchdog recovery failed")
    end
    clean()
    if scenario=="done_changed" then
     interfaces["br-iot"]={index=9000,bridge="alien"};assert(not pcall(invoke,"status"),"historical done accepted changed resources")
    else assert(invoke("status").rolled_back,"fresh done not verified") end
   end
  end
 end
end
print("PASS "..scenario)
