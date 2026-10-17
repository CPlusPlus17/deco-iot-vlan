package.path = "runtime/?.lua;" .. package.path
-- Own task source with virtual files/processes and fixed argv. No device operations.
local source=assert(loadfile("runtime/offer_probe.lua"))
local case=arg[1] or "success"
PLAN={device_id=string.rep("A",40),boot_id="11111111-2222-4333-8444-555555555555",
 deadline=200,tagged_ports="2t 6t"}
NONCE=string.rep("b",32)
PROBE_NONCE=string.rep("c",32)
BASE="/tmp/deco-iot-trial-"..NONCE
local state={nonce=NONCE,phase="staged",deadline=PLAN.deadline}
local clock=100
local files={
 ["/tmp/sync-cached-DEV_ID"]=PLAN.device_id.."\n",
 ["/proc/sys/kernel/random/boot_id"]=PLAN.boot_id.."\n",
 [BASE.."/state.json"]="virtual-state",
 ["/tmp/deco-iot-trial-active/owner"]=NONCE,
 ["/sys/class/net/br-lan/bridge/bridge_id"]="own-main-bridge\n",
 ["/sys/class/net/ath08/master/bridge/bridge_id"]="own-main-bridge\n",
 ["/sys/class/net/ath18/master/bridge/bridge_id"]="own-main-bridge\n",
 ["/sys/class/net/br-iot/bridge/bridge_id"]="own-private-bridge\n",
 ["/sys/class/net/eth1.30/master/bridge/bridge_id"]="own-private-bridge\n"}
local exists={}
if case=="wrong_device" then files["/tmp/sync-cached-DEV_ID"]=string.rep("D",40) end
if case=="wrong_boot" then files["/proc/sys/kernel/random/boot_id"]="22222222-2222-4333-8444-555555555555\n" end
if case=="wrong_phase" then state.phase="activated" end
if case=="wrong_nonce" then state.nonce=string.rep("d",32) end
if case=="wrong_reservation" then files["/tmp/deco-iot-trial-active/owner"]=string.rep("d",32) end
if case=="wrong_deadline" then state.deadline=201 end
if case=="insufficient_time" then clock=171 end
if case=="abort" then exists[BASE.."/abort"]=true end
if case=="done" then exists[BASE.."/done.json"]=true end
if case=="vap_moved" then files["/sys/class/net/ath18/master/bridge/bridge_id"]="other-bridge\n" end
if case=="vlan_master_changed" then files["/sys/class/net/eth1.30/master/bridge/bridge_id"]="other-bridge\n" end
if case=="bad_probe_nonce" then PROBE_NONCE="../unbounded" end
local pidpath=BASE.."/offer-"..PROBE_NONCE..".pid"
local logpath=BASE.."/offer-"..PROBE_NONCE..".log"
if case=="existing_pidpath" then exists[pidpath]=true end
if case=="existing_logpath" then exists[logpath]=true;files[logpath]="foreign log" end
local clock_start=clock
local before={}
for path,body in pairs(files) do before[path]=body end
local probe_calls,getters,forks,kills,waits,execs=0,0,0,0,0,0
local child_live,child_reaped=false,false
local private_mode,logfd,nullfd,exited=false,nil,nil,false
local dups={}
local route="default via 192.168.68.254 dev br-lan\n"
local main="18: br-lan: <UP>\n    inet 192.168.68.1/20 scope global br-lan\n"
local private="41: br-iot: <UP>\n"
if case=="private_ipv4" then private=private.."    inet 10.0.30.99/24 scope global br-iot\n" end
if case=="private_ipv6" then private=private.."    inet6 fe80::1/64 scope link\n" end
local expected={"/bin/busybox","timeout","-t","8","-s","KILL",
 "/bin/busybox","udhcpc","-f","-n","-Q","-m","normal","-i","br-iot",
 "-s","/bin/true","-p",pidpath,"-t","10","-T","2"}
local function fixed_argv(argv)
 assert(#argv==#expected,"unbounded DHCP vector")
 for i,value in ipairs(expected) do assert(argv[i]==value,"changed fixed DHCP argument") end
end
local stdout="rcv dhcp pkts saddr is 18743306 \n"
local stderr="udhcpc: udhcpc (v1.22.1) started\nudhcpc: Sending discover...\n"..
 "udhcpc: get dhcp server info failed or file is empty!\nudhcpc: DHCP offer received, exit\n"
local function client_finish()
 if case=="route_changed" then route="default via 192.168.68.253 dev br-lan\n" end
 if case=="private_address_changed" then private=private.."    inet 10.0.30.99/24 scope global br-iot\n" end
 files[logpath]=stdout..stderr
 if case=="truncated_log" then files[logpath]=files[logpath]..string.rep("x",2049) end
end
io.open=function(path,mode)
 assert(mode=="rb","offer task attempted a file write")
 local body=files[path]
 if path=="/proc/uptime" then body=tostring(clock).." 0\n" end
 if path=="/proc/123/stat" then
  if case=="missing_identity" then return nil end
  local fields={"S"};for i=2,19 do fields[i]="0" end
  fields[20]=(case=="pid_reused" and waits>0) and "501" or "500"
  -- A legitimate exec changes comm while preserving PID and start ticks.
  body="123 ("..(waits>0 and "udhcpc" or "luajit")..") "..table.concat(fields," ").."\n"
 end
 if not body then return nil end
 return {read=function(_,kind)
  if kind=="*a" then return body end
  assert(type(kind)=="number" and kind==2049,"log read was not bounded")
  return body:sub(1,kind)
 end,close=function() return true end}
end
local function getter(argv)
 assert(argv[1]~="/bin/busybox","client went through stdout-only subprocess")
 getters=getters+1
 if argv[1]=="/usr/sbin/ip" then
  if argv[2]=="route" then assert(#argv==3 and argv[3]=="show");return route,0 end
  assert(#argv==5 and argv[2]=="addr" and argv[3]=="show" and argv[4]=="dev")
  if argv[5]=="br-lan" then return main,0 end
  assert(argv[5]=="br-iot");return private,0
 end
 assert(table.concat(argv," ")=="/sbin/swconfig dev switch1 vlan 30 get ports","non-read switch command")
 return case=="wrong_tagged_ports" and "0t 6t\n" or "2t 6t\n",0
end
local nx={stdin="stdin",stdout="stdout",stderr="stderr"}
nx.getuid=function() return case=="not_root" and 1000 or 0 end
nx.open=function(...)
 local args={...};assert(#args==2,"native nixio open received a permission argument")
 local path,mode=args[1],args[2]
 if path=="/dev/null" then
  assert(mode=="r")
  if case=="child_setup_failure" then return nil end
  nullfd={closed=false,close=function(self) self.closed=true;return true end};return nullfd
 end
 assert(path==logpath and mode=="w","unexpected writable path")
 if case=="log_open_failure" then return nil end
 assert(not exists[path],"foreign log overwritten")
 exists[path]=true;files[path]=""
 logfd={closed=false,close_calls=0,close=function(self)
  self.close_calls=self.close_calls+1
  if case=="parent_close_failure" and self.close_calls==1 then return nil end
  self.closed=true;return true
 end}
 return logfd
end
nx.fork=function()
 assert(getters==4 and private_mode,"fork before snapshot or private log permission")
 forks=forks+1;assert(forks==1,"probe retried")
 if case=="fork_failure" then return nil end
 if case=="child_stderr_merge" or case=="child_setup_failure" then return 0 end
 probe_calls=probe_calls+1;child_live=true;return 123
end
nx.dup=function(from,to)
 assert(to==nx.stdin or to==nx.stdout or to==nx.stderr)
 dups[to]=from;return true
end
nx.execp=function(...)
 execs=execs+1;fixed_argv({...})
 assert(dups.stdin==nullfd and dups.stdout==logfd and dups.stderr==logfd,"stdout/stderr were not merged")
 assert(logfd.closed and nullfd.closed,"child original descriptors not closed")
 -- Duplicated descriptors retain the file despite closing the original handle.
 files[logpath]=stdout..stderr
 return nil
end
nx.waitpid=function(pid,flag)
 assert(pid==123 and flag=="nohang","unbounded wait or wrong PID")
 waits=waits+1
 if case=="wait_failure" and waits==1 then error("virtual wait failure") end
 if case=="pid_reused" or case=="cleanup_timeout" then return nil end
 if case=="outer_timeout" then
  if kills==0 then return nil end
  child_live=false;child_reaped=true;return 123,"signaled",9
 end
 if case=="missing_identity" or case=="timeout" then
  if clock<108 then return nil end
  child_live=false;child_reaped=true;files[logpath]="udhcpc: Sending discover...\n"
  return 123,"signaled",9
 end
 child_live=false;child_reaped=true
 if kills>0 then return 123,"signaled",9 end
 client_finish();return 123,"exited",0
end
nx.nanosleep=function(seconds,nanoseconds)
 assert(seconds==0 and nanoseconds>=0 and nanoseconds<=50000000,"unbounded sleep")
 clock=clock+math.max(nanoseconds/1000000000,0.000001)
 assert(clock<=clock_start+10.0001,"cleanup exceeded ten-second budget")
 return true
end
nx.kill=function(pid,signal)
 assert(pid==123 and signal==9,"wrong cleanup target/signal")
 assert(case~="missing_identity" and case~="pid_reused","unproved child identity was signaled")
 kills=kills+1;return true
end
local modules={nixio=nx,
 ["nixio.fs"]={
  stat=function(path) return exists[path] and {type="reg"} or nil end,
  chmod=function(path,mode)
   assert(path==logpath and mode=="rw-------" and logfd,"log permission not native symbolic mode")
   if case=="permission_failure" then return nil end
   private_mode=true;return true
  end},
 ["luci.model.subprocess"]={call_output=getter},
 ["luci.json"]={decode=function(value) assert(value=="virtual-state");return state end}}
require=function(name) return assert(modules[name],"unexpected dependency") end
os.exit=function(code)
 assert(code==127,"child setup failed with unexpected exit")
 exited=true;if logfd then logfd.closed=true end;if nullfd then nullfd.closed=true end
 error("virtual child exit")
end
local ok,result=pcall(source)
local runs=case=="success" or case=="timeout" or case=="route_changed"
 or case=="private_address_changed" or case=="truncated_log" or case=="outer_timeout"
local attempted=runs or case=="parent_close_failure" or case=="wait_failure"
 or case=="missing_identity" or case=="pid_reused" or case=="cleanup_timeout"
local childcase=case=="child_stderr_merge" or case=="child_setup_failure"
assert(ok==runs,"unexpected acceptance: "..case.." "..tostring(result))
assert(probe_calls==(attempted and 1 or 0),"probe ran after refused input")
for path,body in pairs(before) do assert(files[path]==body,"task modified state/baseline file") end
assert(clock<=clock_start+10.0001,"cleanup exceeded ten-second budget")
if logfd then assert(logfd.closed,"parent leaked log descriptor") end
if attempted and case~="cleanup_timeout" and case~="pid_reused" then
 assert(child_reaped and not child_live,"owned child was not reaped")
end
if case=="parent_close_failure" or case=="wait_failure" or case=="outer_timeout" then
 assert(kills>=1,"parent failure/outer timeout did not stop owned child")
end
if case=="permission_failure" or case=="log_open_failure" then assert(forks==0,"fork after log setup failure") end
if case=="missing_identity" or case=="pid_reused" then assert(kills==0,"unknown/reused PID was killed") end
if case=="child_stderr_merge" then
 assert(exited and execs==1 and files[logpath]:find("DHCP offer received, exit",1,true),"child lost stderr OFFER marker")
end
if case=="child_setup_failure" then assert(exited and execs==0,"failed child setup reached exec") end
if runs then
 assert(result.kind=="deco_fleet_offer_probe" and result.uid==0)
 assert(result.offer_only and not result.lease_requested and not result.pcap_collected)
 assert(result.nonce==NONCE and result.probe_nonce==PROBE_NONCE)
 assert(result.device_id==PLAN.device_id and result.boot_id==PLAN.boot_id)
 assert(math.abs(result.remaining_seconds-(200-clock))<0.00001)
 assert(result.client_exit_code==((case=="timeout" or case=="outer_timeout") and 137 or 0))
 assert(result.interface_addresses_routes_unchanged~=(case=="route_changed" or case=="private_address_changed"))
 assert(result.client_log_truncated==(case=="truncated_log"))
 assert(#result.client_log<=2048)
 if case~="timeout" and case~="outer_timeout" then
  assert(result.client_log:find(stdout,1,true) and result.client_log:find("DHCP offer received, exit",1,true),"stderr missing")
 end
end
print('{"case":"'..case..'","passed":true,"probe_ran":'..tostring(attempted or childcase)..',"device_contact":false}')
