-- Own native process adapter. Unlike the vendor call_output pump, EOF alone
-- never means success. Only a definitive waitpid result supplies exit status.
-- Callers provide reviewed fixed argv; no user-facing command interface.
local M={}
local MESSAGES={
 ['owned command context required']=true,['bounded native read failed']=true,
 ['inherited command session invalid']=true,['inherited command session changed']=true,
 ['command session identity changed']=true,['process scan bound']=true,
 ['nested command group kill failed']=true,['command group freeze failed']=true,
 ['command group kill failed']=true,['command descendants remain alive']=true,
 ['fixed argv invalid']=true,['argv field invalid']=true,['absolute fixed executable required']=true,
 ['private command directory missing']=true,['private command directory invalid']=true,
 ['exclusive command output failed']=true,['child gate pipe failed']=true,['owned child wait failed']=true,
 ['command fork failed']=true,['owned command session create failed']=true,['command session marker failed']=true,
 ['child gate revoked']=true,['child identity unavailable']=true,['child did not wait for parent gate']=true,
 ['child session setup timeout']=true,['child escaped owned command group']=true,['child gate release failed']=true,
 ['owned command session stop failed']=true,['owned child did not terminate']=true,
 ['fixed command left background descendants']=true,['command output replaced']=true,
 ['command status/output unavailable']=true,['unknown child completion']=true,['invalid child exit status']=true}
local COMMANDS={
 {'native_iot_zero',{'/sbin/uci','-q','get','iot_wifi.iot.enable'}},
 {'switch_enabled',{'/sbin/swconfig','dev','switch1','get','enable_vlan'}},
 {'pvid_2',{'/sbin/swconfig','dev','switch1','port','2','get','pvid'}},
 {'pvid_6',{'/sbin/swconfig','dev','switch1','port','6','get','pvid'}},
 {'gateway_ping',{'/bin/busybox','ping','-c','1','-W','1','@GATEWAY_IPV4@'}},
 {'gateway_fdb',{'/usr/sbin/brctl','showmacs','br-lan'}},
 {'main_addresses',{'/usr/sbin/ip','addr','show','dev','br-lan'}},
 {'default_routes',{'/usr/sbin/ip','route','show','default'}},
 {'vlan_2',{'/sbin/swconfig','dev','switch1','vlan','2','get','ports'}},
 {'vlan_3',{'/sbin/swconfig','dev','switch1','vlan','3','get','ports'}},
 {'vlan_4',{'/sbin/swconfig','dev','switch1','vlan','4','get','ports'}},
 {'vlan_591',{'/sbin/swconfig','dev','switch1','vlan','591','get','ports'}},
 {'pvid_0',{'/sbin/swconfig','dev','switch1','port','0','get','pvid'}},
 {'pvid_1',{'/sbin/swconfig','dev','switch1','port','1','get','pvid'}}}
local STAGES={validation=true,directory=true,inherited_session=true,capture=true,pipe=true,
 fork=true,detach=true,gate=true,wait=true,descendants=true,output_identity=true,output_read=true,completion=true}
local IDS={other_reviewed_command=true}
for _,row in ipairs(COMMANDS)do IDS[row[1]]=true end
local CODES={unclassified_error=true,own_assertion_failed=true,ok=true,not_checked=true}
for message in pairs(MESSAGES)do CODES[message:gsub('[^a-z0-9]','_')]=true end
function M.command_id(args)
 if type(args)~='table'then return'other_reviewed_command'end
 for _,item in ipairs(COMMANDS)do
  local wanted=item[2];local same=#args==#wanted
  if same then for n,value in ipairs(wanted)do if args[n]~=value then same=false;break end end end
  if same then return item[1]end
 end
 return'other_reviewed_command'
end
function M.error_code(value)
 if type(value)~='string'or #value>2048 then return'unclassified_error'end
 local text=value
 for _=1,4 do
  local source,line,rest=text:match('^/tmp/deco%-iot%-managed/([a-z_]+)%.lua:(%d+): (.*)$')
  if not source then break end
  local n=tonumber(line)
  if source~='bounded_command'or #line>5 or not n or n<1 or n>10000 or tostring(n)~=line then return'unclassified_error'end
  text=rest
 end
 if MESSAGES[text]then return text:gsub('[^a-z0-9]','_')end
 return text=='assertion failed!'and'own_assertion_failed'or'unclassified_error'
end
function M.failure_message(diag,why)
 local id=IDS[diag.id]and diag.id or'other_reviewed_command'
 local stage=STAGES[diag.primary_stage or diag.stage]and(diag.primary_stage or diag.stage)or'completion'
 local cause=diag.cause or M.error_code(why);if not CODES[cause]then cause='unclassified_error'end
 local output=diag.output or'not_checked';if not CODES[output]then output='unclassified_error'end
 local seq=type(diag.sequence)=='number'and diag.sequence==math.floor(diag.sequence)and diag.sequence>=1 and diag.sequence<=65535 and tostring(diag.sequence)or'1'
 local marker=diag.marker==true and'1'or diag.marker==false and'0'or'u'
 return'bounded_diag|'..id..'|'..stage..'|'..cause..'|'..output..'|'..seq..'|'..marker
end
function M.new(options)
    assert(type(options)=='table' and type(options.nonce)=='string' and #options.nonce==32 and options.nonce:match('^[%x]+$')
        and (options.base=='/tmp/deco-iot-managed' or options.base=='/tmp/deco-command-probe-'..options.nonce),'owned command context required')
    local nx,fs=options.nx or require('nixio'),options.fs or require('nixio.fs')
    local sequence=0
    local diagnostic
    local function stage(value)if diagnostic then diagnostic.stage=value end end
    local function read(path,limit)
        local f=io.open(path,'rb');if not f then return nil end
        local body,why=f:read(limit+1);local ok=f:close()
        if body==nil and why==nil then body='' end
        assert(ok and type(body)=='string' and #body<=limit,'bounded native read failed');return body
    end
    local function clock() return assert(tonumber((read('/proc/uptime',128) or ''):match('^[%d.]+'))) end
    local function read_process(pid)
        local f,_,open_errno=io.open('/proc/'..pid..'/stat','rb')
        if not f then
            assert(open_errno==2 or open_errno==3,'bounded native read failed')
            return nil
        end
        local ok,body,why,read_errno=pcall(f.read,f,4097)
        local closed=f:close()
        assert(ok and closed,'bounded native read failed')
        if body==nil and read_errno==3 then return nil end
        if body==nil and why==nil then body='' end
        assert(type(body)=='string' and #body<=4096,'bounded native read failed');return body
    end
    local function process(pid)
        local body=read_process(pid)
        local rest=body and body:match('^%d+ %(.+%) (.*)$');if not rest then return nil end
        local fields={};for v in rest:gmatch('%S+') do fields[#fields+1]=v end
        return {pid=pid,start=tonumber(fields[20]),state=fields[1],group=tonumber(fields[3]),session=tonumber(fields[4])}
    end
    local function same_inode(a,b) return a and b and a.dev==b.dev and a.ino==b.ino and a.uid==b.uid and a.gid==b.gid end
    local function inherited_session()
        local marker=nx.getenv('DECO_IOT_OWN_COMMAND_SESSION')
        if diagnostic then diagnostic.marker=marker~=nil end
        if marker==nil then return nil end
        local pid,start,nonce=marker:match('^(%d+):(%d+):(%x+)$');pid,start=tonumber(pid),tonumber(start)
        assert(pid and pid>1 and start and nonce and #nonce==32,'inherited command session invalid')
        local here,leader=process(nx.getpid()),process(pid)
        assert(here and here.group==pid and here.session==pid and leader and leader.start==start
            and leader.group==pid and leader.session==pid,'inherited command session changed')
        return {pid=pid,start=start}
    end
    local function live_members(group)
        local leader=process(group.pid)
        assert(not leader or leader.start==group.start,'command session identity changed')
        local members={};local count=0
        for name in fs.dir('/proc') do if name:match('^%d+$') then
            count=count+1;assert(count<=512,'process scan bound')
            local p=process(tonumber(name))
            if p and p.group==group.pid and p.session==group.pid and p.state~='Z' then members[#members+1]=p end
        end end
        return members
    end
    local function stop_session(group)
        if #live_members(group)==0 then return true end
        local here=process(nx.getpid())
        if here and here.group==group.pid then
            -- A nested readiness query belongs to its outer helper's group.
            -- Killing that whole group also terminates this nested parent;
            -- the outer adapter, outside the group, reaps and verifies it.
            assert(nx.kill(-group.pid,9),'nested command group kill failed')
            os.exit(127)
        end
        assert(nx.kill(-group.pid,19),'command group freeze failed')
        assert(nx.kill(-group.pid,9),'command group kill failed')
        local until_time=clock()+1
        repeat
            if #live_members(group)==0 then return true end
            assert(clock()<until_time,'command descendants remain alive')
            nx.nanosleep(0,20000000)
        until false
    end
    local adapter={}
    function adapter:command(args)
        stage('validation')
        assert(nx.getuid()==0 and type(args)=='table' and #args>=1 and #args<=32,'fixed argv invalid')
        for _,arg in ipairs(args) do assert(type(arg)=='string' and #arg<=256 and not arg:find('%z'),'argv field invalid') end
        assert(args[1]:sub(1,1)=='/','absolute fixed executable required')
        stage('directory')
        local directory=assert(fs.stat(options.base),'private command directory missing')
        assert(directory.type=='dir' and directory.uid==0 and directory.gid==0
            and directory.modestr=='rwx------','private command directory invalid')
        stage('inherited_session')
        local inherited=inherited_session()
        sequence=sequence+1
        if diagnostic then diagnostic.sequence=sequence end
        local path=options.base..'/command-'..options.nonce..'-'..nx.getpid()..'-'..sequence..'.out'
        stage('capture')
        local file=assert(nx.open(path,nx.open_flags('wronly','creat','excl'),'rw-------'),'exclusive command output failed')
        stage('pipe')
        local owned=assert(file:stat());local rd,wr=nx.pipe()
        if not rd then file:close();os.remove(path);error('child gate pipe failed') end
        local pid,child,observed,group
        local deadline=clock()+4
        local function reap(until_time)
            repeat
                local got,reason,code=nx.waitpid(pid,'nohang')
                if got and got>0 then assert(got==pid);observed={reason=reason,code=code};return true end
                assert(got~=nil,'owned child wait failed')
                if clock()>=until_time then return false end
                nx.nanosleep(0,20000000)
            until false
        end
        local ok,why=pcall(function()
            stage('fork')
            pid=assert(nx.fork(),'command fork failed')
            if pid==0 then
                pcall(function()
                    wr:close()
                    if not inherited then
                        assert(nx.setsid()==nx.getpid(),'owned command session create failed')
                        local own=assert(process(nx.getpid()))
                        assert(nx.setenv('DECO_IOT_OWN_COMMAND_SESSION',own.pid..':'..own.start..':'..options.nonce),'command session marker failed')
                    end
                    -- The child cannot execute a mutation before the parent
                    -- has recorded this exact child's /proc start time.
                    local gate=rd:read(1);rd:close();assert(gate=='G','child gate revoked')
                    local null=assert(nx.open('/dev/null','r'))
                    assert(nx.dup(null,nx.stdin));assert(nx.dup(file,nx.stdout));assert(nx.dup(file,nx.stderr))
                    null:close();file:close();nx.execp(unpack(args))
                end)
                os.exit(127)
            end
            rd:close();rd=nil
            stage('detach')
            repeat
                child=assert(process(pid),'child identity unavailable')
                assert(child.start and child.state~='Z','child did not wait for parent gate')
                if inherited or child.group==pid and child.session==pid then break end
                assert(clock()<deadline,'child session setup timeout');nx.nanosleep(0,20000000)
            until false
            group=inherited or {pid=pid,start=child.start}
            assert(child.group==group.pid and child.session==group.pid,'child escaped owned command group')
            stage('gate')
            assert(wr:write('G')==1,'child gate release failed');wr:close();wr=nil
            assert(file:close());file=nil
            stage('wait')
            if not reap(deadline) then
                assert(stop_session(group),'owned command session stop failed')
                assert(reap(clock()+1),'owned child did not terminate')
            end
            stage('descendants')
            if not inherited and #live_members(group)>0 then
                assert(stop_session(group));error('fixed command left background descendants')
            end
        end)
        if not ok and diagnostic then diagnostic.primary_stage=diagnostic.stage;diagnostic.cause=M.error_code(why)end
        if wr then pcall(wr.close,wr);wr=nil end
        if rd then pcall(rd.close,rd);rd=nil end
        if file then pcall(file.close,file);file=nil end
        if pid and pid>0 and not observed then
            -- Without a released gate, EOF prevents exec. After release, only
            -- a still matching child may be terminated by cleanup.
            local current=process(pid)
            if group then pcall(stop_session,group)
            elseif child and current and current.start==child.start then nx.kill(pid,9) end
            pcall(reap,clock()+1)
        end
        local output_ok,body=pcall(function()
            if diagnostic then diagnostic.output_stage='output_identity'end
            assert(same_inode(fs.stat(path),owned),'command output replaced')
            if diagnostic then diagnostic.output_stage='output_read'end
            return assert(read(path,32768))
        end)
        if diagnostic then
            diagnostic.output=output_ok and'ok'or M.error_code(body)
            if not output_ok and not diagnostic.primary_stage then
                diagnostic.primary_stage=diagnostic.output_stage;diagnostic.cause=M.error_code(body)
            end
        end
        if same_inode(fs.stat(path),owned) then os.remove(path) end
        assert(ok and observed and output_ok,why or 'command status/output unavailable')
        stage('completion')
        local status
        if observed.reason=='exited' then status=observed.code
        elseif observed.reason=='signaled' then status=128+observed.code
        else error('unknown child completion') end
        assert(type(status)=='number' and status>=0 and status<=255,'invalid child exit status')
        return body,status
    end
    local original=adapter.command
    function adapter:command(args)
        local record={id=M.command_id(args),stage='validation',sequence=sequence+1};diagnostic=record
        local ok,body,status=pcall(original,self,args);diagnostic=nil
        if not ok then error(M.failure_message(record,body))end
        return body,status
    end
    return adapter
end
return M
