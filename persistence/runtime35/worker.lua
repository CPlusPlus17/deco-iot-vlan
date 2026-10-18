-- Own local lifecycle entry. No shell, source, file or node is accepted as input.
local M={}
local BASE="/tmp/deco-iot-managed"
local function trim(s) return s and s:match("^%s*(.-)%s*$") end
local function read(path,limit)
    local f=io.open(path,"rb");if not f then return nil end
    local body=f:read(limit+1);local closed=f:close()
    assert(closed and type(body)=="string" and #body<=limit,"bounded worker read")
    return body
end
local function write(path,body)
    local nx=require("nixio")
    local nonce=trim(assert(read("/proc/sys/kernel/random/uuid",128))):gsub("%-","")
    assert(#nonce==32 and not nonce:find("[^0-9a-f]"),"worker write nonce unavailable")
    local next_path=path..".next-"..nonce
    local f=assert(nx.open(next_path,nx.open_flags("wronly","creat","excl"),"rw-------"))
    local done=0
    while done<#body do local n=assert(f:write(body,done));assert(n>0 and n<=#body-done);done=done+n end
    assert(f:sync());assert(f:close());assert(read(next_path,#body)==body,"worker exact temporary write failed")
    assert(os.rename(next_path,path));return true
end
function M.reconcile(activation_lease)
    local nx,json=require("nixio"),require("luci.json")
    local policy_module=assert(loadfile(BASE.."/declarative_policy.lua"))()
    local events=assert(loadfile(BASE.."/event_state.lua"))()
    local quiesce=assert(loadfile(BASE.."/native_quiesce.lua"))()
    local result={schema=1,kind="deco_iot_managed_runtime",completed=false,ready=false,active=false,
        fail_closed=false,held=false,fail_closed_policy=true,boot_persistence_verified=false}
    local platform,lifecycle,context,manifest,policy,first_cold
    local kernel=assert(loadfile(BASE..'/kernel_platform.lua'))()
    local OPERATION_IDS={clear_ready=true,hold_iot_down=true,verify_own_installation=true,
        install_native_writer_guard=true,install_generator_guard=true,protect_network_cleanup=true,
        protect_guest_cleanup=true,wait_native_firewall_finished=true,verify_main_and_switch_baseline=true,
        ensure_owned_private_bridge=true,ensure_owned_vlan30_device=true,ensure_owned_tagged_p2_cpu6=true,
        ensure_owned_firewall_rules=true,register_owned_iot_network=true,verify_private_path=true,
        publish_ready=true,regenerate_iot_vaps_only=true,verify_iot_vaps_private=true,verify_main_unchanged=true}
    local COMMAND_IDS={scoped_vap_ath08=true,scoped_vap_ath18=true,vap_up_ath08=true,vap_up_ath18=true,
        other_reviewed_command=true,native_iot_zero=true,switch_enabled=true,pvid_2=true,pvid_6=true,
        gateway_ping=true,gateway_fdb=true,main_addresses=true,default_routes=true,vlan_2=true,vlan_3=true,
        vlan_4=true,vlan_591=true,pvid_0=true,pvid_1=true}
    local function retain_failure(performed)
        if type(performed)=='table' and performed.completed==false then
            local diagnostic={schema=1,error='fixed_lifecycle_operation_failed',operations={}}
            diagnostic.private_reason=lifecycle.sanitize_error(performed.private_reason)
            diagnostic.failed_operation=OPERATION_IDS[performed.failed_operation] and performed.failed_operation or 'unknown_operation'
            if type(performed.operations)=='table' then
                for _,id in ipairs(performed.operations) do
                    if #diagnostic.operations>=32 then break end
                    if type(id)=='string' and OPERATION_IDS[id] then diagnostic.operations[#diagnostic.operations+1]=id end
                end
            end
            result.lifecycle_failure=diagnostic
        end
        local failure=platform and platform.command_failure
        if type(failure)=='table' and failure.schema==1 and COMMAND_IDS[failure.command_id]
            and type(failure.exit_status)=='number' and failure.exit_status==math.floor(failure.exit_status)
            and failure.exit_status>=1 and failure.exit_status<=255 then
            result.command_failure={schema=1,command_id=failure.command_id,exit_status=failure.exit_status}
        end
    end
    local function lease_guard()
        local fs=require('nixio.fs');local path=BASE..'/activation-lease.json';local st,code=fs.stat(path);local link,lcode=fs.readlink(path)
        if not st then assert(code==2 and link==nil and lcode==2,'activation lease absence unknown');assert(activation_lease==nil,'activation lease revoked');return end
        assert(activation_lease~=nil and link==nil and st.type=='reg' and st.uid==0 and st.gid==0 and st.nlink==1
            and st.modestr=='rw-------' and st.size<=2048,'activation lease requires its own worker')
        local current=json.decode(assert(read(path,2048)));local now=assert(tonumber(trim(read('/proc/uptime',128)):match('^[%d.]+')))
        assert(kernel.lease_matches(current,activation_lease,now),'activation lease revoked or superseded')
        local raw=assert(read('/proc/self/stat',4096));local tail=assert(raw:match('^%d+ %b() (.+)$'));local fields={};for word in tail:gmatch('%S+')do fields[#fields+1]=word end
        assert(activation_lease.pid==nx.getpid() and activation_lease.start==fields[20]
            and trim(read('/tmp/sync-cached-DEV_ID',128))==activation_lease.device_id
            and trim(read('/proc/sys/kernel/random/boot_id',128))==activation_lease.boot_id,'activation lease actor changed')
        local m=json.decode(assert(read(BASE..'/installation.json',32768)));local c=require('uci').cursor()
        local fresh=policy_module.read(c:get_all('deco_iot_vlan','iot'))
        assert(fresh.valid==true and fresh.generation==activation_lease.generation and fresh.enabled==activation_lease.enabled
            and c:get('iot_wifi','iot','enable')=='0' and m.device_id==activation_lease.device_id and m.boot_id==activation_lease.boot_id
            and m.install_nonce==activation_lease.install_nonce and m.generation==activation_lease.generation
            and m.committed==true and m.native_iot_saved_disabled==true,'activation policy superseded before worker')
        if fresh.enabled then assert(assert(loadfile(BASE..'/managed_control.lua'))().verify_attestation(m,fresh)==true,'activation attestation revoked')end
    end
    local function generation_owned()
        local ok,owned=pcall(function()
            local expected=activation_lease or context
            if type(expected)~='table'then return false end
            local current=json.decode(assert(read(BASE..'/installation.json',32768)))
            local c=require('uci').cursor();local fresh=policy_module.read(c:get_all('deco_iot_vlan','iot'))
            local generation=activation_lease and activation_lease.generation or (policy and policy.generation)
            return fresh.valid==true and fresh.generation==generation and current.generation==generation
                and current.device_id==expected.device_id and current.boot_id==expected.boot_id
                and current.install_nonce==(activation_lease and activation_lease.install_nonce or (manifest and manifest.install_nonce))
                and trim(read('/tmp/sync-cached-DEV_ID',128))==expected.device_id
                and trim(read('/proc/sys/kernel/random/boot_id',128))==expected.boot_id
        end)
        return ok and owned==true
    end
    local function clear_own_cancelled_epoch()
        if not activation_lease or not generation_owned()or not result.epoch then return end
        if trim(read(BASE..'/epoch',64))==result.epoch then
            assert(os.remove(BASE..'/epoch'),'own cancelled epoch removal failed')
        end
    end
    local ok,why=pcall(function()
        assert(nx.getuid()==0,"root required")
        lease_guard()
        if activation_lease then result.activation_nonce=activation_lease.nonce;result.activation_transaction=activation_lease.transaction end
        if activation_lease==nil then first_cold=kernel.prepare_first_cold() end
        local qio=quiesce.native_adapter();qio.preserve_complete=true
        assert(quiesce.run("network",qio)==true,"worker quiesce barrier failed")
        lease_guard()
        result.fail_closed=true;result.held=true
        manifest=json.decode(assert(read(BASE.."/installation.json",32768)))
        context={uid=0,device_id=trim(read("/tmp/sync-cached-DEV_ID",128)),
            boot_id=trim(read("/proc/sys/kernel/random/boot_id",128)),mode=nil}
        assert(context.device_id==manifest.device_id,"worker device mismatch")
        assert(events.empty(json.decode(assert(read(BASE.."/active-events.json",32768))),context),"native event still active")
        local cursor=require("uci").cursor()
        policy=policy_module.read(cursor:get_all("deco_iot_vlan","iot"))
        assert(policy.configured and policy.valid and policy.generation>=1,"valid owned policy required")
        result.device_id=context.device_id;result.boot_id=context.boot_id;result.generation=policy.generation
        context.native_iot_enable=cursor:get("iot_wifi","iot","enable")
        context.mode=cursor:get("sysmode","sysmode","mode")
        context.firmware_verified=trim(read("/tmp/sync-cached-MODEL",256))=="XE75Pro"
            and trim(read("/tmp/sync-cached-HARDVERSION",256))=="3.0"
            and trim(read("/tmp/sync-cached-SOFTVERSION",512))=="1.5.0 Build 20260603 Rel. 15804"
        local control=assert(loadfile(BASE.."/managed_control.lua"))()
        context.all_three_generation_committed=control.verify_attestation(manifest,policy)==true
        context.install_committed=manifest.committed==true
        if activation_lease then
            assert(activation_lease.device_id==context.device_id and activation_lease.boot_id==context.boot_id
                and activation_lease.install_nonce==manifest.install_nonce and activation_lease.generation==policy.generation
                and activation_lease.enabled==policy.enabled,'activation policy changed before worker')
            context.activation_lease=activation_lease
        end
        local pending_raw=read(BASE.."/pending.json",4096)
        local pending_ok,pending=pcall(json.decode,pending_raw or "")
        if pending_ok and type(pending)=="table" and pending.schema==1 and pending.pending==true
            and pending.device_id==context.device_id and pending.boot_id==context.boot_id
            and (pending.event=="wifi" or pending.event=="network")
            and type(pending.completion_nonce)=="string" and #pending.completion_nonce==32
            and not pending.completion_nonce:find("[^%x]") then
            context.allow_main_ifindex_rebase=true;context.completed_event=pending
        end
        -- Guest completion has a separate cold/pre-active admission path.
        if pending_ok and type(pending)=="table" and pending.schema==1 and pending.pending==true
            and pending.device_id==context.device_id and pending.boot_id==context.boot_id
            and (pending.event=="guest" or pending.event=="wifi")
            and type(pending.completion_nonce)=="string" and #pending.completion_nonce==32
            and not pending.completion_nonce:find("[^%x]") then
            context.allow_main_cold_guest_rebase=true;context.completed_event=pending
        end
        context.wired_port=2;context.cpu_pvid=1;context.uplink_pvid=4
        local link=tonumber(trim(read("/proc/rtk_gsw/phylink",128)))
        context.wired_p2_live=link and math.floor(link/4)%2==1 or false
        local epoch=trim(assert(read("/proc/sys/kernel/random/uuid",128))):gsub("%-","")
        assert(#epoch==32 and not epoch:find("[^%x]"),"worker epoch unavailable")
        context.epoch=epoch;result.epoch=epoch
        lease_guard()
        assert(write(BASE.."/epoch",epoch.."\n"))
        lease_guard()
        local hooks=assert(loadfile(BASE.."/hook_callbacks.lua"))().new(manifest)
        platform=kernel.new({policy=policy,context=context,manifest=manifest,hooks=hooks,first_cold=first_cold})
        lifecycle=assert(loadfile(BASE.."/lifecycle_plan.lua"))()
        local plan=lifecycle.plan(policy.enabled and "enable" or "disable",policy,context)
        local performed=lifecycle.execute(plan,platform)
        retain_failure(performed)
        lease_guard();assert(generation_owned(),'worker generation superseded')
        for _,key in ipairs({"completed","ready","active","error","operations","failed_operation","private_reason"}) do result[key]=performed[key] end
        result.fail_closed_policy=performed.fail_closed==true
        result.held=performed.active~=true and performed.fail_closed==true
        result.fail_closed=result.held
        if performed.completed==true and performed.active==true and context.completed_event then
            local current=json.decode(assert(read(BASE.."/pending.json",4096)))
            assert(current.pending==true and current.device_id==context.device_id and current.boot_id==context.boot_id
                and current.event==pending.event and current.completion_nonce==pending.completion_nonce,
                "native completion changed before consume")
            current.pending=false;current.consumed_by=epoch
            assert(write(BASE.."/pending.json",json.encode(current)))
        end
        result.scoped_iot_vaps_only=true
    end)
    if not ok then pcall(clear_own_cancelled_epoch)end
    if platform then
        if not ok and generation_owned() then
            local owned=generation_owned();local cleared=owned and pcall(platform.clear_ready,platform);local down=owned and pcall(platform.hold_iot_down,platform)
            result.fail_closed=cleared and down;result.held=result.fail_closed
        end
        local closed=pcall(platform.close,platform)
        if not closed then
            local owned=generation_owned();local cleared=owned and pcall(platform.clear_ready,platform);local down=owned and pcall(platform.hold_iot_down,platform)
            result.fail_closed=cleared and down;result.held=result.fail_closed
            result.completed=false;result.ready=false;result.active=false;result.error="worker_lock_close_failed"
        end
    end
    if not ok then result.error="managed_worker_failed";result.completed=false;result.ready=false;result.active=false end
    -- Private diagnostic contains only fixed own-code errors, never UCI payloads.
    if not ok then
        result.private_reason=type(lifecycle)=="table" and type(lifecycle.sanitize_error)=="function"
            and lifecycle.sanitize_error(why) or "unclassified_error"
    end
    if generation_owned()then
        write(BASE.."/last-result.json",assert(json.encode(result)));result.last_result_published=true
    else result.last_result_published=false;result.superseded=true end
    return result
end
if arg and arg[0]==BASE.."/worker.lua" then
    if #arg~=1 or arg[1]~="reconcile" then os.exit(2) end
    local ok,value=pcall(M.reconcile)
    os.exit(ok and value.completed and 0 or 1)
end
return M
