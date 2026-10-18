-- Own-source data-only RAM lifecycle prototype. These are FIXED operation IDs,
-- never shell strings. A platform executor with verified ownership, deadlines,
-- rollback and exact device APIs is still required before deployment.
local M={}
local QUIESCE={firewall_stop=true,network_prepare=true,guest_prepare=true,wifi_prepare=true}
local START={firewall_start=true,wifi_regenerate=true,network_ready=true,enable=true}
local function is_int(value) return type(value)=="number" and value==math.floor(value) end
function M.vap(policy,ready,context)
    -- A present owned-policy file with invalid contents always holds IoT down.
    if not policy.configured then return {managed=false} end
    local enabled=policy.valid==true and policy.enabled==true
        and ready and ready.verified==true and ready.generation==policy.generation
        and context and ready.boot_id==context.boot_id and ready.device_id==context.device_id
        and ready.native_iot_disabled==true and ready.writer_guard==true
        and ready.private_path==true and ready.firewall_rules==true
    return {managed=true,network="iot",disabled=not enabled}
end
function M.plan(event,policy,context)
    assert(type(event)=="string" and (QUIESCE[event] or START[event] or event=="disable"),"unknown lifecycle event")
    assert(type(policy)=="table" and policy.configured==true,"own policy required")
    local actions={"clear_ready","hold_iot_down"}
    if QUIESCE[event] or event=="disable" or policy.valid~=true or policy.enabled~=true then
        return {event=event,actions=actions,activate=false,fail_closed=true}
    end
    local valid_context=type(context)=="table" and context.uid==0 and context.install_committed==true
        and context.all_three_generation_committed==true and context.native_iot_enable=="0"
        and context.firmware_verified==true and context.mode=="AP" and context.wired_port==2
        and context.cpu_pvid==1 and context.uplink_pvid==4 and context.wired_p2_live==true
        and type(context.device_id)=="string" and #context.device_id==40
        and type(context.boot_id)=="string" and #context.boot_id==36
        and is_int(policy.generation) and policy.generation>=1
    if not valid_context then
        return {event=event,actions=actions,activate=false,fail_closed=true,blocked="fixed_lifecycle_preflight_failed"}
    end
    for _,operation in ipairs({"verify_own_installation","install_native_writer_guard",
        "install_generator_guard","protect_network_cleanup","protect_guest_cleanup",
        "wait_native_firewall_finished","verify_main_and_switch_baseline",
        "ensure_owned_private_bridge","ensure_owned_vlan30_device","ensure_owned_tagged_p2_cpu6",
        "ensure_owned_firewall_rules","register_owned_iot_network","verify_private_path",
        "publish_ready","regenerate_iot_vaps_only","verify_iot_vaps_private","verify_main_unchanged"}) do
        actions[#actions+1]=operation
    end
    return {event=event,actions=actions,activate=true,fail_closed=true,generation=policy.generation}
end
-- Diagnostic data accepts only fixed own operation IDs and own source locations.
local OPERATION_IDS={clear_ready=true,hold_iot_down=true,verify_own_installation=true,
    install_native_writer_guard=true,install_generator_guard=true,protect_network_cleanup=true,
    protect_guest_cleanup=true,wait_native_firewall_finished=true,verify_main_and_switch_baseline=true,
    ensure_owned_private_bridge=true,ensure_owned_vlan30_device=true,ensure_owned_tagged_p2_cpu6=true,
    ensure_owned_firewall_rules=true,register_owned_iot_network=true,verify_private_path=true,
    publish_ready=true,regenerate_iot_vaps_only=true,verify_iot_vaps_private=true,verify_main_unchanged=true}
local ERROR_SOURCES={kernel_platform=true,lifecycle_plan=true,worker=true,hook_callbacks=true,
    native_adapter=true,bounded_command=true,scoped_create=true,wifi_quiet=true,runtime_install=true,
    managed_control=true,declarative_policy=true,event_state=true,native_quiesce=true}
local ERROR_MESSAGES={['worker deadline']=true,['fixed kernel command failed']=true,
    ['firewall check failed']=true,['foreign matching firewall rule']=true,
    ['own firewall rule missing']=true,['fixed platform operation failed']=true,
    ['unimplemented platform operation']=true,['private path changed']=true}
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
local BOUNDED_IDS={other_reviewed_command=true}
for _,row in ipairs(COMMANDS)do BOUNDED_IDS[row[1]]=true end
local BOUNDED_STAGES={validation=true,directory=true,inherited_session=true,capture=true,pipe=true,
 fork=true,detach=true,gate=true,wait=true,descendants=true,output_identity=true,output_read=true,completion=true}
local BOUNDED_CODES={unclassified_error=true,own_assertion_failed=true,ok=true,not_checked=true}
for message in pairs(MESSAGES)do BOUNDED_CODES[message:gsub('[^a-z0-9]','_')]=true end
local function bounded_diagnostic(message)
 local id,stage,cause,output,seq,marker=message:match('^bounded_diag|([a-z0-9_]+)|([a-z0-9_]+)|([a-z0-9_]+)|([a-z0-9_]+)|([0-9]+)|([01u])$')
 local n=seq and #seq<=5 and tonumber(seq)
 return id and BOUNDED_IDS[id]and BOUNDED_STAGES[stage]and BOUNDED_CODES[cause]and BOUNDED_CODES[output]
  and n and n>=1 and n<=65535 and tostring(n)==seq
end
function M.sanitize_error(value)
    if type(value)~='string' or #value>4096 or value:find('%c') then return 'unclassified_error' end
    local name,number,message=nil,nil,value
    for depth=1,4 do
        local source,line,tail=message:match('^/tmp/deco%-iot%-managed/([a-z_]+)%.lua:([0-9]+):%s*(.*)$')
        if not source then break end
        local parsed=#line<=5 and tonumber(line)
        if not ERROR_SOURCES[source] or not parsed or parsed<1 or parsed>10000 or tostring(parsed)~=line then
            return 'unclassified_error'
        end
        name,number,message=source,parsed,tail
        if depth==4 and message:match('^/tmp/deco%-iot%-managed/') then return 'unclassified_error' end
    end
    if not name then return 'unclassified_error' end
    return '/tmp/deco-iot-managed/'..name..'.lua:'..tostring(number)..': '
        ..((ERROR_MESSAGES[message]or(name=='bounded_command'and bounded_diagnostic(message)))and message or'own_error')
end
function M.execute(plan,platform)
    assert(type(plan)=="table" and type(platform)=="table","fixed execution adapter required")
    local completed={}
    local current_operation
    local ok,reason=pcall(function()
        for _,operation in ipairs(plan.actions) do
            current_operation=OPERATION_IDS[operation] and operation or "unknown_operation"
            assert(type(platform[operation])=="function","unimplemented platform operation")
            assert(platform[operation](platform)==true,"fixed platform operation failed")
            completed[#completed+1]=current_operation
        end
    end)
    if not ok then
        -- These emergency methods must be independent of the normal worker's
        -- lock and must prevent VAP restart before incomplete native reloads.
        local cleared=pcall(function() assert(platform.clear_ready(platform)==true) end)
        local down=pcall(function() assert(platform.hold_iot_down(platform)==true) end)
        return {completed=false,fail_closed=cleared and down,operations=completed,
            error="fixed_lifecycle_operation_failed",ready=false,active=false,
            failed_operation=current_operation,private_reason=M.sanitize_error(reason)}
    end
    return {completed=plan.blocked==nil,error=plan.blocked,fail_closed=true,
        operations=completed,ready=plan.activate,active=plan.activate,
        runtime_prototype_only=true,durable_installation_verified=false}
end
return M
