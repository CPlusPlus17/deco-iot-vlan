-- Own source. Data-only checks used by fixed native reload queries.
-- A readiness record never substitutes for fresh resource observations.
local M={}
local NODES={
    ["@MAIN_DEVICE_ID@"]=true,
    ["@BEDROOM_DEVICE_ID@"]=true,
    ["@CELLAR_DEVICE_ID@"]=true}
local function token(value,n)
    return type(value)=="string" and #value==n and not value:find("[^%x]")
end
local function integer(value)
    return type(value)=="number" and value==math.floor(value) and value>=1
end
local function ownership(s)
    local i,j,r=s.installation,s.state,s.resources
    if s.uid~=0 or not NODES[s.device_id] or type(s.boot_id)~="string" or #s.boot_id~=36 then return false,"identity" end
    if type(i)~="table" or i.schema~=1 or i.committed~=true or not token(i.install_nonce,32)
        or i.device_id~=s.device_id then return false,"installation" end
    if type(j)~="table" or j.schema~=1 or j.install_nonce~=i.install_nonce or j.device_id~=s.device_id
        or j.boot_id~=s.boot_id or not token(j.epoch,32) or not integer(j.generation)
        or not integer(j.bridge_index) or not integer(j.vlan_index)
        or type(j.private_bridge_id)~="string" or not j.private_bridge_id:match("^%x%x%x%x%.%x%x%x%x%x%x%x%x%x%x%x%x$") then
        return false,"ownership_journal"
    end
    if type(r)~="table" or r.bridge_index~=j.bridge_index or r.vlan_index~=j.vlan_index
        or r.private_bridge_id~=j.private_bridge_id or r.vlan_master_bridge_id~=j.private_bridge_id
        or r.vlan_parent~="eth1" or r.vlan_id~=30 then return false,"owned_resources_changed" end
    return true
end
function M.evaluate(operation,s)
    assert(operation=="ready" or operation=="own_vlan" or operation=="own_network" or operation=="preserve_vlan","unknown fixed hook query")
    if type(s)~="table" then return false,"snapshot_missing" end
    local ok,reason=ownership(s)
    if not ok then return false,reason end
    -- Ownership remains meaningful after readiness/epoch revocation, and while
    -- a newer desired generation is being prepared. Native cleanup may not
    -- destroy an owned device during that transition.
    if operation=="own_vlan" then return true end
    if operation=="own_network" then
        return type(s.state.network_section)=="table" and s.state.network_section.name=="iot"
            and s.network_registered==true,"owned_network_missing_or_changed"
    end
    if operation=="preserve_vlan" then
        local l=s.load_section
        return type(l)=="table" and l.name=="deco_iot" and l.type=="switch_vlan"
            and l.device=="switch1" and l.vlan=="30" and l.vid=="30" and l.ports=="2t 6t",
            "owned_load_section_missing_or_changed"
    end
    local p,r,j=s.policy,s.ready,s.state
    if type(p)~="table" or p.configured~=true or p.valid~=true or p.enabled~=true
        or p.generation~=j.generation then return false,"desired_policy" end
    if s.native_iot_enable~="0" or s.mode~="AP" or s.firmware_verified~=true then return false,"native_mode" end
    if s.epoch~=j.epoch or type(r)~="table" or r.schema~=1 or r.install_nonce~=j.install_nonce
        or r.device_id~=s.device_id or r.boot_id~=s.boot_id or r.generation~=p.generation
        or r.epoch~=j.epoch then return false,"stale_ready" end
    for _,key in ipairs({"verified","native_iot_disabled","writer_guard","private_path",
        "firewall_rules","network_registered","all_three_generation_committed"}) do
        if r[key]~=true then return false,"ready_attestation_missing" end
    end
    if r.bridge_index~=j.bridge_index or r.vlan_index~=j.vlan_index
        or r.private_bridge_id~=j.private_bridge_id or r.tagged_ports~="2t 6t" then return false,"ready_resource_binding" end
    if s.tagged_ports~="2t 6t" or s.cpu_pvid~=1 or s.uplink_pvid~=4 or s.wired_p2_live~=true
        or s.firewall_rules_verified~=true or s.network_registered~=true
        or s.hooks_verified~=true or s.firewall_finished~=true or s.native_events_empty~=true then return false,"fresh_private_path" end
    for _,key in ipairs({"bridge_up","vlan_up","no_local_address","ipv6_disabled","arp_ignored"}) do
        if s.resources[key]~=true then return false,"private_host_state" end
    end
    return true
end
return M
