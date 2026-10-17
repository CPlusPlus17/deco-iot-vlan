# Startup Extension & Reload Lifecycle Audit

## 1. Native Startup Extension Audit

```text
Native startup extension audit (offline only), 2026-10-17

A documented extension exists in the firewall UCI configuration. tsched and
cron do not independently solve persistent custom startup in the examined image.

Firewall include: concrete intended candidate

- Stock rootfs/etc/config/firewall explicitly says 'include a file with users
  custom iptables rules' and declares config include /etc/firewall.user.
- rootfs/lib/firewall/core_init.sh:295-307 reads the declared path, tests that
  it exists and sources it in a SUBSHELL. A separate own include declaration
  pointing directly to a fixed /tp_data/user_data/... script requires no path
  traversal, injected command string or replacement of an existing service.
- etc_ro/init.d/firewall START45 calls fw_start, whose core.sh:40 loads includes.
  The persistence lane independently confirmed mount_tpdata START00 precedes
  native UCI load at START10, and native saveconfig/restoration includes all
  /etc/config files. Those provide the intended execution/data path; a bounded
  per-node RAM proof and controlled reboot remain required before claiming it
  has actually survived reboot.
- Loader does not consult include.enabled. Disable the own policy in the own
  script; uninstall removes only its exact owned UCI section/path. An enabled=0
  option alone is ineffective.

Exact include timing and implementation boundary

fw_start executes: fw_init; fw_clear DROP; defaults/zones/forwardings/rules/
redirects; includes; notrack; interface configuration; tpcmd; post-core callbacks;
then firewall.core.loaded=1. Missing/failed include does not stop that sequence,
so loaded=1 alone does not attest our bootstrap or rules. Its shell config()
function is deliberately overridden to reject UCI use inside the include.

Keep the source include short and nonrecursive. Install/check only the fixed own
firewall protection synchronously and enqueue or start one explicitly owned
worker using fixed paths with detached stdio; do not synchronously call network,
Wi-Fi, repacd or firewall reload from inside incomplete native fw_start. A worker
must independently validate own identity/boot/policy/resources, check actual own
rules and native readiness, then serialize its own lifecycle work. Repeated
includes must not spawn competing workers. Own path integrity/permissions and
owned PID/start matching matter; never adopt an unrelated same-name process.

This hook is not a pre-stop callback. fw_stop calls fw_clear ACCEPT before it
flushes IPv4/IPv6 tables; fw_reload is stop/start, so includes are reached only in
the new start. Also Wi-Fi START41/repacd START44 precede firewall START45. The
include therefore solves startup execution, but alone does not prove the absence
of an early IoT-to-main bridge interval or the firewall flush gap. The lifecycle
review's native generation/hold-down gate remains necessary before an isolation
claim across boot/reload. A post-start periodic repair cannot replace that gate.

Tsched: module scheduling, no direct durable custom executable hook found

- etc_ro/init.d/tsched START50 launches /usr/sbin/tsched with procd respawn; no
  UCI-supplied executable is selected by that startup script.
- Exact native binary strings name /etc/tsched.conf.d/, its update.d, and the
  executable format /etc/tsched.d/%s. It imports execv, not a generic UCI command
  dispatch interface. Installed modules are LED/eco/power/reboot/camera and
  save_tmp_config scripts. Source is not present in the supplied GPL file list.
- /usr/sbin/tsched_conf is a normal Lua CLI for module/entry/range operations.
  Its bytecode module's static strings likewise contain /etc/tsched.conf.d/,
  update.d and /tmp/.tsched; no /tp_data startup-script path was found.
- save_tmp_config's entry_arg is appended to fixed /etc/tsched.d/script.d/ and
  executes installed data-saving helpers. It is an unrelated native save job,
  not a declared custom startup-script facility. Redirecting it with traversal
  or crafted shell parameters is outside the requested design and was not used.
- Installing a new own module under the volatile /etc/tsched.d tree would still
  require a prior durable bootstrap. Native UCI save does not itself restore that
  script tree, so using tsched here would not remove the original boot problem.

Cron and rc.local

- etc_ro/init.d/cron START50 launches crond against /etc/crontabs. Its UCI system
  setting controls log level only. Native services build their own fixed cron
  lines at runtime. No examined saved UCI declaration restores a custom cron
  command or the crontab file itself.
- etc_ro/init.d/done START95 explicitly executes /etc/rc.local. The stock file
  invites custom commands, but /etc is volatile and native UCI restoration alone
  does not preserve rc.local. Thus this is a valid RAM hook, not independently a
  proven durable bootstrap.

No device connection, script invocation, config save, service restart, readonly
root replacement, flash write or boot-variable change was performed in this audit.
```

## 2. Reload Lifecycle & Topology Review

```text
Deco XE75 Pro V3 IoT VLAN30: lifecycle and topology review
2026-10-17; offline own review only, no device contact or production edits.

Conclusion

The working all-three RAM trial proves the currently staged Ethernet path. Its
runtime is deliberately tied to one boot and the original interface indices;
it is not a persistence/reload reconciler. A startup-only reapply or periodically
moving ath08/ath18 back after native reloads cannot preserve isolation: native
code can recreate those VAPs on br-lan before a later repair runs. Native guest
and firewall reloads also remove parts of the private path independently.

Specific lifecycle owners and consequences

1. Native wireless generation overwrites the bridge assignment.
   rootfs/lib/wifi/wificommon.sh:648-651, the mode=ap/type=iot branch,
   unconditionally writes wireless.<IoT>.network='lan'. The function is invoked
   by wifi_config_inspect after relevant wifi/iot_wifi changes (:1194-1306),
   and repacd start uses its result (:1800ff). etc_ro/init.d/wifi:60-65 adds
   wifi/iot_wifi reload triggers and restarts repacd asynchronously.
   Consequence: setting generated wireless.<IoT>.network once is insufficient.
   Candidate must choose the private bridge in the generator before the VAP is
   brought up, or hold only the IoT VAPs down until its private path is ready.
   Failed/disabled custom policy must not temporarily place opted-in IoT clients
   on br-lan. Native IoT enable/disable remains authoritative for whether a VAP
   should exist/be up; a custom reconciler must not recreate disabled IoT VAPs.

2. Wi-Fi reload can destroy the identities the proven trial owns.
   rootfs/sbin/wifi:191-198 runs network reload and then disables/enables legacy
   Wi-Fi. rootfs/lib/wifi/qcawifi.sh:1555-1616 downs/unbridges VAPs and invokes
   wlanconfig destroy; the enable path derives the bridge from generated config
   (:3507-3515). The faster path is not globally inert either:
   rootfs/lib/wifi/wifiupdate.sh:1746-1786 updates selected VAPs but also changes
   ath12 CAC settings; :1810-1834 calls up_all_vap after its selected action.
   create_process (:55-65) and up_all_vap (:1169-1218) can add native bridge
   members. Consequence: do not run full Wi-Fi/radio/repacd reload while relying
   on the existing exact-ifindex trial rollback. A separate candidate must own
   lifecycle epochs and freshly identify any recreated IoT VAP before adopting
   it. Name reuse alone is insufficient, and foreign/non-IoT VAPs are untouched.

3. Guest/bind changes reset the complete RTL VLAN table.
   rootfs/etc_ro/init.d/guest_eth:48-99 registers wifi/bind triggers and invokes
   switch_guest_config. rootfs/lib/guest-eth/guest-eth.sh:42-64 rewrites the
   stock guest entry then calls swconfig load on /etc/vlan.d/vlan. Clear also
   loads the complete file (:370-382). GPL swconfig/src/uci.c early_settings
   contains reset='1',enable_vlan='1'; swlib_apply_from_uci applies these before
   configured entries and explicitly forces reset for CONFIG_PACKAGE_kmod-rtl8367s
   ('clean vlan table'). RTL reset callback in GPL rtl8367s.c:457-461 invokes
   the registered reset; rtl8367s_mdio.c:279-289/362 registers a function calling
   rtk_vlan_reset for the RTL8221B build.
   Consequence: a RAM-only VID30 entry will not survive this reload. If adding
   a separate named IoT switch section, it must be present in the exact complete
   input used by every load, and must not replace vlan.guest or stock VIDs2/3/4.
   Do not emulate a guest reload with an unconditional full-switch reset.

4. Native guest cleanup can delete the private VLAN netdevice as well.
   rootfs/lib/guest-eth/guest-eth.sh:86-160 del_invalid_guest_eth builds a native
   allowlist from get_all_eth_names plus guest/IPTV VLANs, then enumerates all
   eth1.* devices via ifconfig -a. It downs and vlan_del's any absent device;
   the intermediate 'brctl delif br-lan' failure is not checked. Being attached
   to br-iot therefore does not exempt eth1.30. Called on guest/bind paths at
   :212-215/:246-248 and on guest clear (:384).
   Consequence: an owned, identity-checked eth1.30 exclusion/inclusion is needed
   in this cleanup path or the private netdevice must be recreated before IoT
   VAPs can pass traffic. Full-table preservation alone does not solve this.

5. Firewall reload removes the trial's direct interface DROP rules.
   rootfs/etc_ro/init.d/firewall:25-26 delegates reload to fw_reload.
   lib/firewall/core.sh:62-109 stops and starts; stop calls fw_clear ACCEPT,
   start fw_clear DROP; lib/firewall/core_init.sh:311-320 clears all tables.
   Consequence: local management protection requires a native reload integration
   or fail-closed IoT-down gate before flush and before VAP enable. A periodic
   post-reload rule reinsertion leaves a gap. Preserve IPv4 and IPv6 protection;
   upstream VLAN firewall policy does not protect the Deco's own CPU services.

6. AP/router mode change and mesh-role change are distinct lifecycle events.
   etc_ro/init.d/sysmode:75-142 force-reboots when sysmode changes; this is not
   a harmless reload test. Separately hotplug.d/mode/00-apsd restarts apsd at
   role-change END; 99-guest calls guest_eth reload bind for RE; 99-hyfi-bridging
   reattaches native HYFI bridges; 00-network may commit network and reload it.
   Current policy is AP mode with a proved wired trunk; Router mode and a changed
   native Ethernet profile are unsupported until independently planned. If mode,
   firmware, native Ethernet VIDs/PVIDs, or selected uplink changes, stop only the
   custom IoT path and report degraded state; never guess new tagged ports.

Topology scope and per-node preservation

- 2t 6t is justified by current all-three gateway/known-peer FDB P5 -> eth1.4 ->
  VID4 -> RTL physical2 and per-node VLAN30 transport/client tests. This proves
  the current wired link, not arbitrary cable movement, wireless failover, or
  an unobserved daisy-chain via ports0/1. A persistent policy must explicitly
  retain this topology scope. Lost or changed trunk means custom IoT unavailable,
  without falling back to the main bridge or tagging all Ethernet sockets.
- Native guest VID500 differs: main6t, sat10t 1t 2t 6t, Node3 empty. Do not
  clone it across nodes or treat a later legitimate guest change as foreign
  corruption to be overwritten with an old snapshot. The custom VID30 section
  must remain independent. Preserve stock VID2='0 6t',VID3='1 6t',VID4='2 6t'
  and nonzero PVID0=2,1=3,2=4,6=1; runtime changes must compare fresh own state.
- HYFI startup attaches br-lan/br-iptv/br-wan, not the new private bridge
  (etc_ro/init.d/hyfi-bridging:30ff). Direct CPU br-iot->eth1.30 probes do not
  demonstrate wireless transport. Prior static QCA MP/NSS evidence gives no
  additional switch0 per-VID registration prerequisite; see
  analysis/access-offline/topology-dts/qca-mp-vlan-path-review.txt.

Minimal RAM candidate proof before a durable install/reboot

A. Keep all-three scope, independent own backups/undo, and the proved common
   deadline. After the existing trial fully expires, use a NEW transaction and
   separately backed lifecycle-aware candidate; do not change the frozen runtime.
   Before any native event, prove rollback can handle the precise event's new
   ifindices, bridge lifetime and rules. The existing trial is suitable only for
   direct apply/status/undo without native interface recreation.

B. Offline source/mocked-native lifecycle tests first: native generation with
   custom enabled emits the private IoT network; disabled native IoT stays
   disabled; unknown policy/firmware/mode holds IoT down. Guest full-load keeps
   VID30 and each node's current stock entries; guest cleanup retains only the
   exact owned private VLAN device; firewall stop/start holds IoT down until both
   address-family protections exist. Recreated VAP identities are adopted only
   from the expected native IoT config/parent and a new journal epoch. Foreign
   same-name resources, failed native events, a killed worker and expired timer
   all end in verified undo or explicit held-down state.

C. In RAM, first invoke ONLY the new candidate's prepare/reconcile/status twice
   on every node. Require the second call to make no new changes. Exercise its
   own private VID30 recreation while IoT VAPs are held down, then all-node
   offers and the owner's client test. This isolates ownership/recovery from
   native Wi-Fi disruption and proves the candidate is idempotent.

D. Next test one real native event at a time, sequentially per node while other
   nodes remain unchanged and recoverable; complete the same event on ALL3
   before claiming mesh-wide support. Begin with a same-value native IoT config
   regeneration test only if its selected action is known and bounded. Then
   one native guest reload and one native firewall reload, with own backups and
   the IoT-down gate already armed. Collect before/after VID2/3/4/500/PVIDs,
   management addresses/routes, non-IoT bridge membership, the private resources,
   active IPv4/IPv6 rules and exact restoration. Renew the phone lease only on
   that node's IoT WLAN and verify VLAN30 addressing/Internet plus management
   denial. Require no interval where an enabled opted-in IoT VAP joins br-lan.
   Do not label /sbin/wifi update an IoT-only action merely from its VAP list;
   its native up_all_vap/CAC side effects must be included in the boundary.

E. Full Wi-Fi reload, network reload, role switch, Ethernet cable movement and
   reboot are separate later proofs. They are not prerequisites to a bounded
   RAM-only control, but they ARE prerequisites to claiming those persistent
   lifecycle cases are supported. A system-mode toggle is a reboot/sync action;
   never use it as the first test of the custom startup hook. The persistence
   lane must first establish exactly which durable hook restores the candidate
   and that recovery survives a failure before management/Wi-Fi become ready.

Only analysis/mesh-persistence/lifecycle-topology-review.txt was written by this
review. No VAP, switch, service, policy, flash, or production source was changed.
```
