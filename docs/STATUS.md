# Alpha status

Snapshot: **18 October 2026**. This page describes the available evidence, not a support or security guarantee.

## Scope

The implementation targets one specific profile: Deco XE75 Pro V3, firmware 1.5.0 Build 20260603 Rel. 15804, AP mode, three wired units, fixed IoT VLAN 30, and an untagged main network. The intended upstream VLAN/DHCP/firewall configuration is supplied by the operator.

The public project sources are under `persistence/runtime35/` and `persistence/ui14/`; vendor-derived changes are under `persistence/vendor-patches/`. Reconstructing the full payload requires operator-supplied exact stock firmware inputs. Earlier top-level runtime and UI prototypes are retained as historical material. The public UI copy uses generic unit labels and disables migration from historical private UI overlays; it is not byte-for-byte identical to the privately exercised UI assets. Consult the source inventory for the packaging changes.

## What has been observed

| Area | Evidence | Limit |
| --- | --- | --- |
| Warm runtime | Enabled, active and READY states were verified across the three-unit wired test setup. Earlier phone/client checks also covered that setup. | This is not a new cold-boot or final client regression. |
| Reload/persistent loading | Genuine firewall reloads and persistent/RAM source checks have succeeded in the tested environment. | This is not qualification of arbitrary firmware or installation methods. |
| Ordinary reboot | One Keller unit passed an ordinary reboot on the production source set, at internal policy generation 38. | Peer cold verification and repeatability across the full setup remain open. |
| Instrumented reboot | A separate Keller diagnostic reboot at internal generation 40 passed strict source, native binding, main-network, MAC and READY checks across two stable full snapshots. | Diagnostic tracing was the source change. The pass does not establish a causal fix or final production qualification. |
| Native UI | The current assets contain an owner-authenticated, main-unit IoT VLAN 30 controller and status view. | Final browser/UI validation remains pending. The UI persistence badge still says **Reboot unverified**. |
| Client isolation | Warm-state client evidence exists. | A fresh, shared final DHCP/DNS/connectivity/management-isolation regression is incomplete. |
| Offline alpha build | 19 builder boundary tests passed. Exact stock reconstruction and the private-profile runtime35 checksum comparison passed; repeated example builds were byte-identical. Generated Lua, JavaScript, shell and JSON syntax checks passed. | Local source/bundle validation does not execute the on-device runtime or establish deployment, UI, isolation or reboot acceptance. |

Policy generation counters are internal transaction history, not release versions.

## Open issues

**Native guest VLAN 591 preservation remains unresolved.** Its tagged port state has changed between boots while the IoT runtime reached READY. Strict boot verification correctly rejected earlier rounds where the guest/main projection differed.

A later, bounded diagnostic trace positively recorded native ADD and load calls returning success. A subsequent read-only native observation confirmed that VLAN 591 had an empty hardware port list in both readings, despite enabled guest/tagging configuration, and that the loaded VLAN package contained no guest row. VLAN 30, core VLANs and port settings remained as expected in that observation.

The native UCI set/commit return codes are unchecked, so the successful outer return does not prove that the guest row committed. The partial trace does not rule out other invocations or establish complete startup history. The hardware/configuration mismatch is established; its cause and functional effect on the guest network remain unproven. No functional fix is claimed.

The alpha excludes the temporary diagnostic guest/hook tracing changes. Kernel and worker sources are shared with the tested implementation, but that alone does not prove guest preservation or reboot repeatability.

## What is not claimed

- A completed three-unit cold-boot, UI and client/isolation acceptance run.
- A reliable fix for the unresolved guest VLAN behavior.
- Support for other hardware, firmware, arbitrary VLANs or wireless backhaul.
- A flashable image, one-command installer, privilege bootstrap, or automatic enrollment of new units.
- An independent security audit or a repository-wide license grant.

## Development and acceptance

Corrections are developed, deployed and cold-tested on Keller first. A working result is then distributed once to the other units, followed by one shared final validation. Per-unit results and mixed versions must remain explicit.

The older analysis documents retain their historical observations. This page and the source inventory describe the alpha's current scope; an offline build is not a live acceptance test.
