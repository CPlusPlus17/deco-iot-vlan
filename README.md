# deco-iot-vlan — alpha

Experimental IoT VLAN runtime and native web UI integration for **TP-Link Deco XE75 Pro V3, firmware 1.5.0 Build 20260603 Rel. 15804**, using a three-unit mesh with wired backhaul in AP mode.

This alpha targets **fixed VLAN 30**. It separates the supported IoT Wi-Fi interfaces onto a private bridge and tagged Ethernet uplink while checking that the main, untagged network stays intact. It includes persistence and reload handling, per-unit ownership checks, coordinated policy control, and an owner-authenticated native IoT VLAN page.

**The public alpha contains project sources and patches, not a flashable firmware image or a general-purpose installer.** Persistence and guest-network preservation still have open issues. Read [STATUS](docs/STATUS.md) before using it.

## Supported profile

- Deco XE75 Pro **V3** on the exact firmware build above.
- Three wired units: one main unit and two satellites.
- AP mode with an upstream VLAN-aware network providing VLAN 30 service.
- VLAN 30 for IoT; the main network remains untagged.
- The native IoT interfaces and switch layout of this specific hardware/firmware profile.

Other hardware revisions, firmware releases, arbitrary VLAN IDs, wireless backhaul, and different switch layouts are unverified.

## Current implementation

The current alpha lives in [`persistence/`](persistence/):

| Path | Purpose |
| --- | --- |
| `persistence/runtime35/` | Project runtime source templates for the 35-file runtime build. |
| `persistence/ui14/` | UI boot loader, manifest and project UI assets. |
| `persistence/vendor-patches/` | Patches applied to the operator’s exact stock runtime/UI inputs. |
| `persistence/ui-patch-plan.json` | Description of the UI integration points. |
| `persistence/source-inventory.json` | Source inventory and provenance information. |
| `persistence/profile.example.json` | Synthetic example profile, not a device enrollment. |
| `persistence/tools/` | Offline validation and source-bundle construction. |
| `persistence/NOTICE`, `persistence/LICENSES/` | Provenance and licensing notices. |

The top-level `runtime/`, `tests/`, and `ui/` directories contain earlier prototypes. Their test results and the older read-only status page do not establish verification of the current persistence runtime.

The current native UI adds an **IoT VLAN** page on the main unit. It provides owner-authenticated enable/disable control for VLAN 30 and status for the three-unit policy. It does not offer arbitrary VLAN selection. Its **Reboot unverified** badge remains separate from external reboot evidence; it is not a complete persistence ledger. Public UI templates use generic labels and disable migration from historical private UI overlays; the inventory records the packaging changes.

## Build locally

From the repository root, with Python 3.9 or later and your own extracted stock root filesystem from the exact firmware build. Replace the placeholder stock path:

```sh
python3 persistence/tools/validate_alpha.py
python3 persistence/tools/build_alpha.py --profile persistence/profile.example.json --stock-rootfs /path/to/extracted-stock-rootfs --allow-example --output persistence/dist/example
python3 persistence/tools/validate_alpha.py --bundle persistence/dist/example
```

Run the offline builder boundary tests without stock firmware or device access:

```sh
python3 persistence/tests/test_alpha_tools.py
```

The first command checks the public source/patch inventory. The build requires the exact stock inputs and rejects missing or mismatched files; the final command checks the generated local bundle. They do not connect to a Deco, install code, obtain privileged access, create policy attestations, or verify a live device. The example uses synthetic identifiers and a documentation-only gateway.

See [INSTALL](docs/INSTALL.md) for the deployment boundary and [ROLLBACK](docs/ROLLBACK.md) for recovery requirements.

## Verification status

Earlier warm-state tests covered all three wired units, including phone/client checks. One Keller unit passed an ordinary reboot using the production source set. A separate Keller reboot with diagnostic tracing also passed the unchanged strict boot checks.

**This does not establish a completed three-unit cold-boot regression or a causal fix.** Native guest VLAN 591 state has varied between boots. The latest native readings confirmed an empty hardware port list and no guest UCI row despite enabled guest/tagging configuration and successful outer native return codes. The cause remains unresolved. Peer cold tests and the final shared UI/client/isolation checks remain incomplete. The diagnostic tracing changes are excluded from this production-source alpha bundle.

[STATUS](docs/STATUS.md) records these distinctions. Development proceeds on Keller first; the working result is then distributed to the peers before one shared final regression.

## Further reading

- [Status and limitations](docs/STATUS.md)
- [Installation/build boundary](docs/INSTALL.md)
- [Rollback](docs/ROLLBACK.md)
- [Security and reporting](docs/SECURITY.md)
- [Earlier startup/lifecycle analysis](docs/startup-and-lifecycle.md)
- [Earlier stock datapath analysis](docs/stock-datapath-analysis.md)

The last two documents describe earlier investigation and may predate the current alpha. Separate security research is maintained in the [companion advisory repository](https://github.com/CPlusPlus17/deco-filepush-disclosure).

The maintainer’s newly authored code is offered under the [MIT license](persistence/LICENSES/MIT.txt). Vendor-derived and third-party material retains its original terms; this is not a blanket MIT license for the repository. Consult the notices and file-level provenance.
