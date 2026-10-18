# Build and installation boundary

This alpha provides project runtime/UI sources, patches for vendor-derived files, and an offline source-bundle builder. It does **not** provide a reviewed, general-purpose device installer or a flashable firmware image.

## Requirements

Local reconstruction requires an operator-provided extracted stock root filesystem from the exact firmware build. Stock source files are not downloaded automatically. Missing inputs or mismatched source hashes must stop the build; do not substitute another firmware version. Generated full payloads remain local and untracked.

The only tested device profile is Deco XE75 Pro V3 on firmware 1.5.0 Build 20260603 Rel. 15804, AP mode, three wired units, fixed VLAN 30. An operator must supply the matching upstream VLAN, DHCP and firewall configuration.

On-device work requires authorized owner/administrator access, an exact per-unit baseline, and a reviewed recovery path. Those deployment prerequisites are not created by the build tools. Read [STATUS](STATUS.md), [ROLLBACK](ROLLBACK.md), and [SECURITY](SECURITY.md) first.

## Validate the source artifact

From the repository root, using Python 3.9 or later. Replace `/path/to/extracted-stock-rootfs` with your own matching stock root filesystem:

```sh
python3 persistence/tools/validate_alpha.py
python3 persistence/tools/build_alpha.py --profile persistence/profile.example.json --stock-rootfs /path/to/extracted-stock-rootfs --allow-example --output persistence/dist/example
python3 persistence/tools/validate_alpha.py --bundle persistence/dist/example
```

The first command checks the public source and patch inventory without reconstructing vendor-derived files. The build requires `--stock-rootfs`, verifies the expected stock file hashes, applies the supplied patches, and produces a local source bundle with a manifest and checksums. Missing or mismatched stock files are an error; there is no automatic download. The final command verifies that generated bundle. It is not signed by the device manufacturer and is not an input to a firmware-flashing workflow. No device connection is made by these commands.

The source inventory is the authority for the selected runtime/UI files. The older top-level prototype tests do not validate the entire current source set.

`python3 persistence/tests/test_alpha_tools.py` runs the offline builder boundary tests without stock firmware, network access or a device. They exercise patch rejection, profile validation and bundle completeness/checksums. They do not validate on-device runtime behavior.

## Local configuration

The checked-in example is explicitly fictional and non-deployable. It contains synthetic unit identifiers and a documentation-only gateway. The `--allow-example` flag permits only this local example build. A profile customizes only the supported three-unit identifiers and gateway; it does not change the VLAN, hardware layout or firmware support.

If preparing a real deployment, keep a separate **untracked** local profile, for example `profile.local.json`, set `example_only` to false, and supply the three distinct unit identifiers and gateway. Keep account passwords, SSH private keys and other authentication secrets outside profiles and the repository. Check the working tree before committing anything. Do not replace the public example with a real environment.

A profile and a successful build do not create installation ownership, native-source attestations, policy receipts, live identity verification or reboot evidence.

## Device deployment

There is no universal install command to copy from this alpha. The privately exercised maintenance/deployment tooling is not included as a public privilege bootstrap. Integrating the source bundle onto a device remains an experimental operator task.

A reviewed deployment must preserve each unit's own native/configuration preimages, authenticate that unit, verify the exact firmware and source set, and keep the main network intact. Readiness must be held during source replacement and established again by the original runtime checks afterward. A transport timeout is an unknown outcome to inspect, not permission to repeat a write.

Develop and verify on Keller first. Do not treat a Keller-only success as three-unit support, or distribute each unproven iteration across the mesh. Final acceptance needs an ordinary reboot and the shared UI/client/isolation checks described in [STATUS](STATUS.md).
