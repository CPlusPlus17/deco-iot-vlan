# Security and reporting

This is an experimental alpha for a specific hardware/firmware profile. It has not received an independent security audit. Its warm-state checks and individual reboot results are not a general isolation or security guarantee.

## Intended boundary

The IoT path uses fixed VLAN 30 with a private bridge and management-plane filtering. The main network is intended to remain untagged and unchanged. Upstream routing, DHCP, DNS and inter-VLAN firewall policy belong to the operator's network configuration.

The native UI control is owner-authenticated and fixed to VLAN 30. This repository does not supply an authentication bypass, credential transport, privilege bootstrap or a ready-to-flash image. Operate only on devices you own or are authorized to administer.

## Known limitations

Native guest VLAN 591 state has varied across boots. Guest UCI set/commit outcomes are not established by successful outer native return codes, and a causal fix has not been demonstrated. Full three-unit cold/UI/client acceptance remains incomplete. See [STATUS](STATUS.md).

The UI's **Reboot unverified** badge does not consume the external reboot evidence and must not be interpreted as an independent security attestation. Likewise, READY alone is not proof of guest preservation or successful isolation across the whole mesh.

Separate security research is maintained in the [companion advisory repository](https://github.com/CPlusPlus17/deco-filepush-disclosure). Deployment exploit instructions are outside this alpha's installation guide.

## Reporting

Use a private reporting channel offered by the repository host when available. If no private channel is enabled, request a private contact without publishing exploit details or device data in the initial issue. No monitored security mailbox or response-time commitment is asserted here.

A useful sanitized report identifies the hardware revision, firmware build, source revision, broad operation, expected behavior and observed behavior. Separate source inspection, synthetic/offline tests and actual device observations.

Do not publish credentials, account email addresses, keys, device identifiers, MAC addresses, private network addresses, nonces, per-unit configuration, binary caches, raw logs, private evidence archives or a working exploit chain. Keep local profiles and collected evidence untracked; share only the minimum information needed through an agreed private channel.

## Provenance

The maintainer’s newly authored code is offered under the [MIT license](../persistence/LICENSES/MIT.txt). Vendor-derived and third-party material retains its original terms. The MIT file does not relicense that material or grant rights to the vendor firmware.

Retain file-level notices and review `persistence/NOTICE`, `persistence/LICENSES/`, and the source inventory. Modified vendor-derived files are distributed as patches; operators supply their own exact stock firmware inputs for a local build. Public availability does not replace a review of the applicable upstream terms.
