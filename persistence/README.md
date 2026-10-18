# Persistence source alpha

This directory describes 35 runtime sources and the 14-file MAIN UI source set
for the fixed VLAN30, wired three-node XE75 Pro V3 firmware profile. Authored
modules are included; seven stock-derived native scripts and five stock UI
files are represented by exact-hash patches rather than complete vendor files.
It is a source release. It has no generic installer, privilege bootstrap,
transport exploit, saved device configuration, or reusable installation proof.
See the repository's installation, rollback, status and security documents.

Validate the checked-in source inputs from the repository root:

```sh
python3 persistence/tools/validate_alpha.py
```

Build and verify a **fictional, non-deployable example** locally:

```sh
python3 persistence/tools/build_alpha.py --stock-rootfs /path/to/owner-extracted-stock-rootfs --profile persistence/profile.example.json --allow-example --output persistence/dist/example
python3 persistence/tools/validate_alpha.py --bundle persistence/dist/example
```

For a local owner profile, copy the example to ignored `profile.local.json`, set
`example_only` to false, and supply all three real, distinct device IDs and the
actual gateway. Do not commit that file or the generated output. The builder
accepts only those four profile values and the schema/example markers; VLAN and
port substitutions are not supported. Building does not validate the hardware
or authorize installation. Fresh identity, firmware, per-device backups,
attestation, native IoT-disabled storage, mounts, rollback and cold checks remain
deployment prerequisites.

The build requires exact stock files at the 12 paths and SHA-256 values listed
under `stock_relative_path`/`stock` in `source-inventory.json`. Wrong firmware or
modified inputs fail closed. Eleven unified patches use exact offsets/context;
the minified locale uses compact original-byte-offset edits containing only the
new text. Neither format uses fuzzy matching or external commands. The exact
result template hash is checked after reconstruction. No stock rootfs is copied
into the public source tree or bundled wholesale. Generated full source bundles
are ignored local output and may include material governed by upstream terms.

`source-inventory.json` distinguishes original verified descriptors from public
template bytes. An owner with the original private test profile can use
`--require-reference-match` to check exact **runtime35** byte reproduction. The
public UI deliberately has generic labels and disables migration from historical
private UI overlays; its descriptors are recomputed during the local build.

The alpha excludes temporary guest startup tracing. Guest VLAN591 startup is an
open limitation. A source checksum or successful local build is not a cold-boot,
client-isolation, final mesh regression or deployment result.
