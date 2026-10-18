# Rollback and recovery

The source contains ownership journals, guarded disable/cleanup paths, source-transaction recovery and fail-held behavior. The public alpha does not include a universal deployment or uninstallation command. Recovery still needs the operator's per-unit preimages and reviewed integration tooling.

## Prepare before deployment

Preserve each unit's own native files, configuration, source metadata, interface/main-network baseline, and undo information. Keep these private and outside the repository. A backup or binary cache from one unit is not a substitute for another unit's data.

Maintain a way to reach the owner administration interface while testing. Fixed VLAN 30 and the tested switch layout are part of the recovery assumptions, not automatically discovered capabilities.

## Disable the managed IoT path

Use the original reviewed managed Disable path for the installed version. Confirm that the managed IoT runtime is inactive/held and that the main network remains intact. Disabling the runtime and removing its persistent integration are separate operations.

Restore only resources and files positively attributed to this installation. Check the ownership journal before restoring a file or removing a bind/interface. Preserve native guest/main configuration; the unresolved guest VLAN issue is not authorization to clear or normalize a native VLAN.

## Failed source transactions

A verified rollback returns to the exact previous source set and verifies the ending state. Runtime readiness can remain held afterward; a separate genuine worker recovery is needed before claiming READY.

If a write, response, cleanup or rollback outcome is unknown, inspect the exact attempt first. Do not replay a nonce, remove journals manually, or infer absence from an unavailable read. Keep the unit held when the required source, ownership or main-network checks cannot be established.

A host-side closure records a known outcome. It does not restore device state, create a successful reboot, or replace on-device verification.

## After recovery

Verify the unit's identity, expected source set, main-network state and managed runtime state. A recovered warm state does not prove ordinary reboot persistence. Test the corrected version on Keller, including a real reboot, before distributing it to the peers for the final shared regression.

For a failure without a reviewed recovery path, stop deployment and retain private evidence for investigation. There is no blanket promise that this alpha can recover every interrupted state.
