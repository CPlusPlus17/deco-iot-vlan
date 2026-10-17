Deco XE75 Pro V3 — native VLAN status UI source patch
Target: 1.5.0 Build 20260603 Rel. 15804

This package is a source overlay and unified diff. It is now temporarily
installed on 192.168.68.1 using RAM copies and seven bind mounts. The normal
owner login and live native page were verified. It is not a firmware image.

What it adds
------------
Advanced > VLAN status in the stock Router and AP web navigation, using the
existing jQuery $.su widgets, styles, model loader, session token and encrypted
request handling. The page displays:
- Whether the Guest configuration exists and Guest Wi-Fi is enabled.
- The stored Guest VLAN enable flag and usable VLAN ID, if configured.
- That the Guest VLAN setting is global across Guest Wi-Fi bands.
- Whether an IoT configuration exists; IoT VLAN support is not implemented.

These are stored configuration fields, not proof of operational packet tagging
or AP-mode VLAN support. Missing data and service errors are displayed clearly.
The page registers no Save/Apply action and cannot change network settings.

The accompanying authenticated LuCI route is:
  /admin/vlan_status?form=status, operation read

It reads only five fixed UCI keys/section identities. It returns no SSIDs,
passwords, account details, or session secrets. There is no write operation,
command execution, caller-selected file/key, or authentication exception.
Backend and frontend must be installed together for the page to load data.

Build and review
----------------
From the FirmwareDeco workspace:
  python3 patches/vlan-ui/build_overlay.py

Inputs are the exact extracted stock filesystem at:
  analysis/crypto-research/rootfs/

Outputs:
  overlay/             Patched/new source files, with rootfs-relative paths.
  vlan-status.patch    Unified diff against the extracted stock source.
  patch-plan.json      File list and exact original/patched SHA256 hashes.
  validation.json      Local checks and references to live installation receipts.

The build script does not connect to the device or modify the stock inputs.
New UI code and route live in overlay/; JSON registrations, menus and English
labels are generated from ui-integration.json plus the stock assets.

Validation
----------
The unified diff has been applied to a temporary copy and compared byte for
byte with every overlay file. Reversing it restored the exact original files
and removed all new files. All patched JavaScript passed node --check; JSON
registrations parse successfully. The new Lua module passed the vendor Lua
syntax parser and offline contract tests for missing sections, independent
flags, VLAN bounds, route authentication, and rejection of write operations.
Independent source review found no blocking issues.

Cached Chromium also rendered the unchanged module using the stock App loader,
widgets and encrypted request/response handling against a localhost fixture.
Configured values, missing configuration, a missing route, malformed data and
the legacy response envelope all rendered as expected, with no runtime errors, external page
requests or visible Save buttons. The fixture server never contacts a Deco;
this does not test installation or the new route on the running device.
See preview/results/configured.png and preview/results/report.json.

Repeat backend contract tests with the host LuaJIT interpreter:
  luajit analysis/vlan-next/test_vlan_status.lua \
    patches/vlan-ui/overlay/usr/lib/lua/luci/controller/admin/vlan_status.lua

This runs only our new source and local UCI/controller stubs, not firmware
bytecode. See validation.json for the complete local verification record.

Temporary standalone preview on the device
-----------------------------------------
device-preview.html is a separate, inert design mockup with explicit sample
values. It is not the native module above. A uniquely named copy was uploaded
to the existing writable /www/log_export mount, read back exactly through the
management channel, and fetched byte for byte over HTTPS with HTTP 200.
Desktop and phone browser checks passed, with no scripts, forms, controls,
external requests or runtime errors. It makes no API calls and displays no
actual device settings. The file remains in volatile storage until removed
or rebooted; no configuration, service or firmware change was performed.

The current URL and exact file hash are recorded in:
  analysis/write-access/ui-preview-result.json
Browser results and screenshots:
  analysis/write-access/ui-preview-browser.json
  analysis/write-access/ui-preview-desktop.png
  analysis/write-access/ui-preview-phone.png

This separate sample demonstrates temporary static hosting. The native menu,
model and Lua controller are now also installed as described below.

Temporary native installation
-----------------------------
Open https://192.168.68.1/webpages/index.html#guestVlan and use the normal owner
login, or select Advanced > VLAN status. A full reload may be needed for the
new menu. Only English labels have been added.

Owner-authenticated file transfer and a one-use Lua loading task were verified
on the running device. The task restores the original index before running,
copies two stock code/asset directories into a unique /tmp directory, assembles
the nine reviewed files, and binds these RAM copies over the original paths.
It then invalidates the route index so the normal dispatcher registers the
new controller. All 29 original index functions remain bytecode-identical;
the only added index function is our authenticated status route.

All eight web assets were fetched byte for byte from the device over HTTPS.
A fresh temporary browser profile completed one normal owner login and loaded
the real status through the stock encrypted proxy, with no runtime errors or
visible Save button. The captured page contains only the new status panel.
An unauthenticated request did not return status metadata.

Receipts and screenshot:
  analysis/native-ui-runtime/deployment.json
  analysis/native-ui-runtime/browser-validation.json
  analysis/native-ui-runtime/native-status.png
  analysis/native-ui-runtime/index-verification.json

A later independent command probe displaced this route index and then restored
an empty cache because its backup filenames did not match. The verified index
was restored, and a fresh owner login plus live status-page check passed again.
See analysis/native-ui-runtime/site-recovery.json. The two incompatible legacy
helpers deco_cmd.py and deco_lua_exec.py now exit locally before credentials or
network access. Future tasks must preserve the current validated index, restore
it before doing work, and use unique paths with independent failure recovery.

The live stored guest VLAN ID was 500, with its enable flag set. This was read
from existing configuration; it was not changed and is not proof of tagged
uplink traffic. Target IoT30/cameras35/guest40 remain unapplied. The user confirms
Ethernet upstream but VLANs there still need configuring; prerequisites 11a/P7
also remain outside this installation. Camera VLAN35 needs a separate SSID or
another verified assignment mechanism.

Rollback command from the workspace (private owner authentication prompt):
  python3 analysis/web-access/deploy_native_ui.py --rollback

Rollback removes only mounts whose unique source path and filesystem device
match this installation, and restores the exact original route-index backup.
Each rollback attempt gets a fresh lock and receipt. Recovery identity is saved
locally before any transfer. The helpers, original backup and overlay files
must remain available for this command. The rollback paths passed local failure
simulation; a complete live unmount/reinstall cycle has not been performed.

Reboot removes this RAM-only installation. No network UCI settings were changed,
services reloaded, flash written or persistent startup hook installed. The
original SquashFS files remain untouched. There is no interactive SSH shell.

The stock Guest VLAN setter has no verified disable/cleanup transaction, and
the stock IoT VLAN helper is missing. This package therefore does not add VLAN
configuration controls or claim that custom per-SSID VLANs are working.
