Earlier native VLAN status UI prototype
======================================

This directory retains the earlier read-only Guest VLAN status UI prototype
for Deco XE75 Pro V3, firmware 1.5.0 Build 20260603 Rel. 15804. It is historical
source material, not the current persistence/UI package or a deployment guide.

Current alpha
-------------
See ../README.md and ../docs/STATUS.md first. The current project UI sources and stock UI patches are in:

  ../persistence/ui14/
  ../persistence/ui-patch-plan.json
  ../persistence/vendor-patches/ui14/

The current assets add Advanced > IoT VLAN on the main unit's normal owner web
interface. After a reviewed installation, the native page fragment is:

  /webpages/index.html#iotVlan

Use the operator's own management address and normal owner login. No device
address, credentials, installation transport or authentication bypass is
provided here.

The current page provides fixed VLAN 30 Enable/Disable controls and a three-unit
policy status view. It uses the existing native UI framework and authenticated
request handling. Controls are disabled when status cannot be validated or the
policy is in an unsafe transition. It does not offer arbitrary VLAN selection.
Final browser/UI acceptance of the current persistence source set is pending.
The public copy uses generic labels; consult the source inventory for the
sanitizing changes relative to the privately exercised assets.

The separate Advanced > VLAN status / #guestVlan page reports stored guest
configuration. Stored fields do not prove effective hardware tagging. The IoT
page's Reboot unverified badge also does not consume external reboot evidence;
packet tagging, Internet access and isolation are not measured by the page.

Historical scope
----------------
Files in this directory describe the earlier status-only integration. Its
read-only backend and preview/test results must not be confused with current
IoT policy control or full persistence acceptance. Earlier environment-specific
deployment instructions are not a public installation contract.

Build and recovery
------------------
Use the repository-root commands documented in ../docs/INSTALL.md to validate
and package the current sources locally. Reconstruction requires the operator’s exact stock firmware root filesystem.
The local result is a source bundle, not a
flashable image or universal installer. Owner-admin device integration and a
reviewed, per-unit rollback path remain prerequisites.

See ../docs/ROLLBACK.md and ../docs/SECURITY.md. Preserve the notices and
file-level provenance supplied with the sources. The maintainer’s new code is
MIT-licensed; vendor-derived and third-party material retains its own terms.
