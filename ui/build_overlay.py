#!/usr/bin/env python3
"""Build an isolated native UI source patch; never connect to or flash a Deco."""

import difflib
import hashlib
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
PROJECT = HERE.parents[1]
STOCK = PROJECT / "analysis/crypto-research/rootfs"
OVERLAY = HERE / "overlay"
WEB = Path("www/webpages")


def load_json(relative):
    return json.loads((STOCK / WEB / relative).read_text())


def emit(relative, content):
    destination = OVERLAY / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(content)


def main():
    manifest = json.loads((HERE / "ui-integration.json").read_text())
    if manifest["version"] != 1:
        raise ValueError("Unknown UI integration manifest version.")
    for section, filename in (("modules", "config/modules.json"),
                              ("models", "config/models.json")):
        entries = load_json(filename)
        for name, value in manifest[section].items():
            if name in entries:
                raise ValueError("Refusing to replace an existing stock registration: " + name)
            entries[name] = value
        emit(WEB / filename, json.dumps(entries, indent=2) + "\n")

    for navigation in manifest["navigation"]:
        entries = load_json(navigation["path"])
        parent = next(item for item in entries if item["name"] == navigation["parent"])
        children = parent["children"]
        if any(item["name"] == navigation["item"]["name"] for item in children):
            raise ValueError("Stock navigation already contains the proposed module.")
        index = next(index for index, item in enumerate(children)
                     if item["name"] == navigation["after"])
        children.insert(index + 1, navigation["item"])
        emit(WEB / navigation["path"], json.dumps(entries, indent=4) + "\n")

    locale = manifest["locale"]
    original = (STOCK / WEB / locale["path"]).read_text()
    additions = {"MENU_ITEMS_NAME": locale["menu"], **locale["groups"]}
    extension = ("\n;(function($){$.extend(true,$.su.CHAR,"
                 + json.dumps(additions, separators=(",", ":")) + ");})(jQuery);\n")
    emit(WEB / locale["path"], original + extension)

    files = []
    diffs = []
    for path in sorted(OVERLAY.rglob("*")):
        if not path.is_file():
            continue
        if path.is_symlink():
            raise ValueError("Overlay files must not be symlinks.")
        relative = path.relative_to(OVERLAY)
        baseline = STOCK / relative
        before = baseline.read_bytes() if baseline.is_file() else b""
        after = path.read_bytes()
        files.append({
            "path": str(relative), "new": not baseline.is_file(),
            "stock_sha256": hashlib.sha256(before).hexdigest() if baseline.is_file() else None,
            "patched_sha256": hashlib.sha256(after).hexdigest(), "bytes": len(after),
        })
        old_lines = before.decode("utf-8").splitlines(keepends=True)
        new_lines = after.decode("utf-8").splitlines(keepends=True)
        generated = difflib.unified_diff(
            old_lines, new_lines, fromfile="a/" + str(relative) if baseline.is_file() else "/dev/null",
            tofile="b/" + str(relative), n=2 if path.suffix != ".js" else 0)
        for line in generated:
            if line.endswith("\n"):
                diffs.append(line)
            else:
                diffs.extend((line + "\n", "\\ No newline at end of file\n"))
    (HERE / "vlan-status.patch").write_text("".join(diffs))
    report = {"target": "XE75 Pro V3 1.5.0 Build 20260603 Rel. 15804",
              "purpose": "Authenticated read-only VLAN status page; no device configuration writes",
              "deployment_receipt": "analysis/native-ui-runtime/deployment.json", "files": files}
    (HERE / "patch-plan.json").write_text(json.dumps(report, indent=2) + "\n")
    print("Built source overlay and unified diff for", len(files), "files. No device changes.")


if __name__ == "__main__":
    main()
