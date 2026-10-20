#!/usr/bin/env python3
"""Validate release source without macOS, credentials or network access."""
import pathlib
import plistlib
import re
import subprocess
import xml.etree.ElementTree as ET

root = pathlib.Path(__file__).resolve().parent.parent
version = (root / "VERSION").read_text().strip()
assert re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version), "Invalid VERSION"
distribution = ET.parse(root / "scripts/installer/Distribution.xml").getroot()
for package in distribution.findall("pkg-ref"):
    assert package.attrib["version"] == version, "Installer version differs from VERSION"
assert "v" + version in distribution.findtext("title"), "Installer title has wrong version"
for folder in ("src", "scripts", "tests"):
    for path in (root / folder).rglob("*"):
        if not path.is_file():
            continue
        if path.stat().st_size < 2_000_000:
            data = path.read_bytes()
            assert not re.search(rb"(?:glpat-|gh[pousr]_|github_pat_)[A-Za-z0-9_\-]{20,}", data), "Possible token: " + str(path)
            assert not re.search(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", data), "Private key: " + str(path)
        if path.suffix in (".sh", ".command") or path.name in ("preinstall", "postinstall"):
            subprocess.run(["/bin/sh", "-n", str(path)], check=True)
        elif path.suffix == ".py":
            compile(path.read_bytes(), str(path), "exec")
        elif path.suffix in (".ui", ".xml"):
            ET.parse(path)
        elif path.suffix == ".plist":
            with path.open("rb") as stream:
                plistlib.load(stream)
assert (root / "LICENSE.txt").is_file()
assert (root / "docs/third-party/pfctl-rs-MIT.txt").is_file()
assert "OCGUI_RELEASE_VERSION" in (root / "CMakeLists.txt").read_text()
assert (root / "scripts/clean-macos-all.sh").read_bytes() == (root / "scripts/uninstall-macos-test-build.sh").read_bytes()
print("PASS: release", version, "versions, shell/Python/XML/plist syntax and license files")
