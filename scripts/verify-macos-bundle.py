#!/usr/bin/env python3
"""Read-only audit: bundled Mach-O dependencies and truthful minimum OS."""
import json
from pathlib import Path
import plistlib
import re
import subprocess
import sys

app = Path(sys.argv[1]).resolve()
frameworks = app / "Contents/Frameworks"
executable_dir = app / "Contents/MacOS"
magic = {b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"}
failures = []
count = 0
minimum = (0,)

for path in app.rglob("*"):
    if not path.is_file() or path.is_symlink():
        continue
    with path.open("rb") as file:
        if file.read(4) not in magic:
            continue
    count += 1
    output = subprocess.check_output(["/usr/bin/otool", "-L", str(path)], text=True)
    identifiers = subprocess.check_output(["/usr/bin/otool", "-D", str(path)], text=True).splitlines()[1:]
    own_ids = {line.strip() for line in identifiers}
    for line in output.splitlines()[1:]:
        dependency = line.strip().split(" (", 1)[0]
        if dependency in own_ids:
            continue  # LC_ID_DYLIB is metadata, not a loaded dependency.
        if dependency.startswith(("/System/", "/usr/lib/")):
            continue
        if dependency.startswith("@rpath/"):
            candidate = frameworks / dependency[len("@rpath/"):]
        elif dependency.startswith("@executable_path/"):
            candidate = executable_dir / dependency[len("@executable_path/"):]
        elif dependency.startswith("@loader_path/"):
            candidate = path.parent / dependency[len("@loader_path/"):]
        else:
            failures.append(f"{path.relative_to(app)}: external dependency {dependency}")
            continue
        if not candidate.is_file():
            failures.append(f"{path.relative_to(app)}: missing dependency {dependency}")
    build = subprocess.check_output(["/usr/bin/xcrun", "vtool", "-show-build", str(path)], text=True)
    for version in re.findall(r"\bminos\s+([0-9.]+)", build):
        minimum = max(minimum, tuple(map(int, version.split("."))))

with (app / "Contents/Info.plist").open("rb") as file:
    info = plistlib.load(file)
declared = tuple(map(int, info["LSMinimumSystemVersion"].split(".")))
if declared < minimum:
    failures.append(f"Info.plist claims {declared}, bundled binaries require {minimum}")

print(json.dumps({"macho_files": count, "minimum_macos": ".".join(map(str, minimum)),
    "declared_minimum": info["LSMinimumSystemVersion"], "errors": failures}, indent=2))
sys.exit(bool(failures) or count == 0)
