#!/usr/bin/env python3
"""Distribute the corresponding modified LGPL library source, without build output."""
import gzip
import hashlib
import io
import pathlib
import tarfile

root = pathlib.Path(__file__).resolve().parent.parent
version = (root / "VERSION").read_text().strip()
archive = root / "build/deps/openconnect-9.21.tar.gz"
assert hashlib.sha256(archive.read_bytes()).hexdigest() == "5b32369467db6e5f317aa1ed12cfcbb81ed00bdbc765450b6bfcbdc300944a58"
patched = {"openconnect.h", "openconnect-internal.h", "library.c", "gnutls.c", "libopenconnect.map.in", "compat.c"}
target = root / ("dist/openconnect-9.21-ocgui-v" + version + "-source.tar.gz")
target.parent.mkdir(exist_ok=True)
with tarfile.open(archive) as original, target.open("wb") as output, gzip.GzipFile(fileobj=output, mode="wb", mtime=0) as compressed, tarfile.open(fileobj=compressed, mode="w|") as destination:
    for member in original:
        relative = member.name.removeprefix("openconnect-9.21/")
        data = None
        if member.isfile():
            data = original.extractfile(member).read()
            if relative in patched:
                data = (root / "build/deps/source/openconnect-9.21" / relative).read_bytes()
            member.size = len(data)
        member.uid = member.gid = 0
        member.uname = member.gname = ""
        destination.addfile(member, io.BytesIO(data) if data is not None else None)
    for patch_name in ("openconnect-9.21-tls12-policy.patch", "openconnect-9.21-ucrt.patch"):
        patch = (root / "patches" / patch_name).read_bytes()
        member = tarfile.TarInfo("openconnect-9.21/ocgui-" + patch_name)
        member.size = len(patch); member.mode = 0o644; member.mtime = 0
        destination.addfile(member, io.BytesIO(patch))
digest = hashlib.sha256(target.read_bytes()).hexdigest()
pathlib.Path(str(target) + ".sha256").write_text(digest + "  " + target.name + "\n")
print("Created corresponding LGPL source:", target.name)
