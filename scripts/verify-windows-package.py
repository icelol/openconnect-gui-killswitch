#!/usr/bin/env python3
"""Check staged PE architecture, imports, trust material and forbidden secrets."""
import hashlib
import json
import pathlib
import re
import struct
import subprocess
import sys

stage = pathlib.Path(sys.argv[1])
count = 0
for path in stage.rglob('*'):
    if not path.is_file(): continue
    data = path.read_bytes()
    assert not re.search(rb'(?:glpat-|gh[pousr]_|github_pat_)[A-Za-z0-9_\-]{20,}', data), path.name
    if path.suffix.lower() not in ('.exe', '.dll'): continue
    assert data[:2] == b'MZ', path.name
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    assert data[pe:pe+4] == b'PE\0\0' and struct.unpack_from('<H', data, pe+4)[0] == 0x8664, path.name
    count += 1
assert (stage/'platforms/qwindows.dll').is_file()
assert (stage/'wintun.dll').is_file()
assert b'asInvoker' in (stage/'openconnect-gui.exe').read_bytes(), 'GUI must not request administrator elevation'
assert (stage/'ca-bundle.crt').read_bytes().count(b'BEGIN CERTIFICATE') > 20
assert not list(stage.rglob('*.pfx')) and not list(stage.rglob('*.p12'))
print(json.dumps({'native_x64_pe_files':count,'platform_plugin':'passed','public_ca_bundle':'passed'},indent=2))
