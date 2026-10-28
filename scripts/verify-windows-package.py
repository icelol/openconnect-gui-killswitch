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

# Several upstream MSYS2 packages install no license files. Their PACKAGE.txt
# metadata and recipe URLs are not substitutes for the original notices.
provenance = json.loads((stage/'DEPENDENCIES.json').read_text(encoding='utf-8'))
notices = json.loads((stage/'licenses/windows-dependency-notices.json').read_text(encoding='utf-8'))
required = {'gmp', 'gnutls', 'icu', 'libidn2', 'lz4', 'nettle', 'p11-kit'}
assert notices['schema'] == 1
assert {entry['package'] for entry in notices['dependencies']} == required
notice_count = 0
for entry in notices['dependencies']:
    package = 'mingw-w64-ucrt-x86_64-' + entry['package']
    installed = provenance['packages'][package]['version']
    # An MSYS2 packaging-only revision can change without changing the upstream
    # notices. A new upstream version requires reviewing and refreshing them.
    assert re.fullmatch(re.escape(package + ' ' + entry['upstream_version']) + r'-[0-9]+', installed), \
        'Review upstream notices after dependency update: ' + package
    assert entry['upstream_source'].startswith('https://') and entry['notices']
    for notice in entry['notices']:
        name = notice['file']
        assert pathlib.PurePath(name).name == name and name != 'PACKAGE.txt'
        data = (stage/'licenses'/name).read_bytes().replace(b'\r\n', b'\n')
        assert data and hashlib.sha256(data).hexdigest() == notice['sha256'], \
            'Missing or altered upstream notice: ' + name
        notice_count += 1
print(json.dumps({'native_x64_pe_files':count,'platform_plugin':'passed','public_ca_bundle':'passed',
    'upstream_notices':'passed','verified_upstream_notice_files':notice_count},indent=2))
