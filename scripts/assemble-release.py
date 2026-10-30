#!/usr/bin/env python3
"""Assemble or verify a complete offline release. No credentials or network."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--dist', type=Path, default=root / 'dist')
parser.add_argument('--check', action='store_true')
args = parser.parse_args()
dist = args.dist.resolve()
version = (root / 'VERSION').read_text().strip()
commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()

def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()

manifest_path = dist / 'RELEASE-MANIFEST.json'
if args.check:
    manifest = json.loads(manifest_path.read_text())
    assert manifest['version'] == version and manifest['commit'] == commit
    for item in manifest['files']:
        assert Path(item['name']).name == item['name']
        path = dist / item['name']
        assert path.stat().st_size == item['bytes'] and digest(path) == item['sha256'], item['name']
    for line in (dist / 'SHA256SUMS').read_text().splitlines():
        value, name = line.split(maxsplit=1)
        assert Path(name).name == name and digest(dist / name) == value, name
    print('PASS: complete release manifest and public-file SHA-256')
else:
    assert not subprocess.check_output(['git', 'status', '--porcelain'], cwd=root).strip(), 'Commit the source before release assembly'
    binaries = ['OpenConnect-GUI-KillSwitch-Setup-windows-x64-v' + version + '.exe',
                'OpenConnect-GUI-KillSwitch-Setup-arm64-v' + version + '.pkg',
                'OpenConnect-GUI-KillSwitch-arm64-v' + version + '.dmg']
    sources = ['openconnect-gui-killswitch-v' + version + '-source.zip',
               'openconnect-9.21-ocgui-v' + version + '-source.tar.gz',
               'windows-dependency-sources-v' + version + '.tar.gz',
               'macos-dependency-sources-v' + version + '.tar.gz']
    reports = ['windows-verification.json', 'MACOS-VERIFICATION.json',
               'PRIVACY-VERIFICATION.json', 'SOURCE-INPUTS-VERIFICATION.json']
    for name in binaries + sources + reports:
        assert (dist / name).is_file(), 'Missing release file: ' + name
    win = json.loads((dist / reports[0]).read_text())
    assert win['version'] == version and win['commit'] == commit and win['complete'] is True
    for name in reports[1:]:
        report = json.loads((dist / name).read_text())
        assert report['version'] == version and report['commit'] == commit and report['complete'] is True, name
    files = [{'name': name, 'bytes': (dist / name).stat().st_size, 'sha256': digest(dist / name)}
             for name in binaries + sources + reports]
    manifest = {'schema': 1, 'version': version, 'commit': commit,
                'platforms': ['Windows x64', 'macOS Apple Silicon 27+'], 'files': files}
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')
    names = binaries + sources + reports + [manifest_path.name]
    (dist / 'SHA256SUMS').write_text(''.join(digest(dist / name) + '  ' + name + '\n' for name in names))
    for name in binaries + sources + ['RELEASE-MANIFEST.json', 'SHA256SUMS']:
        (dist / (name + '.sha256')).write_text(digest(dist / name) + '  ' + name + '\n')
    print('PASS: assembled release ' + version + '; installers, source, evidence and SHA-256')
