#!/usr/bin/env python3
"""Bundle notices and exact Homebrew source inputs for deployed Mach-O files."""
import hashlib
import gzip
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.parse
import urllib.request

root = Path(__file__).resolve().parents[1]
bundle = Path(sys.argv[1]).resolve()
cellar = Path(subprocess.check_output(['brew', '--cellar'], text=True).strip()).resolve()
cache = root / 'build/dependency-source-cache'
inputs = root / 'build/macos-dependency-inputs'
cache.mkdir(parents=True, exist_ok=True)
inputs.mkdir(parents=True, exist_ok=True)
resources = bundle / 'Contents/Resources'
licenses = resources / 'licenses/homebrew'
magic = {b'\xcf\xfa\xed\xfe', b'\xfe\xed\xfa\xcf', b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf'}

def sha(data):
    return hashlib.sha256(data).hexdigest()

native = []
for folder in ('Contents/Frameworks', 'Contents/PlugIns'):
    for path in (bundle / folder).rglob('*'):
        if path.is_file() and not path.is_symlink():
            with path.open('rb') as stream:
                if stream.read(4) in magic and path.name != 'libopenconnect.5.dylib':
                    native.append(path)
needed = {path.name for path in native}
index = {name: set() for name in needed}
for folder, directories, files in os.walk(cellar):
    directories[:] = [name for name in directories if name not in ('.git', 'node_modules')]
    for name in needed.intersection(files):
        path = (Path(folder) / name).resolve()
        if path.is_file():
            with path.open('rb') as stream:
                if stream.read(4) in magic:
                    index[name].add(path)
components = {}
file_map = []
for path in native:
    candidates = index[path.name]
    # Prefer the active keg, not an older installed version of the same formula.
    active = {p for p in candidates if (cellar.parent / 'opt' / p.relative_to(cellar).parts[0]).resolve()
              == cellar / Path(*p.relative_to(cellar).parts[:2])}
    if active:
        candidates = active
    assert len(candidates) == 1, 'Cannot identify the source package: ' + path.name
    original = next(iter(candidates))
    formula, installed = original.relative_to(cellar).parts[:2]
    prefix = cellar / formula / installed
    components[formula] = (installed, prefix)
    file_map.append({'file': str(path.relative_to(bundle)), 'formula': formula,
                     'original_binary_sha256': sha(original.read_bytes())})

notices_pattern = re.compile(r'^(?:licen[sc]e|copying|copyright|authors|notice)(?:[._-]|$)', re.I)
records = []
for formula, (installed, prefix) in sorted(components.items()):
    recipe_files = list((prefix / '.brew').glob('*.rb'))
    assert len(recipe_files) == 1, 'Missing exact Homebrew recipe: ' + formula
    recipe = recipe_files[0].read_bytes()
    target = inputs / formula
    target.mkdir(exist_ok=True)
    (target / 'recipe.rb').write_bytes(recipe)
    pairs = []
    pending = None
    for kind, value in re.findall(r'^\s*(url|sha256)\s+"([^"]+)"', recipe.decode(), re.M):
        if kind == 'url':
            pending = value
        elif pending and re.fullmatch('[a-f0-9]{64}', value):
            assert pending.startswith('https://') and '#{' not in pending, 'Unresolved source URL: ' + formula
            pairs.append((pending, value))
            pending = None
    assert pairs, 'Missing source archive digest: ' + formula
    source_inputs = []
    notice_data = {}
    for path in prefix.iterdir():
        if path.is_file() and notices_pattern.match(path.name):
            notice_data[path.name] = path.read_bytes()
    for number, (url, expected) in enumerate(pairs):
        cached = cache / expected
        if not cached.is_file():
            print('Fetching source input: ' + formula + ' ' + str(number + 1), flush=True)
            request = urllib.request.Request(url, headers={'User-Agent': 'OpenConnect-release-source-inputs'})
            with urllib.request.urlopen(request, timeout=120) as response:
                value = response.read()
            assert sha(value) == expected, 'Source input SHA-256 mismatch: ' + formula
            cached.write_bytes(value)
        value = cached.read_bytes()
        assert sha(value) == expected, 'Cached source SHA-256 mismatch: ' + formula
        name = expected[:12] + '-' + (Path(urllib.parse.urlparse(url).path).name or 'source')
        shutil.copy2(cached, target / name)
        source_inputs.append({'file': name, 'url': url, 'sha256': expected})
        if number == 0:
            try:
                with tarfile.open(fileobj=io.BytesIO(value)) as archive:
                    for member in archive:
                        relative = Path(member.name)
                        if not member.isfile() or member.size > 1024 * 1024 or '..' in relative.parts:
                            continue
                        if notices_pattern.match(relative.name) or 'LICENSES' in relative.parts:
                            content = archive.extractfile(member).read()
                            if content:
                                notice_data['upstream/' + str(Path(*relative.parts[1:]))] = content
            except tarfile.ReadError:
                assert notice_data, 'Cannot extract required license notices: ' + formula
    assert notice_data, 'No upstream notices found: ' + formula
    for name, value in notice_data.items():
        destination = licenses / formula / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(value)
    receipt = json.loads((prefix / 'INSTALL_RECEIPT.json').read_text())
    record = {'formula': formula, 'installed_version': installed,
              'recipe': formula + '/recipe.rb', 'recipe_sha256': sha(recipe),
              'tap_git_head': receipt.get('source', {}).get('tap_git_head'),
              'source_inputs': source_inputs,
              'notice_files': [{'file': name, 'sha256': sha(value)} for name, value in sorted(notice_data.items())]}
    (target / 'manifest.json').write_text(json.dumps(record, indent=2) + '\n')
    records.append(record)

report = {'schema': 1, 'components': records, 'native_files': file_map,
          'hash_note': 'original_binary_sha256 identifies the Homebrew input before deployment/signing rewrites',
          'modified_openconnect_source': 'Provided separately with the matching release',
          'complete': True}
(resources / 'DEPENDENCIES-MACOS.json').write_text(json.dumps(report, indent=2) + '\n')
(inputs / 'MANIFEST.json').write_text(json.dumps(report, indent=2) + '\n')
print('PASS: notices and exact source/recipe inputs for ' + str(len(records)) + ' bundled Homebrew components')

# Source inputs are a separate release asset; they contain no installed receipt,
# local ownership, absolute prefix, user settings or credentials.
version = (root / 'VERSION').read_text().strip()
commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip()
members = {}
for record in records:
    formula = record['formula']
    folder = inputs / formula
    for name in ['recipe.rb', 'manifest.json'] + [item['file'] for item in record['source_inputs']]:
        members[formula + '/' + name] = (folder / name).read_bytes()
qt_commit = '777e95ba69952f11eaec0adfb0cb987fabcdecb3'
qt_hash = '4ae03c300a5e45ea9ff534414d1c5f9405df4da04d5df9e9b8a1cd5b83331f62'
qt_cache = cache / qt_hash
qt_url = 'https://codeload.github.com/qtproject/qt-solutions/tar.gz/' + qt_commit
if not qt_cache.is_file():
    with urllib.request.urlopen(qt_url, timeout=120) as response:
        value = response.read()
    assert sha(value) == qt_hash
    qt_cache.write_bytes(value)
assert sha(qt_cache.read_bytes()) == qt_hash
members['qt-solutions/source.tar.gz'] = qt_cache.read_bytes()
members['qt-solutions/CMakeLists.txt'] = (root / 'CMake/Includes/CMakeLists_qt-solutions.cmake.in').read_bytes()
members['README.md'] = ('''# macOS dependency source inputs

Exact preferred source archives, remote patch inputs and installed Homebrew
recipes for the deployed native libraries. MANIFEST.json records upstream URLs,
SHA-256 and installed formula versions. Formula recipes preserve inline patches
and build instructions; general build tools and the macOS SDK are not included.
Use a macOS Apple Silicon build environment and the corresponding recipe to
rebuild a component. Modified OpenConnect and the GUI source are separate release
assets. The pinned QtSingleApplication source and project CMake input are included.

Libraries are dynamically linked. Replacing an ABI-compatible framework/library
requires administrator access for an installed runtime, preserving its protected
ownership and re-signing the changed bundle with an ad-hoc signature. Use the
project build scripts to package a complete replacement application instead of
changing system libraries. Turn protection OFF before stopping a working service.

The archive stores source/build inputs; it does not include local receipts,
corporate configuration, keys or profiles. Verify every member's SHA-256 against
MANIFEST.json. Its project commit/version identifies the matching GUI release.
''').encode()
source_manifest = {'schema': 1, 'version': version, 'commit': commit, 'complete': True,
                   'components': records, 'qt_solutions': {'commit': qt_commit, 'url': qt_url, 'sha256': qt_hash},
                   'files': [{'file': name, 'sha256': sha(value)} for name, value in sorted(members.items())]}
members['MANIFEST.json'] = (json.dumps(source_manifest, indent=2) + '\n').encode()
dist = root / 'dist'
dist.mkdir(exist_ok=True)
name = 'macos-dependency-sources-v' + version + '.tar.gz'
archive = dist / name
with archive.open('wb') as output, gzip.GzipFile(filename='', mode='wb', fileobj=output, mtime=0) as zipped:
    with tarfile.open(fileobj=zipped, mode='w', format=tarfile.USTAR_FORMAT) as tar:
        for member_name, value in sorted(members.items()):
            member = tarfile.TarInfo('macos-dependency-sources-v' + version + '/' + member_name)
            member.size = len(value)
            member.mode = 0o644
            tar.addfile(member, io.BytesIO(value))
(dist / (name + '.sha256')).write_text(sha(archive.read_bytes()) + '  ' + name + '\n')
print('PASS: corresponding macOS dependency sources: ' + name)
