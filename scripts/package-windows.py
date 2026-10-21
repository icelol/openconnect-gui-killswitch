#!/usr/bin/env python3
"""Stage pinned runtime files and recursively resolve PE imports from MSYS2."""
import hashlib
import os
import pathlib
import re
import shutil
import subprocess
import sys
import zipfile

root = pathlib.Path(__file__).resolve().parent.parent
stage = pathlib.Path(sys.argv[1])
prefix = pathlib.Path(os.environ.get('MINGW_PREFIX', '/ucrt64'))
if os.name == 'nt' and str(prefix).startswith('/'):
    prefix = pathlib.Path(subprocess.check_output(['cygpath', '-w', str(prefix)], text=True).strip())
if '--dependencies' not in sys.argv:
    with zipfile.ZipFile(root / 'wintun/wintun-0.14.1.zip') as archive:
        member = next(name for name in archive.namelist() if name.endswith('/bin/amd64/wintun.dll'))
        (stage / 'wintun.dll').write_bytes(archive.read(member))
        license_name = next(name for name in archive.namelist() if name.lower().endswith('/license.txt'))
        (stage / 'wintun-LICENSE.txt').write_bytes(archive.read(license_name))
    ca = pathlib.Path('/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem')
    if not ca.is_file():
        ca = pathlib.Path(subprocess.check_output(['cygpath', '-w', str(ca)], text=True).strip())
    shutil.copy2(ca, stage / 'ca-bundle.crt')
    for name in ('LICENSE.txt', 'README.md', 'README.ru.md', 'VERSION', 'UPSTREAM.md', 'AUTHORS'):
        shutil.copy2(root / name, stage / name)
    (stage/'docs').mkdir(exist_ok=True)
    for name in ('windows.md','windows.ru.md','windows-architecture.md','macos-killswitch.md'):
        shutil.copy2(root/'docs'/name,stage/'docs'/name)
    (stage / 'licenses').mkdir(exist_ok=True)
    for source in (root / 'docs/third-party').glob('*'):
        if source.is_file(): shutil.copy2(source, stage / 'licenses' / source.name)
    for source in (root/'patches').glob('openconnect-9.21-*.patch'):
        shutil.copy2(source, stage/'licenses'/source.name)

search = [root / 'build/deps/openconnect/bin', prefix / 'bin']
system = pathlib.Path(os.environ.get('SystemRoot', 'C:/Windows')) / 'System32'
system_names = {p.name.lower() for p in system.glob('*.dll')}
seen = set()
pending = [p for p in stage.rglob('*') if p.suffix.lower() in ('.dll', '.exe')]
while pending:
    binary = pending.pop()
    if binary.resolve() in seen: continue
    seen.add(binary.resolve())
    output = subprocess.check_output(['objdump', '-p', str(binary)], text=True, errors='replace')
    for name in re.findall(r'DLL Name:\s*([^\r\n]+)', output):
        name = name.strip()
        if name.lower().startswith(('api-ms-win-', 'ext-ms-win-')) or name.lower() in system_names: continue
        existing = next((p for p in stage.glob('*') if p.name.lower() == name.lower()), None)
        if existing is not None:
            pending.append(existing); continue
        source = next((p for folder in search for p in folder.glob('*') if p.name.lower() == name.lower()), None)
        if source is None: raise SystemExit('Unresolved PE dependency: ' + binary.name + ' -> ' + name)
        target = stage / name
        shutil.copy2(source, target); pending.append(target)
print('PASS: recursively staged', len(seen), 'native PE files')

# Preserve licenses from the packages that actually supplied bundled DLLs.
# Keep their exact versions and hashes so source/build provenance is reviewable.
if '--dependencies' in sys.argv:
    import json
    packages={}; originals=[]
    for binary in sorted(stage.rglob('*.dll')):
        original=next((p for folder in search for p in folder.glob('*') if p.name.lower()==binary.name.lower()),None)
        if original is None or prefix not in original.parents:continue
        originals.append(str(original))
    # Batch package ownership lookup; spawning MSYS2 processes per DLL is slow.
    package_names=set(subprocess.check_output(['pacman','-Qoq',*originals],text=True).splitlines())
    for package in sorted(package_names):
        version=subprocess.check_output(['pacman','-Q',package],text=True).strip()
        metadata=subprocess.check_output(['pacman','-Qi',package],text=True)
        files=subprocess.check_output(['pacman','-Qlq',package],text=True).splitlines()
        destination=stage/'licenses'/package;destination.mkdir(parents=True,exist_ok=True)
        (destination/'PACKAGE.txt').write_text(metadata,encoding='utf-8')
        for value in files:
            if '/share/licenses/' not in value or value.endswith('/'):continue
            source=pathlib.Path(subprocess.check_output(['cygpath','-w',value],text=True).strip())
            if source.is_file():
                relative=pathlib.PurePosixPath(value.split('/share/licenses/',1)[1])
                target=destination/pathlib.Path(*relative.parts);target.parent.mkdir(parents=True,exist_ok=True)
                shutil.copy2(source,target)
        packages[package]={'version':version,'metadata':'licenses/'+package+'/PACKAGE.txt',
            'recipe':'https://github.com/msys2/MINGW-packages','package':'https://packages.msys2.org/package/'+package}
    provenance={'packages':packages,'files':{str(p.relative_to(stage)):hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(stage.rglob('*')) if p.suffix.lower() in ('.exe','.dll')}}
    (stage/'DEPENDENCIES.json').write_text(json.dumps(provenance,indent=2)+'\n',encoding='utf-8')
