#!/usr/bin/env python3
"""Remove build-host runpaths before signing a self-contained application."""
from pathlib import Path
import plistlib
import re
import subprocess
import sys

app = Path(sys.argv[1]).resolve()
magic = {b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"}
for path in app.rglob('*'):
    if not path.is_file() or path.is_symlink(): continue
    with path.open('rb') as stream:
        if stream.read(4) not in magic: continue
    output = subprocess.check_output(['/usr/bin/otool', '-l', str(path)], text=True)
    for runpath in re.findall(r'cmd LC_RPATH\s+cmdsize \d+\s+path (.+?) \(offset', output):
        if runpath.startswith('/') and not runpath.startswith(('/System/', '/usr/lib/')):
            subprocess.run(['/usr/bin/install_name_tool', '-delete_rpath', runpath, str(path)], check=True)
info = plistlib.loads((app / 'Contents/Info.plist').read_bytes())
main = app / 'Contents/MacOS' / info['CFBundleExecutable']
output = subprocess.check_output(['/usr/bin/otool', '-l', str(main)], text=True)
if 'path @executable_path/../Frameworks (offset' not in output:
    subprocess.run(['/usr/bin/install_name_tool', '-add_rpath', '@executable_path/../Frameworks', str(main)], check=True)
