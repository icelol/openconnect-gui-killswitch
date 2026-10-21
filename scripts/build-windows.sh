#!/bin/sh
# Native UCRT64 build; invoke from MSYS2, not a Unix cross-compiler.
set -eu
case "$(uname -s)" in MINGW*|MSYS*) ;; *) printf '%s\n' 'Use an MSYS2 UCRT64 shell on Windows.' >&2;exit 1;;esac
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$project_dir"
sh scripts/build-openconnect.sh
export PKG_CONFIG_PATH="$project_dir/build/deps/openconnect/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DOCGUI_SYSTEM_DEPS=ON -DBUILD_TESTING=ON
cmake --build build -j 4
ctest --test-dir build --output-on-failure
stage="$project_dir/dist/windows-stage"
if [ -d "$stage" ]; then rm -rf "$stage"; fi
mkdir -p "$stage" "$project_dir/dist"
cp build/bin/openconnect-gui.exe "$stage/"
cp build/external/vpnc-script.js "$stage/"
python3 scripts/package-windows.py "$stage"
if command -v windeployqt6 >/dev/null 2>&1;then deploy=windeployqt6;else deploy=windeployqt;fi
"$deploy" --release --no-translations --no-opengl-sw --compiler-runtime --dir "$stage" "$stage/openconnect-gui.exe"
python3 scripts/package-windows.py "$stage" --dependencies
makensis -DVERSION="$(cat VERSION)" -DSTAGE="$(cygpath -w "$stage")" \
    -DOUTFILE="$(cygpath -w "$project_dir/dist/OpenConnect-GUI-KillSwitch-Setup-windows-x64-v$(cat VERSION).exe")" nsis/windows-killswitch.nsi
python3 scripts/verify-windows-package.py "$stage"
python3 scripts/package-openconnect-source.py
python3 - <<'PY'
import hashlib, pathlib
for path in pathlib.Path('dist').iterdir():
    if path.name.endswith(('.exe', '-source.tar.gz')):
        path.with_name(path.name+'.sha256').write_text(hashlib.sha256(path.read_bytes()).hexdigest()+'  '+path.name+'\n')
PY
