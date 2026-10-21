#!/bin/sh
set -eu

if [ "$(uname -s)" != Darwin ]; then
    printf '%s\n' 'This build script requires macOS.' >&2
    exit 1
fi
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
release_version=$(cat "$project_dir/VERSION")
python3 "$project_dir/scripts/validate-release.py"
build_dir="$project_dir/build"
dist_dir="$project_dir/dist"
target_version=${OCGUI_DEPLOYMENT_TARGET:-"$(sw_vers -productVersion | cut -d. -f1).0"}

for program in cmake ninja macdeployqt brew python3; do
    if ! command -v "$program" >/dev/null 2>&1; then
        printf 'Missing build dependency: %s\n' "$program" >&2
        exit 1
    fi
done

sh "$project_dir/scripts/build-openconnect.sh"
PKG_CONFIG_PATH="$project_dir/build/deps/openconnect/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
export PKG_CONFIG_PATH

cmake -S "$project_dir" -B "$build_dir" -G Ninja \
    -DCMAKE_BUILD_TYPE=Release -DCMAKE_OSX_DEPLOYMENT_TARGET="$target_version"
if ! grep -q '^#define OCGUI_HAVE_TLS12_API' "$build_dir/src/config.h"; then
    printf '%s\n' 'Release requires the pinned OpenConnect compatibility API.' >&2; exit 1
fi
cmake --build "$build_dir" -j 6
ctest --test-dir "$build_dir" --output-on-failure
mkdir -p "$dist_dir"
mkdir -p "$dist_dir/.app-build.noindex"
app="$dist_dir/.app-build.noindex/OpenConnect-GUI-KillSwitch.app"
# Replacing only this build artifact is intentional; no installed app is touched.
if [ -d "$app" ]; then
    rm -rf "$app"
fi
ditto --norsrc --noextattr --noqtn --noacl "$build_dir/bin/OpenConnect-GUI-KillSwitch.app" "$app"
cp -X "$(brew --prefix ca-certificates)/share/ca-certificates/cacert.pem" "$app/Contents/Resources/ca-bundle.crt"
mkdir -p "$app/Contents/Resources/licenses"
cp -X "$project_dir/docs/third-party/pfctl-rs-MIT.txt" "$app/Contents/Resources/licenses/"
cp -X "$project_dir/docs/third-party/openconnect-LGPL-2.1.txt" "$app/Contents/Resources/licenses/"
cp -X "$project_dir/patches/openconnect-9.21-tls12-policy.patch" "$app/Contents/Resources/licenses/"
cp -X "$project_dir/patches/openconnect-9.21-ucrt.patch" "$app/Contents/Resources/licenses/"
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $release_version" "$app/Contents/Info.plist"
macdeployqt "$app" -verbose=1 -libpath="$(brew --prefix qtsvg)/lib"
codesign --force --deep --sign - "$app"
codesign --verify --deep --strict "$app"
python3 "$project_dir/scripts/verify-macos-bundle.py" "$app"
sh "$project_dir/scripts/build-macos-installer.sh" "$app"

stage=$(mktemp -d "$dist_dir/dmg-stage.XXXXXX")
trap 'rm -rf "$stage"' EXIT HUP INT TERM
cp -X "$project_dir/LICENSE.txt" "$stage/LICENSE.txt"
cp -X "$project_dir/scripts/recover-killswitch.sh" "$stage/Recover Kill Switch.command"
cp -X "$project_dir/scripts/clean-macos-all.sh" "$stage/Clean OpenConnect.command"
cp -X "$project_dir/README.md" "$stage/README.md"
cp -X "$project_dir/README.ru.md" "$stage/README.ru.md"
cp -X "$project_dir/UPSTREAM.md" "$stage/UPSTREAM.md"
cp -X "$project_dir/AUTHORS" "$stage/AUTHORS"
mkdir -p "$stage/docs"
for document in windows.md windows.ru.md windows-architecture.md macos-killswitch.md; do
    cp -X "$project_dir/docs/$document" "$stage/docs/$document"
done
cp -X "$project_dir/docs/macos-killswitch.md" "$stage/ARCHITECTURE.md"
cp -X "$dist_dir/OpenConnect-GUI-KillSwitch-Setup-$(uname -m)-v$release_version.pkg" "$stage/"
image="$dist_dir/OpenConnect-GUI-KillSwitch-$(uname -m)-v$release_version.dmg"
hdiutil create -ov -volname 'OpenConnect Kill Switch' -srcfolder "$stage" \
    -format UDZO "$image"
(cd "$dist_dir" && shasum -a 256 "$(basename "$image")") > "$image.sha256"
python3 "$project_dir/scripts/package-openconnect-source.py"
printf '\nCreated: %s\n' "$image"
