#!/bin/sh
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
release_version=$(cat "$project_dir/VERSION")
app=${1:?Usage: build-macos-installer.sh /path/to/OpenConnect-GUI-KillSwitch.app}
dist_dir="$project_dir/dist"
mkdir -p "$dist_dir"
stage=$(mktemp -d "$dist_dir/pkg-stage.XXXXXX")
trap 'rm -rf "$stage"' EXIT HUP INT TERM
payload="$stage/root"
scripts="$stage/scripts"
remove_scripts="$stage/remove-scripts"
resources="$stage/resources"
support="$payload/Library/Application Support/OpenConnect-GUI-KillSwitch"
runtime="$payload/Library/PrivilegedHelperTools/OpenConnect-KillSwitch"
mkdir -p "$payload/Applications" "$payload/Library/LaunchDaemons" "$support" "$scripts" "$runtime" "$remove_scripts" "$resources"
ditto --norsrc --noextattr --noqtn --noacl "$app" "$payload/Applications/OpenConnect-GUI-KillSwitch.app"
# A launchd root executable must live outside the admin-writable /Applications
# directory. Keep its complete runtime under a root-owned protected parent.
ditto --norsrc --noextattr --noqtn --noacl "$app" "$runtime/Runtime.app"
# Preserve the v5 helper's bundle identity at this fixed path. Changing it makes
# Installer put the new runtime in Runtime.localized instead of replacing v5,
# even when BundleIsRelocatable is false. The launchd SERVICE label is separate.
/usr/libexec/PlistBuddy -c 'Set :CFBundleIdentifier net.openconnect-vpn.gui.killswitch.boot' "$runtime/Runtime.app/Contents/Info.plist"
/usr/libexec/PlistBuddy -c 'Add :LSBackgroundOnly bool true' "$runtime/Runtime.app/Contents/Info.plist"
codesign --force --deep --sign - "$runtime/Runtime.app"
codesign --verify --deep --strict "$runtime/Runtime.app"
cp -X "$project_dir/scripts/installer/net.openconnect-vpn.killswitch.service.plist" "$payload/Library/LaunchDaemons/"
cp -X "$project_dir/scripts/installer/net.openconnect-vpn.killswitch.gui.plist" "$support/"
cp -X "$project_dir/scripts/recover-killswitch.sh" "$support/recover-killswitch.sh"
cp -X "$project_dir/scripts/clean-macos-all.sh" "$support/clean-macos-all.sh"
cp -X "$project_dir/README.md" "$support/README.md"
cp -X "$project_dir/README.ru.md" "$support/README.ru.md"
cp -X "$project_dir/VERSION" "$support/VERSION"
cp -X "$project_dir/scripts/installer/preinstall" "$scripts/preinstall"
cp -X "$project_dir/scripts/installer/postinstall" "$scripts/postinstall"
chmod 755 "$scripts/preinstall" "$scripts/postinstall" "$support/recover-killswitch.sh" "$support/clean-macos-all.sh"
chmod 644 "$payload/Library/LaunchDaemons/"*.plist "$support/"*.plist
# Never let Installer relocate this bundle to a development/dist copy, and
# replace an earlier local build even when its upstream version is identical.
python3 - "$stage/components.plist" <<'PY'
import plistlib
import sys
path = sys.argv[1]
components = [dict(RootRelativeBundlePath=bundle, BundleIsRelocatable=False,
    BundleIsVersionChecked=False, BundleOverwriteAction='upgrade',
    BundleHasStrictIdentifier=True) for bundle in (
        'Applications/OpenConnect-GUI-KillSwitch.app',
        'Library/PrivilegedHelperTools/OpenConnect-KillSwitch/Runtime.app')]
with open(path, 'wb') as stream:
    plistlib.dump(components, stream)
PY
pkgbuild --root "$payload" --scripts "$scripts" --ownership recommended \
    --component-plist "$stage/components.plist" \
    --identifier net.openconnect-vpn.gui.killswitch --version "$release_version" \
    --install-location / "$stage/Install.pkg"
cp -X "$project_dir/scripts/clean-macos-all.sh" "$remove_scripts/postinstall"
chmod 755 "$remove_scripts/postinstall"
pkgbuild --nopayload --scripts "$remove_scripts" \
    --identifier net.openconnect-vpn.gui.killswitch.remove --version "$release_version" \
    "$stage/Remove.pkg"
cp -X "$project_dir/scripts/installer/welcome.html" "$resources/"
product="$dist_dir/OpenConnect-GUI-KillSwitch-Setup-$(uname -m)-v$release_version.pkg"
productbuild --distribution "$project_dir/scripts/installer/Distribution.xml" \
    --package-path "$stage" --resources "$resources" "$product"
(cd "$dist_dir" && shasum -a 256 "$(basename "$product")") > "$product.sha256"
