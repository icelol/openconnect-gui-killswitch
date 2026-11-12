#!/bin/sh
# Reproducible dependency build; no system installation or trust-store changes.
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
deps="$project_dir/build/deps"
prefix="$deps/openconnect"
source="$deps/source/openconnect-9.21"
archive="$deps/openconnect-9.21.tar.gz"
patch_file="$project_dir/patches/openconnect-9.21-tls12-policy.patch"
expected='5b32369467db6e5f317aa1ed12cfcbb81ed00bdbc765450b6bfcbdc300944a58'
mkdir -p "$deps/source"
patch_hash=$(shasum -a 256 "$patch_file" | cut -d ' ' -f 1)
ucrt_patch="$project_dir/patches/openconnect-9.21-ucrt.patch"
patch_hash="$patch_hash:$(shasum -a 256 "$ucrt_patch" | cut -d ' ' -f 1)"
stamp="$expected:$patch_hash:$(uname -s):${MACOSX_DEPLOYMENT_TARGET:-}:${OCGUI_LZ4_PREFIX:-}:lz4-identity-v1"
if [ -f "$prefix/ocgui-build-stamp" ] && [ -f "$prefix/include/openconnect.h" ] \
    && [ "$(cat "$prefix/ocgui-build-stamp")" = "$stamp" ]; then
    printf '%s\n' 'Pinned OpenConnect + TLS compatibility API is ready.'
    exit 0
fi
if [ -n "${OCGUI_LZ4_PREFIX:-}" ]; then
    # An explicit compatible keg may be required after a host package-manager
    # upgrade raises the deployment floor. Do not relink the global Homebrew keg.
    mkdir -p "$deps/pkgconfig"
    /usr/bin/awk -v prefix="$OCGUI_LZ4_PREFIX" '
        /^prefix=/ { print "prefix=" prefix; next } { print }
    ' "$OCGUI_LZ4_PREFIX/lib/pkgconfig/liblz4.pc" > "$deps/pkgconfig/liblz4.pc"
elif [ -f "$deps/pkgconfig/liblz4.pc" ]; then
    rm -f "$deps/pkgconfig/liblz4.pc"
fi
PKG_CONFIG_PATH="$deps/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
export PKG_CONFIG_PATH
if [ ! -f "$archive" ]; then
    curl --fail --location --retry 3 --connect-timeout 10 --max-time 240 \
        'https://www.infradead.org/openconnect/download/openconnect-9.21.tar.gz' -o "$archive"
fi
actual=$(shasum -a 256 "$archive" | cut -d ' ' -f 1)
if [ "$actual" != "$expected" ]; then
    printf '%s\n' 'OpenConnect source SHA-256 mismatch.' >&2; exit 1
fi
# Only this pinned, generated dependency directory is replaced.
if [ -d "$source" ]; then rm -rf "$source"; fi
tar -xzf "$archive" -C "$deps/source"
patch -d "$source" -p1 < "$patch_file"
patch -d "$source" -p1 < "$ucrt_patch"
case "$(uname -s)" in
    MINGW*|MSYS*) vpnc_script='vpnc-script.js' ;;
    *) vpnc_script='/etc/vpnc/vpnc-script' ;;
esac
cd "$source"
./configure --prefix="$prefix" --with-gnutls --without-openssl --without-libproxy \
    --without-libpskc --without-libpcsclite --with-vpnc-script="$vpnc_script" \
    --disable-nls --disable-static --enable-shared \
    CFLAGS="-O2 -ffile-prefix-map=$source=."
make -j 6 libopenconnect.la
make install-libLTLIBRARIES install-includeHEADERS install-pkgconfigDATA
if [ "$(uname -s)" = Darwin ] && [ -n "${OCGUI_LZ4_PREFIX:-}" ]; then
    # Homebrew kegs retain an opt install name. Pin the explicit compatible input
    # so macdeployqt cannot silently substitute the active, newer opt keg.
    lz4_library="$OCGUI_LZ4_PREFIX/lib/liblz4.1.dylib"
    lz4_identity=$(/usr/bin/otool -D "$lz4_library" | /usr/bin/sed -n '2p')
    [ -n "$lz4_identity" ] || { echo 'Missing LZ4 install name' >&2; exit 1; }
    /usr/bin/install_name_tool -change "$lz4_identity" "$lz4_library" "$prefix/lib/libopenconnect.5.dylib"
fi
printf '%s\n' "$stamp" > "$prefix/ocgui-build-stamp"
