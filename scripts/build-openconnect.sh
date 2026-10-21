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
stamp="$expected:$patch_hash:$(uname -s)"
if [ -f "$prefix/ocgui-build-stamp" ] && [ -f "$prefix/include/openconnect.h" ] \
    && [ "$(cat "$prefix/ocgui-build-stamp")" = "$stamp" ]; then
    printf '%s\n' 'Pinned OpenConnect + TLS compatibility API is ready.'
    exit 0
fi
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
printf '%s\n' "$stamp" > "$prefix/ocgui-build-stamp"
