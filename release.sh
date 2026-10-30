#!/bin/sh
# Assemble an already built release locally; no network, credentials or publishing.
set -eu
project_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
version=$(cat "$project_dir/VERSION")
if [ "$#" -gt 0 ] && [ "$1" != "$version" ]; then
    printf 'VERSION is %s; requested %s\n' "$version" "$1" >&2
    exit 1
fi
python3 "$project_dir/scripts/validate-release.py"
exec python3 "$project_dir/scripts/assemble-release.py" --dist "$project_dir/dist"
