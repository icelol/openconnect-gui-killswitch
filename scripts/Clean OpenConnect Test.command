#!/bin/sh
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
report='/tmp/openconnect-cleanup-report.log'
umask 077
/bin/sh "$script_dir/uninstall-macos-test-build.sh" 2>&1 | /usr/bin/tee "$report"
printf '\nReport: %s\n' "$report"
