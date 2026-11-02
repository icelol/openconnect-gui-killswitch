#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
LC_ALL=C
export LC_ALL

binary='/Library/PrivilegedHelperTools/OpenConnect-KillSwitch/Runtime.app/Contents/MacOS/OpenConnect-GUI-KillSwitch'
if [ "$(id -u)" != 0 ]; then
    # The authenticated root service can perform ordinary OFF without sudo.
    # Older/unavailable services fall back to the explicit administrator repair.
    if [ -x "$binary" ]; then
        capabilities=$("$binary" --service-status 2>/dev/null || :)
        case "$capabilities" in
            *'"explicitOff":true'*) if "$binary" --service-disable; then exit 0; fi ;;
        esac
    fi
    exec /usr/bin/sudo /bin/sh "$0" "$@"
fi

anchor='com.apple/000.openconnect-gui-killswitch'
state='/var/run/openconnect-gui-killswitch/state.json'
support='/Library/Application Support/OpenConnect-GUI-KillSwitch'
boot="$support/boot.json"
daemon='/Library/LaunchDaemons/net.openconnect-vpn.killswitch.service.plist'

# These parents are installed root-owned. Never follow a substituted file or
# directory while performing an administrator repair.
for path in "$support" /var/run/openconnect-gui-killswitch "$boot" "$state"; do
    if [ -L "$path" ]; then
        printf 'Unsafe recovery path: %s\n' "$path" >&2
        exit 1
    fi
done
umask 077
quarantine() {
    saved=$(/usr/bin/mktemp "$1.corrupt.XXXXXX") || return 1
    if /bin/mv -f "$1" "$saved"; then
        /bin/chmod 600 "$saved"
        printf 'Invalid recovery metadata retained at: %s\n' "$saved" >&2
    else
        /bin/rm -f "$saved"
        return 1
    fi
}

# Stop this client's in-flight workers before clearing its persistent rules.
# No Cisco/other VPN process is matched.
/bin/launchctl bootout system/net.openconnect-vpn.killswitch.service 2>/dev/null || :
/usr/bin/killall -TERM OpenConnect-GUI-KillSwitch 2>/dev/null || :

# Explicit recovery also disables protection at the next boot. A failed boot
# job must not immediately re-arm the firewall behind the operator's back.
/bin/launchctl bootout system/net.openconnect-vpn.killswitch.boot 2>/dev/null || :
boot_saved=true
if [ -d "$support" ]; then
    # Explicit recovery needs neither a valid previous JSON document nor DNS.
    # Keep malformed metadata for diagnosis, then atomically persist minimal OFF.
    if [ -f "$boot" ] && ! /usr/bin/plutil -lint "$boot" >/dev/null 2>&1; then
        quarantine "$boot" || boot_saved=false
    fi
    if temporary=$(/usr/bin/mktemp "$support/.boot-off.XXXXXX"); then
        if ! /usr/bin/printf '%s\n' '{"schema":1,"enabled":false,"host":"unconfigured.invalid","port":443,"addresses":[]}' > "$temporary" \
            || ! /bin/mv -f "$temporary" "$boot"; then
            /bin/rm -f "$temporary"
            boot_saved=false
        fi
    else
        boot_saved=false
    fi
fi

# Never flush the global ruleset and never disable PF globally.
/sbin/pfctl -a "$anchor" -f /dev/null
remaining=$(/sbin/pfctl -a "$anchor" -sr)
if [ -n "$remaining" ]; then
    printf '%s\n' 'Kill switch rules are still present. PF reference was retained.' >&2
    exit 1
fi

if [ -f "$state" ] && [ ! -L "$state" ]; then
    # Corrupt/partial metadata must not prevent removal of our rules. Never
    # guess a PF reference: retaining an unknown reference leaves PF enabled,
    # but an empty owned anchor no longer blocks this client's traffic.
    valid_token=true
    token=$(/usr/bin/plutil -extract token raw -o - "$state" 2>/dev/null) || valid_token=false
    schema=$(/usr/bin/plutil -extract schema raw -o - "$state" 2>/dev/null) || valid_token=false
    if [ "$schema" != 1 ]; then valid_token=false; fi
    case "$token" in
        '') ;;
        *[!0-9]*) valid_token=false ;;
    esac
    if [ "$valid_token" != true ]; then
        quarantine "$state"
        printf '%s\n' 'Own rules are empty; an unknown PF reference was retained without affecting other clients.' >&2
    else
    case "$token" in
        '') ;;
        *)
            if released=$(/sbin/pfctl -X "$token" 2>&1); then :
            else
                case "$released" in
                    *'DIOCSTOPREF: Invalid argument'*|*'DIOCSTOPREF: No such file or directory'*|*'pfctl: pf: token invalid'*)
                        printf '%s\n' 'Own saved PF reference is already absent.' ;;
                    *'pf not enabled'*)
                        /sbin/pfctl -s info | /usr/bin/grep -q '^Status: Disabled' || exit 1 ;;
                    *) printf '%s\n' "$released" >&2; exit 1 ;;
                esac
            fi ;;
    esac
    /bin/rm "$state"
    fi
fi
printf '%s\n' 'This client’s kill switch rules were removed. Other PF rules were retained.'
if [ "$boot_saved" != true ]; then
    printf '%s\n' 'Rules are removed, but persistent OFF could not be saved. Service remains stopped; repair protected storage before restarting it.' >&2
    exit 1
fi

# Restore a usable control panel after recovery, with explicit OFF persisted.
# Uninstallation uses its own script and deliberately does not restart anything.
if [ -f "$daemon" ] && [ ! -L "$daemon" ] && [ -x "$binary" ]; then
    /bin/launchctl bootstrap system "$daemon"
    ready=false
    for attempt in 1 2 3 4 5 6 7 8; do
        if "$binary" --service-status; then ready=true; break; fi
    done
    if [ "$ready" != true ]; then
        printf '%s\n' 'Rules are removed, but network service readiness was not confirmed.' >&2
        exit 1
    fi
    desktop_uid=$(/usr/bin/stat -f '%u' /dev/console)
    if [ "$desktop_uid" -ge 500 ]; then
        /bin/launchctl kickstart "gui/$desktop_uid/net.openconnect-vpn.killswitch.gui" 2>/dev/null || :
    fi
    printf '%s\n' 'Network service restarted with the kill switch OFF.'
fi
