#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
LC_ALL=C
export LC_ALL

if [ "$(id -u)" != 0 ]; then
    exec /usr/bin/sudo /bin/sh "$0" "$@"
fi

anchor='com.apple/000.openconnect-gui-killswitch'
state='/var/run/openconnect-gui-killswitch/state.json'
boot='/Library/Application Support/OpenConnect-GUI-KillSwitch/boot.json'
daemon='/Library/LaunchDaemons/net.openconnect-vpn.killswitch.service.plist'
binary='/Library/PrivilegedHelperTools/OpenConnect-KillSwitch/Runtime.app/Contents/MacOS/OpenConnect-GUI-KillSwitch'

# Stop this client's in-flight workers before clearing its persistent rules.
# No Cisco/other VPN process is matched.
/bin/launchctl bootout system/net.openconnect-vpn.killswitch.service 2>/dev/null || :
/usr/bin/killall -TERM OpenConnect-GUI-KillSwitch 2>/dev/null || :

# Explicit recovery also disables protection at the next boot. A failed boot
# job must not immediately re-arm the firewall behind the operator's back.
/bin/launchctl bootout system/net.openconnect-vpn.killswitch.boot 2>/dev/null || :
if [ -f "$boot" ] && [ ! -L "$boot" ]; then
    /usr/bin/plutil -replace enabled -bool false "$boot"
fi

# Never flush the global ruleset and never disable PF globally.
/sbin/pfctl -a "$anchor" -f /dev/null
remaining=$(/sbin/pfctl -a "$anchor" -sr)
if [ -n "$remaining" ]; then
    printf '%s\n' 'Kill switch rules are still present. PF reference was retained.' >&2
    exit 1
fi

if [ -f "$state" ] && [ ! -L "$state" ]; then
    token=$(/usr/bin/plutil -extract token raw -o - "$state")
    case "$token" in
        '') ;;
        *[!0-9]*) printf '%s\n' 'Invalid PF token. No PF reference was released.' >&2; exit 1 ;;
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
printf '%s\n' 'This client’s kill switch rules were removed. Other PF rules were retained.'

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
