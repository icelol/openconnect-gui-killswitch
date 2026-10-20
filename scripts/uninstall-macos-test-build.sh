#!/bin/sh
# Remove only this project's installed prototype and its own PF reference.
# Cisco Secure Client, other VPNs, /etc/pf.conf and global PF rules stay intact.
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
LC_ALL=C
export LC_ALL

# Child mode handles only validated, project-owned test bundles, using the
# desktop user's rights for the move into Trash.
if [ "${1:-}" = --trash-test-copies ]; then
    shift
    copy_uid=$1; copy_home=$2; trash=$3; shift 3
    copy_user=$(/usr/bin/id -nu "$copy_uid")
    for app in "$@"; do
        case "$app" in
            "$copy_home/Documents/openconnect-gui-killswitch/"*|"$copy_home/Downloads/"*|"$copy_home/Applications/"*|"$copy_home/Documents/openconnect-gui-killswitch-public/"*) ;;
            *) continue ;;
        esac
        identifier=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$app/Contents/Info.plist" 2>/dev/null || :)
        case "$identifier" in
            net.openconnect-vpn.gui.killswitch|net.openconnect-vpn.gui.killswitch.boot|net.openconnect-vpn.gui.killswitch.service) ;;
            *) continue ;;
        esac
        /bin/launchctl asuser "$copy_uid" /usr/bin/sudo -u "$copy_user" /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -u "$app" 2>/dev/null || :
        count=1
        destination="$trash/$(basename "$app")"
        while [ -e "$destination" ]; do count=$((count + 1)); destination="$trash/copy-$count-$(basename "$app")"; done
        /bin/launchctl asuser "$copy_uid" /usr/bin/sudo -u "$copy_user" /bin/mv "$app" "$destination"
        printf 'Test copy moved to Trash: %s -> %s\n' "$app" "$destination"
    done
    exit 0
fi

if [ "${1:-}" = --dry-run ]; then
    printf '%s\n' 'DRY RUN: no processes, files, services or PF rules will be changed.' \
        'Scope: OpenConnect-GUI-KillSwitch app, own helpers, launchd jobs, own PF anchor/token, preferences, logs, caches, receipts.' \
        'Own test app copies under the current user project/Downloads/Applications will move to Trash.' \
        'Project source files, PKG/DMG installers, shared Homebrew libraries and Cisco/other VPNs are retained.'
    exit 0
fi

if [ "$(id -u)" != 0 ]; then
    exec /usr/bin/sudo /bin/sh "$0" "$@"
fi

anchor='com.apple/000.openconnect-gui-killswitch'
runtime='/var/run/openconnect-gui-killswitch'
state="$runtime/state.json"
desktop_uid=$(/usr/bin/stat -f '%u' /dev/console)
desktop_home='/var/empty'
if [ "$desktop_uid" -ge 500 ]; then
    desktop_user=$(/usr/bin/id -nu "$desktop_uid")
    desktop_home=$(/usr/bin/dscl . -read "/Users/$desktop_user" NFSHomeDirectory | /usr/bin/cut -d ' ' -f 2-)
fi

printf '%s\n' 'Stopping OpenConnect test autostart and GUI...'
/bin/launchctl bootout system/net.openconnect-vpn.killswitch.boot 2>/dev/null || :
/bin/launchctl bootout system/net.openconnect-vpn.killswitch.service 2>/dev/null || :
/bin/launchctl bootout "gui/$desktop_uid/net.openconnect-vpn.killswitch.gui" 2>/dev/null || :
/usr/bin/killall -TERM OpenConnect-GUI-KillSwitch 2>/dev/null || :

# No global PF reload, disable, rules/state flush, or changes to Cisco anchors.
printf '%s\n' 'Removing only the OpenConnect test firewall rules...'
/sbin/pfctl -a "$anchor" -f /dev/null
remaining=$(/sbin/pfctl -a "$anchor" -sr)
if [ -n "$remaining" ]; then
    printf '%s\n' 'ERROR: own PF rules remain; installed recovery files retained.' >&2
    exit 1
fi
if [ -f "$state" ] && [ ! -L "$state" ]; then
    token=$(/usr/bin/plutil -extract token raw -o - "$state")
    case "$token" in
        '') ;;
        *[!0-9]*) printf '%s\n' 'ERROR: invalid saved PF reference; recovery files retained.' >&2; exit 1 ;;
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
fi
printf '%s\n' 'PASS: own PF rules cleared; own enable reference released if present.'

# Remove LaunchServices registrations before moving our old development apps.
lsregister='/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister'
if [ "$desktop_uid" -ge 500 ]; then
    /bin/launchctl asuser "$desktop_uid" /usr/bin/sudo -u "$desktop_user" "$lsregister" -u /Applications/OpenConnect-GUI-KillSwitch.app 2>/dev/null || :
    if [ -L "$desktop_home/.Trash" ]; then printf '%s\n' 'Unsafe Trash path' >&2; exit 1; fi
    if [ ! -d "$desktop_home/.Trash" ]; then /usr/bin/install -d -m 700 -o "$desktop_uid" "$desktop_home/.Trash"; fi
    trash="$desktop_home/.Trash/OpenConnect-cleanup-$(date +%Y%m%d-%H%M%S)-$$"
    /usr/bin/install -d -m 700 -o "$desktop_uid" "$trash"
    for search in "$desktop_home/Documents/openconnect-gui-killswitch" "$desktop_home/Downloads" "$desktop_home/Applications" "$desktop_home/Documents/openconnect-gui-killswitch-public"; do
        if [ -d "$search" ] && [ ! -L "$search" ]; then
            /usr/bin/find "$search" -type d -name '*.app' -prune -exec /bin/sh "$0" --trash-test-copies "$desktop_uid" "$desktop_home" "$trash" {} + 2>/dev/null || printf 'Copies could not all be inspected under: %s\n' "$search" >&2
        fi
    done
fi

# Each target is an exact, project-owned path. Never remove shared parents.
for target in \
    /Applications/OpenConnect-GUI-KillSwitch.app \
    /Library/PrivilegedHelperTools/OpenConnect-KillSwitch \
    '/Library/Application Support/OpenConnect-GUI-KillSwitch' \
    /Library/LaunchDaemons/net.openconnect-vpn.killswitch.boot.plist \
    /Library/LaunchDaemons/net.openconnect-vpn.killswitch.service.plist \
    "$desktop_home/Library/LaunchAgents/net.openconnect-vpn.killswitch.gui.plist" \
    "$desktop_home/Library/Preferences/com.openconnect-gui-team.OpenConnect-GUI-KillSwitch.plist" \
    "$desktop_home/Library/Preferences/com.openconnect-gui-team.OpenConnect-GUI-KillSwitch-Preview.plist" \
    "$desktop_home/Library/Application Support/OpenConnect-GUI Team/OpenConnect VPN + Kill Switch" \
    "$desktop_home/Library/Caches/OpenConnect-GUI Team/OpenConnect VPN + Kill Switch" \
    "$desktop_home/Library/Logs/OpenConnect-GUI-KillSwitch" \
    "$desktop_home/Library/Saved Application State/net.openconnect-vpn.gui.killswitch.savedState" \
    /var/root/Library/Preferences/com.openconnect-gui-team.OpenConnect-GUI-KillSwitch.plist \
    /var/root/Library/Preferences/com.openconnect-gui-team.OpenConnect-GUI-KillSwitch-Preview.plist \
    '/var/root/Library/Application Support/OpenConnect-GUI Team/OpenConnect VPN + Kill Switch' \
    /var/log/openconnect-killswitch-boot.log \
    /var/log/openconnect-network-service.log \
    /var/log/openconnect-network-service-error.log \
    /var/log/openconnect-killswitch-boot-error.log \
    "$runtime"; do
    if [ -e "$target" ] || [ -L "$target" ]; then
        /bin/rm -rf -- "$target"
        printf 'Removed: %s\n' "$target"
    fi
done
for receipt in net.openconnect-vpn.gui.killswitch net.openconnect-vpn.gui.killswitch.remove; do
    if /usr/sbin/pkgutil --pkg-info "$receipt" >/dev/null 2>&1; then /usr/sbin/pkgutil --forget "$receipt"; fi
done
if [ "$desktop_uid" -ge 500 ]; then
    /bin/launchctl asuser "$desktop_uid" /usr/bin/sudo -u "$desktop_user" "$lsregister" -gc 2>/dev/null || :
fi

if /bin/launchctl print system/net.openconnect-vpn.killswitch.boot >/dev/null 2>&1; then
    printf '%s\n' 'ERROR: boot service is still registered.' >&2
    exit 1
fi
if /bin/launchctl print system/net.openconnect-vpn.killswitch.service >/dev/null 2>&1; then
    printf '%s\n' 'ERROR: network service is still registered.' >&2
    exit 1
fi
remaining=$(/sbin/pfctl -a "$anchor" -sr)
if [ -n "$remaining" ]; then
    printf '%s\n' 'ERROR: own PF rules reappeared.' >&2
    exit 1
fi
printf '%s\n' 'PASS: test app, helper, settings and startup removed; own PF anchor is empty.'
printf '%s\n' 'Cisco and other VPN clients were not changed.'
