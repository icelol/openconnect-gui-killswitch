# macOS network service and kill switch

See [README.md](../README.md) or [README.ru.md](../README.ru.md) for installation and use.

## Ownership and control

The GUI runs as the logged-in desktop user. A persistent root LaunchDaemon owns
libOpenConnect, the bundled network script, tunnel setup and PF rules. A protected
Unix socket accepts requests only from the designated desktop UID or root; the
client verifies the server UID with `getpeereid`.

The root-owned service configuration contains a schema version and desktop UID.
Gateways and protocols are selected from local user profiles. The service validates
HTTPS URLs, port ranges and the protocol list reported by libOpenConnect. URLs
with embedded credentials, query strings or fragments are rejected. Arbitrary
commands, script paths, client-certificate files, proxies and saved passwords are
not accepted through IPC.

Credentials are requested through a bounded challenge/response exchange. Responses
belong to the requesting client and session challenge. The service does not write
VPN passwords to files, logs or process arguments. Closing the GUI during an
unfinished authentication cancels that authentication; closing an already
connected GUI leaves the service session alive.

## Independent blocking

A fresh installation starts with blocking off. The user can enable protection even
without a profile; an empty profile installs a block with no gateway exception.
An explicit switch-off removes only this application's rules and releases its
own saved PF enable reference. Disconnect, connection failure, closing the GUI and
service restarts preserve an enabled protection policy.

An unsuccessful restoration keeps the authenticated control socket available
with an unverified/error status. It must never cause a launchd restart loop that
prevents OFF. The GUI has a separate explicit OFF button, usable with an unchecked
toggle or invalid/absent profile. `--service-disable` waits for the confirmed OFF
snapshot; `--service-ready` checks authenticated control availability separately
from the stricter `--service-status` firewall-health check.

Connect is a separate operation. A queued or repeated click must not create an
additional session. A profile may use any validated gateway and any protocol
available in the shipped libOpenConnect. Changing gateways atomically replaces
the allowlist while retaining the general block. An active VPN must be disconnected
before another session is established.

## Firewall policy

The GUI polls authenticated status every two seconds. A missing heartbeat is
reported after six seconds and the socket reconnects without replaying mutations.
Version, PID, uptime, connection phase and elapsed phase time are separate from
the confirmed PF state. Errors are inline so OFF and Cancel remain accessible.
`--service-diagnostics` and the diagnostics button read bounded root rules, Apple
child anchors and interface flags locally. They do not expose the enable reference,
recovery journal or credentials and do not upload reports. Queries run outside
the service control thread. Reports can contain local network policy.

Connection deadlines are 30 seconds for server contact, 90 after an authentication
form is submitted, and 60 for tunnel setup. Each user prompt allows 120 seconds.
A timeout does not confirm password acceptance or rejection. Cancellation leaves
service control available while the library finishes connection cleanup.

Non-quick root filters before the standard Apple hook and rules after it are
compatible: the owned anchor's final quick block decides every remaining packet.
Prior unknown anchors or quick bypasses remain rejected. OFF is confirmed by
reading back the owned anchor as empty, including after a rejected ON operation.

The application owns `com.apple/000.openconnect-gui-killswitch` and never disables
PF globally. Existing system and other-client rules are inspected; incompatible
quick bypasses are reported rather than silently replacing another product's policy.

The base policy allows loopback, DHCP and IPv6 NDP, root-owned packets to selected
VPN IPs/ports and packets on the exact tunnel interface with its assigned addresses.
It ends in a general block. There is no general LAN, mDNS or arbitrary-utun allowance.
Only the exact negotiated outer UDP ports are added when reported by OpenConnect.

Existing PF states are evaluated against the policy. The state decoder checks the
platform ABI and removes incompatible tuples using their interface, direction,
addresses, protocol and ports. It does not perform a global PF state flush.

## Endpoint DNS bootstrap

A new gateway may need DNS while the base block is already enabled. The root
service reads resolver addresses from macOS, adds temporary root-only UDP/TCP 53
rules to those addresses and requests only the selected hostname's A/AAAA records.
There is a bounded lookup deadline. No fixed external resolver is configured.

The temporary rules are not stored in the recovery journal. They are removed on
success, failure, cancellation or lookup exceptions. Their states are then pruned
under the normal policy before the gateway IP allowlist is installed. A restarted
service rebuilds its policy from persistent intent and clears temporary exceptions.
Secondary gateway names and ports requested by libOpenConnect during negotiation
are resolved and pinned as bounded session endpoints. TLS hostname validation stays
enabled. These endpoint exceptions are removed when the session ends or the service
restarts, rather than becoming permanent gateway permissions.
Normal application traffic remains blocked throughout. A local DNS proxy that
cannot reach its upstream while blocked may prevent resolution; numeric gateway
addresses or previously pinned addresses can still be used.

## Installed paths

- `/Applications/OpenConnect-GUI-KillSwitch.app`: user GUI.
- `/Library/PrivilegedHelperTools/OpenConnect-KillSwitch/Runtime.app`: protected runtime.
- `/Library/LaunchDaemons/net.openconnect-vpn.killswitch.service.plist`: root service.
- `/Library/Application Support/OpenConnect-GUI-KillSwitch`: configuration and recovery.
- `/var/run/openconnect-gui-killswitch`: protected local socket and recovery state.
- `~/Library/Logs/OpenConnect-GUI-KillSwitch`: user GUI logs.

A login agent opens the normal-user GUI. The daemon's bundle identity is kept stable
for upgrades of older builds. Installation checks utun allocation, protected storage,
read-only PF ABI inspection and actual service readiness before reporting success.
It migrates older root GUI preferences locally without putting them in the package.
No actual profiles, endpoints or credentials are distributed.

## Recovery and removal

Use the installer removal option or `scripts/clean-macos-all.sh` to remove the
application's installed components and profiles. `--dry-run` prints scope without
changing files, jobs or rules. The cleaner identifies its development app copies
by exact bundle identifiers before moving them to the current user's Trash.
It retains source files, installers, shared libraries, unrelated VPNs and PF rules.

`scripts/recover-killswitch.sh` removes this client's rules, persists OFF and
restarts the service, keeping the application and profiles. A saved PF reference
that is already absent is treated as an idempotent cleanup result; other failures
retain recovery information and are reported. Nothing uses a global `pfctl -d`.

## Validation and limits

Automated tests use injected PF/VPN sessions and a real non-mutating PF parser.
They cover state selection, first connection, duplicate commands, cancellation,
protocol and URL validation, endpoint switching and bounded DNS exception cleanup.
Packaging audits inspect actual PKG/DMG contents, signatures, dependencies and the
minimum OS required by every bundled Mach-O file.

A local build does not prove end-to-end compatibility with every vendor server.
Real VPN authentication, reconnection, sleep/wake, network changes and boot must
be checked on the target Mac. SAML browser login, arbitrary proxy configurations,
custom CA/client-certificate files and a separate switch-off password are outside
the current privileged-service implementation.

A future switch-off password should be enforced by the service, not a GUI checkbox.
Possible policies include macOS LocalAuthentication/admin authorization or an
administrator-managed root policy. Credentials or password hashes must not be
embedded in the app bundle. No separate password is enabled in this release.
