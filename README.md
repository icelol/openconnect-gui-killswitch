# OpenConnect GUI + Kill Switch

**A macOS OpenConnect client with a system-wide kill switch, independent of Connect and Disconnect.**

[Русская версия](README.ru.md) · [Releases](https://github.com/icelol/openconnect-gui-killswitch/releases) · [Architecture](docs/macos-killswitch.md)

Choose your own VPN server and an OpenConnect protocol. No organization, account,
server address, internal Git remote or credentials are bundled or preconfigured.

## Features

- One switch blocks traffic outside the VPN established by this client.
- Connect remains available with the kill switch enabled.
- Choose any compatible gateway; switching gateways updates the firewall without
  temporarily restoring ordinary Internet access.
- Protocols come from the bundled libOpenConnect: AnyConnect/ocserv, Juniper,
  Pulse/Ivanti, GlobalProtect, F5, Fortinet and Array, when supported by that library.
- A privileged background service owns the VPN and firewall; the GUI runs as your user.
- Closing the GUI or disconnecting the VPN does not disable an enabled kill switch.
- Optional per-profile TLS 1.2 and legacy AnyConnect login compatibility.
- Connection progress reaches **View log**; stalled pre-login attempts time out.
- Installer includes complete removal; the DMG includes cleanup and recovery launchers.

OpenConnect is an SSL VPN client. OpenVPN `.ovpn` and WireGuard profiles require
other VPN engines and are not supported by this application. Direct connections,
username/password challenges and standard trusted TLS certificates are supported;
custom scripts, profile proxies, client-certificate files and browser SSO are not
implemented in the privileged-service flow.

## Install and use

The prebuilt package targets **Apple Silicon and macOS 27 or newer**. Homebrew and
Python are not required on the computer running the installed application.

1. Download and open the PKG from [Releases](https://github.com/icelol/openconnect-gui-killswitch/releases).
2. Choose the normal installation option. A fresh installation leaves the kill switch off.
3. Add your own VPN profile: gateway, matching protocol and optional username.
4. Enable **Block Internet without VPN** (shown as **«Блокировать интернет без VPN»**)
   when needed, then click **Connect**.
5. Enter the VPN credentials locally. Turn the switch off explicitly to restore
   ordinary access without this VPN.

| State | Network access |
| --- | --- |
| Switch off | Ordinary network access |
| Switch on, no VPN connected | Ordinary Internet and LAN traffic blocked; VPN bootstrap permitted |
| Switch on, VPN connected | Traffic through this client's selected VPN tunnel |
| VPN disconnected or connection lost | Blocking remains enabled |
| GUI closed | Service and selected protection state remain active |

The switch also works before any profile exists: it blocks ordinary traffic until
VPN connection or an explicit switch-off. An update closes this client's existing
VPN session and preserves the selected protection state. Reconnect after updating.

For gateways that stall before showing the username/password form, edit the profile
and enable **«Совместимость: только TLS 1.2»** and, if required,
**«Вход Cisco без XML POST»**. These settings are off by default and apply only to
that profile. TLS 1.0/1.1, obsolete ciphers and certificate bypasses are not enabled.
The service uses direct password forms; browser SSO is not advertised.

Network bootstrap exceptions are loopback, DHCP, IPv6 NDP and root-owned connections
to the selected gateway IPs/ports. To resolve a new gateway while blocked, the
service briefly permits **root-only DNS to macOS-configured DNS servers**, asks for
that gateway's A/AAAA records, then removes the exception and its PF states. There
is no permanent general DNS allowance or built-in third-party DNS provider.

The build uses an **ad-hoc application signature**. The PKG has no Developer ID
signature or Apple notarization. This is a community build, not an MDM-managed
Always On VPN or a protection boundary against an administrator with root access.

## Remove or recover

Select **Complete OpenConnect cleanup** (**«Полностью очистить OpenConnect»**) in the same installer to remove this
application, its background service, startup items, settings, caches, logs and
its own firewall rules. Stored profiles are deleted. Known development app copies
are moved to Trash. Other VPN clients and unrelated PF rules are retained.

The DMG also contains `Clean OpenConnect.command` and
`Recover Kill Switch.command`. Recovery removes this client's blocking rules and
restarts its service with the switch off, preserving application profiles.

The **«Снять блокировку OpenConnect»** button explicitly requests OFF, including
after a failed enable/restore and when the switch is already unchecked. A firewall
restore error leaves the service controls available and is shown in the GUI; it
does not cause a restart loop that prevents OFF. Ordinary OFF removes this client's
rules and releases its PF reference. PF may remain enabled for other applications.

Installed-client command without an administrator prompt:

```sh
/Applications/OpenConnect-GUI-KillSwitch.app/Contents/MacOS/OpenConnect-GUI-KillSwitch --service-disable
```

Success is reported only after the service confirms OFF. If the service is
unavailable, use the recovery launcher and confirm the local administrator prompt.

From a source checkout:

```sh
./scripts/clean-macos-all.sh --dry-run
./scripts/clean-macos-all.sh
# Or recover network access without uninstalling:
./scripts/recover-killswitch.sh
```

Enter the macOS administrator password only in the local system prompt.

## Build and test

On an Apple Silicon Mac with Xcode Command Line Tools, Homebrew and Python 3:

```sh
brew install cmake ninja pkg-config qtbase qtsvg qtscxml openconnect gnutls spdlog ca-certificates
export PATH="$(brew --prefix qtbase)/bin:$PATH"
./scripts/build-macos.sh
```

The script runs the tests, audits bundled libraries and minimum macOS versions,
checks signatures, then creates PKG, DMG and portable SHA-256 files in `dist/`.
It never installs the application or changes the live firewall. The intermediate
GUI bundle stays in `.app-build.noindex` to avoid duplicate search entries.
The bundled trust store comes from the vendor CA package, not local custom roots.
The build script downloads OpenConnect 9.21 with a pinned SHA-256 and applies the
small compatibility API patch. Each release includes the corresponding modified
LGPL library source archive. No system OpenConnect library is overwritten.

```sh
python3 scripts/validate-release.py
ctest --test-dir build --output-on-failure
```

Tests inject PF and VPN sessions; the real `pfctl -n` checks rule syntax.
Regressions cover the first Connect, duplicate attempts, cancellation, endpoint
changes, root-only temporary DNS cleanup, protocol validation, IPC identity and
independent switch control. Real server compatibility, sleep/wake, network changes
and reboot still require testing on a Mac. Other vendor servers are not claimed as
end-to-end tested merely because their protocol is listed.

## License and origin

GPL-2.0-or-later. Based on OpenConnect-GUI 1.6.2. Original author notices and
third-party license notices are preserved; see [UPSTREAM.md](UPSTREAM.md),
[AUTHORS](AUTHORS) and [LICENSE.txt](LICENSE.txt).
