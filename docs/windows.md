# Windows installation and recovery

[По-русски](windows.ru.md) · [Architecture](windows-architecture.md)

The x64 installer includes the GUI, libOpenConnect, public TLS roots and Wintun.
You do not need MSYS2, Python, Homebrew or a separate OpenConnect installation on
the destination computer. The application supports OpenConnect protocols; it does
not import OpenVPN `.ovpn` or WireGuard profiles.

1. Download the Windows x64 setup EXE from the project's Releases page.
2. Run it and approve the Windows administrator prompt. Close the old GUI before
   updating. If an interface is still running, setup stops before changing the
   service or its protection and asks you to close it. The protected service is
   installed in Program Files and starts with
   Windows. Opening the GUI at login is a separate installer option.
3. Add your own gateway and select its matching protocol. For Cisco AnyConnect or
   ocserv choose **Cisco AnyConnect or OpenConnect**. Username/password input is
   requested during connection.
4. Use **Блокировать интернет без VPN** to block Internet and LAN access outside
   this client's VPN. **Connect** and **Disconnect** remain separate controls.
5. Turn the switch off explicitly to restore ordinary access. Closing the GUI,
   disconnecting the VPN, or stopping the service does not mean OFF.

A fresh installation starts with protection OFF. Updating preserves the selected
ON/OFF setting and ends the old VPN session; connect again after updating. The
GUI shows the service's confirmed state, version, response latency and VPN phase.
The diagnostics button reads local service/filter state without uploading it.

The installer is unsigned. No publisher certificate is bundled. This build targets
Windows x64; Windows ARM64 and 32-bit editions are not packaged.

## OFF and recovery

Use the switch or **Снять блокировку OpenConnect** in the main window. The selected
desktop account can request OFF without another administrator password while the
service is available.

From PowerShell, through the service:

```powershell
& "$env:ProgramFiles\OpenConnect-GUI-KillSwitch\openconnect-gui.exe" --service-disable
```

If the service cannot answer, open PowerShell **as administrator** and run:

```powershell
& "$env:ProgramFiles\OpenConnect-GUI-KillSwitch\openconnect-gui.exe" --recover-killswitch
```

Recovery stops this service, removes this project's WFP filters and starts the
service again with OFF saved. It preserves application profiles and other
applications' firewall policies. It does not globally reset Windows Firewall.

Close the interface, then remove the application using Windows **Installed apps**,
or the **Remove** entry
in its Start menu folder. Removal confirms that its own filtering is cleared
before deleting the runtime and protected service state. If the interface is
still open, removal stops before changing the service or its protection.

## Build

Use an MSYS2 **UCRT64** shell on Windows with the packages listed in
`.github/workflows/windows.yml`, then run:

```sh
sh scripts/build-windows.sh
```

The script verifies and builds the pinned OpenConnect source, compiles the GUI and
service, runs DNS parser tests, stages native dependencies and their license
notices, checks PE architecture and the non-elevating GUI manifest, and creates an
NSIS setup EXE with SHA-256 files. The corresponding modified LGPL source is
distributed alongside the installer. `DEPENDENCIES.json` records package versions
and the hashes of bundled native files.

`tests/windows_smoke.py` is reserved for a **disposable Windows GitHub Actions
runner**. It deliberately changes that runner's network policy and refuses to run
on a normal endpoint. It exercises the installed EXE, authenticated service status,
invalid IPC, existing/new traffic, ON/OFF, an actual local TLS/CSTP/Wintun packet
path, restart, upgrade, recovery and removal. Its generated test CA exists only in
the runner's installed copy and is removed after the test; it is never shipped.

The hosted Windows Server 2022 check does not replace endpoint QA on Windows 10/11:
test your real gateway, DTLS/UDP, sleep/wake, switching Wi-Fi/Ethernet, reboot and
coexistence with endpoint security software before deployment. IPv6 Internet
testing is reported as unavailable if the hosted runner lacks an IPv6 baseline.

