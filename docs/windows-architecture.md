# Windows network service and filtering

The GUI uses the same authenticated command/status model as the macOS client.
It runs with `asInvoker`. SCM starts `OpenConnectKillSwitch` as LocalSystem from a
fixed protected Program Files directory. The installer and recovery commands need
administrator rights; ordinary ON/OFF requests do not.

The service stores the designated desktop account SID and selected firewall
intent in an administrator/System-only ProgramData directory. Neither passwords
nor authentication cookies are persisted by the service. The GUI authenticates
the pipe server against SCM's service PID and configured account. The service
impersonates the authenticated pipe client token on each message, checks the
account and local logon type, and rejects network/delegated logons. No status is
sent before authentication. Arbitrary scripts, files, proxy settings and client
certificate paths are not accepted through IPC.

WFP owns a project-specific persistent provider and sublayer. Four persistent
ALE filters block outbound and inbound-initiated traffic for IPv4 and IPv6.
Higher-weight rules inside the same sublayer allow loopback, system DHCP and
limited IPv6 neighbor discovery. Outbound VPN endpoint permissions match numeric
addresses, ports, this runtime's App ID **and the LocalSystem SID**. Another
process or a desktop-user copy of the same executable does not inherit them.

The service may briefly allow its own DNS to adapter-configured resolvers when a
new gateway must be resolved. It validates transaction ID, exact question, class,
record lengths, compression and CNAME ownership before accepting A/AAAA data.
DNS permissions disappear after resolution. There is no permanent general DNS
exception and no fixed external resolver.

Tunnel permissions match the assigned local address and exact interface LUID:
next-hop interface outbound, arrival interface inbound. The service verifies the
adapter is up and owns the negotiated address. Server redirects and negotiated
DTLS ports are added only for the active session. New gateway/adapter permissions
replace previous dynamic permits inside one WFP transaction.

Blocking filters persist across service exit. Endpoint and tunnel permits belong
to a dynamic WFP session, so they disappear if the service exits or crashes. On
restart only saved primary endpoint addresses are restored; previous tunnel LUIDs
and redirect exceptions are not reused. OFF saves explicit intent, deletes only
the project's provider objects and verifies the absence of its filters.
An update stops the runtime while retaining persistent filters and intent.

Policy changes trigger ALE reauthorization of existing flows. No global
connection-table reset or Windows Firewall policy reset is used. Other firewall
products may still deny traffic; this service does not claim to override them.
This is not protection against a local administrator, SYSTEM-level malware, a
kernel driver or an administrator who disables BFE. Early boot before BFE,
forwarded/bridged traffic and endpoint security products require separate target
validation; they are not claimed as covered by the hosted test.

Primary references:

- [WFP object lifetimes and transactions](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management)
- [ALE reauthorization](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization)
- [Application and user conditions](https://learn.microsoft.com/en-us/windows/win32/fwp/permitting-and-blocking-applications-and-users)
- [Conditions supported at each layer](https://learn.microsoft.com/en-us/windows/win32/fwp/filtering-conditions-available-at-each-filtering-layer)
