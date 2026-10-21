// SPDX-License-Identifier: GPL-2.0-or-later
// TLS + auth-form inspection only: no credentials, cookies, tunnel or PF writes.
#include "NetworkGuard.h"
#include "config.h"
#include "VpnProgress.h"
#include <QCoreApplication>
#include <QHostInfo>
#include <cstdio>
#include <cstdarg>
#include <netdb.h>
extern "C" {
#include <openconnect.h>
}

struct Probe {
    QString host;
    QStringList addresses;
    bool formSeen = false;
    bool certificateFailed = false;
    bool resolverUsed = false;
};

static int resolve(void* data, const char* node, const char* service,
    const struct addrinfo* hints, struct addrinfo** result)
{
    auto probe = static_cast<Probe*>(data);
    probe->resolverUsed = true;
    return NetworkGuard::resolvePinned(probe->host, probe->addresses, node, service, hints, result);
}

static int certificate(void* data, const char*)
{
    static_cast<Probe*>(data)->certificateFailed = true;
    return -1; // A probe must never accept a certificate trust failure.
}

static int form(void* data, struct oc_auth_form* auth)
{
    auto probe = static_cast<Probe*>(data);
    for (auto option = auth->opts; option; option = option->next) {
        if (option->type == OC_FORM_OPT_TEXT || option->type == OC_FORM_OPT_PASSWORD)
            probe->formSeen = true;
    }
    return OC_FORM_RESULT_CANCELLED;
}

static void progress(void*, int level, const char* format, ...)
{
    if (!qEnvironmentVariableIsSet("OCGUI_PROBE_VERBOSE") || level > PRG_INFO) return;
    char buffer[1024]; va_list args;
    va_start(args, format); std::vsnprintf(buffer, sizeof(buffer), format, args); va_end(args);
    const auto safe = safeVpnProgress(QString::fromUtf8(buffer));
    if (!safe.isEmpty()) std::fprintf(stderr, "%s", qPrintable(safe));
}

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    if (argc < 2 || argc > 4) {
        std::fprintf(stderr, "usage: gateway-probe https://vpn.example.com [ca-bundle.crt] [--tls12]\n");
        return 2;
    }
    const QUrl url(QString::fromLocal8Bit(argv[1]));
    Probe probe;
    probe.host = url.host();
    for (const auto& address : QHostInfo::fromName(probe.host).addresses())
        probe.addresses << address.toString();
    if (probe.addresses.isEmpty())
        return 1;
    openconnect_init_ssl();
    auto vpn = openconnect_vpninfo_new("AnyConnect-compatible OpenConnect GUI VPN Agent", certificate,
        nullptr, form, progress, &probe);
    if (!vpn)
        return 1;
    if (openconnect_setup_cmd_pipe(vpn) < 0) return 1;
    openconnect_set_protocol(vpn, "anyconnect");
#ifdef OCGUI_HAVE_TLS12_API
    openconnect_set_password_auth_only(vpn, 1);
#endif
    if (qEnvironmentVariableIsSet("OCGUI_PROBE_LEGACY_GET")) openconnect_set_xmlpost(vpn, 0);
    openconnect_set_system_trust(vpn, 1);
    if (argc >= 3) {
        openconnect_set_system_trust(vpn, 0);
        openconnect_set_cafile(vpn, argv[2]);
    }
    if (argc == 4) {
#ifdef OCGUI_HAVE_TLS12_API
        if (QString::fromLocal8Bit(argv[3]) != "--tls12" || openconnect_set_tls12_only(vpn, 1) != 0) return 2;
#else
        return 2;
#endif
    }
    openconnect_override_getaddrinfo(vpn, resolve);
    const auto encoded = url.toEncoded();
    const auto parsed = openconnect_parse_url(vpn, encoded.constData());
    if (!parsed)
        (void)openconnect_obtain_cookie(vpn);
    const bool ok = !parsed && probe.resolverUsed && probe.formSeen && !probe.certificateFailed
        && QString::fromUtf8(openconnect_get_dnsname(vpn)) == probe.host;
    openconnect_vpninfo_free(vpn);
    std::printf("%s\n", ok
        ? "PASS: pinned gateway resolver, original DNS name, trusted TLS, Cisco login form; cancelled before credential submission."
        : "FAIL: TLS or login-form compatibility was not established.");
    return ok ? 0 : 1;
}
