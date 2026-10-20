// SPDX-License-Identifier: GPL-2.0-or-later
// TLS + auth-form inspection only: no credentials, cookies, tunnel or PF writes.
#include "MacKillSwitch.h"
#include <QCoreApplication>
#include <QHostInfo>
#include <cstdio>
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
    return MacKillSwitch::resolvePinned(probe->host, probe->addresses, node, service, hints, result);
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

static void progress(void*, int, const char*, ...) { }

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    if (argc != 2 && argc != 3) {
        std::fprintf(stderr, "usage: gateway-probe https://vpn.example.com [ca-bundle.crt]\n");
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
    auto vpn = openconnect_vpninfo_new("OpenConnect-GUI compatibility probe", certificate,
        nullptr, form, progress, &probe);
    if (!vpn)
        return 1;
    openconnect_set_protocol(vpn, "anyconnect");
    openconnect_set_system_trust(vpn, 1);
    if (argc == 3) {
        openconnect_set_system_trust(vpn, 0);
        openconnect_set_cafile(vpn, argv[2]);
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
