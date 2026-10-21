// SPDX-License-Identifier: GPL-2.0-or-later
#include "NetworkGuard.h"
#include "MacPfStates.h"
#include <QCoreApplication>
#include <QFile>
#include <QJsonDocument>
#include <QProcess>
#include <QTemporaryDir>
#include <QtTest>
#include <netdb.h>
#include <QtEndian>
#include <cstring>

namespace {
// The ONLY real PF invocation in these tests is the non-mutating parser (-n).
NetworkGuard::Result parse(const QByteArray& input)
{
    QProcess p;
    p.start("/sbin/pfctl", {"-n", "-v", "-a", NetworkGuard::anchor(), "-f", "-"});
    if (!p.waitForStarted())
        return {-1, {}, p.errorString()};
    p.write(input);
    p.closeWriteChannel();
    if (!p.waitForFinished())
        return {-1, {}, "parser timeout"};
    return {p.exitCode(), QString::fromUtf8(p.readAllStandardOutput()),
        QString::fromUtf8(p.readAllStandardError())};
}

struct FakePf {
    QString installed;
    bool enabled = false;
    bool flushFails = false;
    bool loadFails = false;
    bool removeFails = false;
    bool releaseFails = false;
    QString releaseError = "injected release failure";
    QStringList calls;
    QString root = "anchor \"com.apple/*\" all\n";
    QString ciscoRules;
    QString ciscoChildren;

    NetworkGuard::Result operator()(const QStringList& args, const QByteArray& input)
    {
        calls << args.join(' ');
        if (args.contains("-n"))
            return parse(input);
        if (args == QStringList{"-sr"})
            return {0, root, {}};
        if (args == QStringList{"-a", "com.apple", "-s", "Anchors"})
            return {0, "com.apple/100.InternetSharing\n", {}};
        if (args == QStringList{"-a", "cisco.anyconnect.vpn", "-sr"})
            return {0, ciscoRules, {}};
        if (args == QStringList{"-a", "cisco.anyconnect.vpn", "-s", "Anchors"})
            return {0, ciscoChildren, {}};
        if (args == QStringList{"-v", "-s", "Interfaces"})
            return {0, "en0\nlo0 (skip)\nutun0\n", {}};
        if (args == QStringList{"-s", "info"})
            return {0, enabled ? "Status: Enabled for 0 days" : "Status: Disabled", {}};
        if (args == QStringList{"-a", NetworkGuard::anchor(), "-sr"})
            return {0, installed, {}};
        if (args == QStringList{"-E"}) {
            enabled = true;
            return {0, {}, "pf enabled\nToken : 123456\n"};
        }
        if (args == QStringList{"-a", NetworkGuard::anchor(), "-f", "-"}) {
            if ((input.isEmpty() && removeFails) || (!input.isEmpty() && loadFails))
                return {1, {}, "injected load failure"};
            const auto parsed = parse(input);
            if (parsed.exitCode == 0)
                installed = parsed.output.trimmed();
            return {parsed.exitCode, {}, parsed.error};
        }
        if (args == QStringList{":prune-states"})
            return {flushFails ? 1 : 0, {}, {}};
        if (args == QStringList{"-X", "123456"}) {
            if (releaseFails)
                return {1, {}, releaseError};
            enabled = false;
            return {0, {}, {}};
        }
        return {1, {}, "unexpected PF invocation"};
    }
};

NetworkGuard::Policy policy()
{
    NetworkGuard::Policy p;
    p.host = "vpn.example.test";
    p.addresses = {"203.0.113.10", "2001:db8::10"};
    p.port = 8443;
    p.udpPorts = {443, 8443};
    return p;
}
}

class MacKillSwitchTest : public QObject {
    Q_OBJECT
private slots:
    void blockWithoutProfileAndSwitchGatewaysWithoutFailOpen()
    {
        QTemporaryDir directory; FakePf pf; QString error;
        NetworkGuard guard(std::ref(pf), directory.filePath("state.json"));
        QVERIFY2(guard.arm(QUrl(), error), qPrintable(error));
        QVERIFY(pf.installed.contains("ocgui_ks_block"));
        QVERIFY(!pf.installed.contains("ocgui_ks_gateway"));
        QVERIFY(guard.prepareConnection(QUrl("https://203.0.113.21:9443"), error));
        QVERIFY(pf.installed.contains("203.0.113.21"));
        QVERIFY(guard.prepareConnection(QUrl("https://203.0.113.22:8443"), error));
        QVERIFY(pf.installed.contains("203.0.113.22"));
        QVERIFY(!pf.installed.contains("203.0.113.21"));
        QCOMPARE(pf.calls.count("-E"), 1);
        QVERIFY(!pf.calls.contains("-d"));
        QVERIFY(!pf.calls.contains("-X 123456"));
        QVERIFY(guard.isArmed());
    }

    void rootOnlyDnsBootstrapIsRemovedOnSuccessFailureAndCancel()
    {
        for (int mode = 0; mode != 3; ++mode) {
            QTemporaryDir directory; FakePf pf; QString error;
            bool queriedWhileBlocked = false;
            NetworkGuard* active = nullptr;
            NetworkGuard guard(std::ref(pf), directory.filePath("state.json"),
                directory.filePath("boot.json"), {},
                [&](const QString& host, const QStringList& servers, QString&) {
                    queriedWhileBlocked = host == "vpn.example.test" && servers == QStringList{"192.0.2.53"}
                        && pf.installed.contains("ocgui_ks_dns") && pf.installed.contains("ocgui_ks_block")
                        && (pf.installed.contains("user = root") || pf.installed.contains("user = 0"));
                    if (mode == 2) active->requestEnabled(false);
                    return mode == 0 ? QStringList{"203.0.113.30"} : QStringList{};
                }, {"192.0.2.53"});
            active = &guard;
            QVERIFY2(guard.arm(QUrl("https://vpn.example.test"), error), qPrintable(error));
            QVERIFY(queriedWhileBlocked);
            QVERIFY(!pf.installed.contains("ocgui_ks_dns"));
            QVERIFY(pf.installed.contains("ocgui_ks_block"));
            QCOMPARE(pf.installed.contains("203.0.113.30"), mode == 0);
            QFile state(directory.filePath("state.json")); QVERIFY(state.open(QIODevice::ReadOnly));
            QVERIFY(!state.readAll().contains("ocgui_ks_dns"));
            QVERIFY(!pf.calls.contains("-d"));
            QVERIFY(guard.disable(error));
        }
    }

    void dnsBootstrapRulesKeepOtherTrafficBlockedAndValidateAddresses()
    {
        QString error;
        const auto text = NetworkGuard::dnsBootstrapRules(policy(), {"192.0.2.53", "2001:db8::53"}, error);
        QVERIFY2(!text.isEmpty(), qPrintable(error));
        QCOMPARE(parse(text.toUtf8()).exitCode, 0);
        QCOMPARE(text.count("port 53 user 0"), 4);
        QVERIFY(text.endsWith("label \"ocgui_ks_block\"\n"));
        QVERIFY(NetworkGuard::dnsBootstrapRules(policy(), {"dns.invalid; pass quick all"}, error).isEmpty());
        QVERIFY(!NetworkGuard::rules(policy(), error).contains("ocgui_ks_dns"));
    }

    void negotiatedGatewayAndPortArePinnedForOnlyTheCurrentSession()
    {
        QTemporaryDir directory; FakePf pf; QString error;
        NetworkGuard guard(std::ref(pf), directory.filePath("state.json"), {}, {},
            [](const QString&, const QStringList&, QString&) { return QStringList{"203.0.113.40"}; },
            {"192.0.2.53"});
        QVERIFY(guard.arm(QUrl("https://203.0.113.20"), error));
        struct addrinfo hints{}; hints.ai_socktype = SOCK_STREAM;
        struct addrinfo* addresses = nullptr;
        QCOMPARE(guard.resolve("gateway.example.test", "9443", &hints, &addresses), 0);
        QVERIFY(addresses); freeaddrinfo(addresses);
        QVERIFY(pf.installed.contains("203.0.113.20"));
        QVERIFY(pf.installed.contains("203.0.113.40"));
        QVERIFY(pf.installed.contains("ocgui_ks_endpoint"));
        QVERIFY(!pf.installed.contains("ocgui_ks_dns"));
        QVERIFY(guard.allowDtlsPort(443, error));
        const auto udp443 = parse("pass out quick inet proto udp from any to 203.0.113.40 port 443 user 0 keep state (if-bound) label \"ocgui_ks_endpoint\"\n");
        QCOMPARE(udp443.exitCode, 0);
        QVERIFY2(pf.installed.contains(udp443.output.trimmed()), qPrintable(pf.installed));
        NetworkGuard::Policy p = policy();
        p.sessionEndpoints << NetworkGuard::Endpoint{"gateway.example.test", {"203.0.113.40"}, 9443, {9443}};
        MacPfStates::State state; state.remote = QHostAddress("203.0.113.40");
        state.interfaceName = "en0"; state.direction = 2; state.protocol = 6; state.remotePort = 9443;
        QVERIFY(MacPfStates::permitted(state, p, true));
        QVERIFY(!MacPfStates::permitted(state, p, false));
        state.remotePort = 443; QVERIFY(!MacPfStates::permitted(state, p, true));
        QVERIFY(guard.lockTunnel(error));
        QVERIFY(!pf.installed.contains("203.0.113.40"));
        QVERIFY(pf.installed.contains("203.0.113.20"));
        QVERIFY(guard.isArmed());
    }

    void stalePfReferenceDoesNotPreventOffOrServiceRestart()
    {
        for (const auto& message : {QString("pfctl: DIOCSTOPREF: Invalid argument"),
                QString("pfctl: DIOCSTOPREF: No such file or directory"), QString("pfctl: pf not enabled"),
                QString("No ALTQ support in kernel\nALTQ related functions disabled\npfctl: pf: token invalid\n")}) {
            QTemporaryDir directory;
            FakePf pf;
            QString error;
            NetworkGuard guard(std::ref(pf), directory.filePath("state.json"));
            QVERIFY(guard.arm(QUrl("https://203.0.113.10"), error));
            pf.releaseFails = true; pf.releaseError = message;
            if (message.endsWith("pf not enabled")) pf.enabled = false;
            QVERIFY2(guard.disable(error), qPrintable(error));
            QVERIFY(!guard.isArmed()); QVERIFY(pf.installed.isEmpty());
            QVERIFY(!QFile::exists(directory.filePath("state.json")));
            QCOMPARE(pf.enabled, !message.endsWith("pf not enabled"));
            QVERIFY(guard.restore(error));
        }
    }
    void serviceRestartRecoversPersistedOffWithInvalidToken()
    {
        QTemporaryDir directory;
        FakePf pf;
        QString error;
        const auto state = directory.filePath("state.json");
        const auto boot = directory.filePath("boot.json");
        {
            NetworkGuard oldService(std::ref(pf), state, boot);
            QVERIFY(oldService.armPinned(policy(), error));
            pf.releaseFails = true;
            QVERIFY(!oldService.disable(error));
            QVERIFY(QFile::exists(state));
            bool enabled = true;
            auto cached = policy();
            QVERIFY(NetworkGuard::readBootPolicy(boot, cached, enabled, error));
            QVERIFY(!enabled);
        }
        pf.releaseError = "No ALTQ support in kernel\nALTQ related functions disabled\npfctl: pf: token invalid\n";
        NetworkGuard service(std::ref(pf), state, boot);
        QVERIFY2(service.restoreBootProtection(error), qPrintable(error));
        QVERIFY(!service.isArmed());
        QVERIFY(!QFile::exists(state));
        QVERIFY(pf.installed.isEmpty());
        QVERIFY(pf.enabled); // An absent own reference must not disable foreign references.
        const auto calls = pf.calls.count("-X 123456");
        QVERIFY(service.restoreBootProtection(error));
        QCOMPARE(pf.calls.count("-X 123456"), calls);
        QVERIFY(!pf.calls.contains("-d"));
    }
    void exactStateDeletionRespectsOriginalDirectionAndPorts()
    {
        for (const auto family : {2, 30}) for (const auto direction : {1, 2}) {
            QByteArray wire(297, '\0');
            std::memcpy(wire.data() + 8, "en0", 4);
            wire[24] = '\x0a'; wire[27] = '\x02';
            wire[72] = '\xcb'; wire[75] = '\x0a';
            qToBigEndian<quint16>(49152, wire.data() + 40);
            qToBigEndian<quint16>(443, wire.data() + 88);
            wire[282] = family; wire[284] = 6; wire[285] = direction;
            MacPfStates::State state;
            QString error;
            QVERIFY(MacPfStates::decode(wire, state, error));
            const auto request = MacPfStates::killRequest(state, error);
            QCOMPARE(request.size(), 216);
            QCOMPARE(request.mid(136, 4), QByteArray("en0\0", 4));
            const int source = direction == 2 ? 24 : 72, destination = direction == 2 ? 72 : 24;
            QCOMPARE(request.mid(8, 16), wire.mid(source, 16));
            QCOMPARE(request.mid(72, 16), wire.mid(destination, 16));
            QCOMPARE(request.mid(24, 16), QByteArray(family == 2 ? 4 : 16, '\xff') + QByteArray(family == 2 ? 12 : 0, '\0'));
            QCOMPARE(request.mid(88, 16), request.mid(24, 16));
            QCOMPARE(request.mid(60, 2), wire.mid(source + 16, 2));
            QCOMPARE(request.mid(62, 2), wire.mid(source + 16, 2));
            QCOMPARE(request.mid(124, 2), wire.mid(destination + 16, 2));
            QCOMPARE(request[64], '\x02'); QCOMPARE(request[128], '\x02');
        }
    }

    void selectiveStatePolicyPreservesOnlyApprovedConnections()
    {
        auto p = policy();
        p.interfaceName = "utun42"; p.ipv4 = "10.23.0.2"; p.ipv6 = "2001:db8:1::2";
        MacPfStates::State state;
        state.interfaceName = "lo0"; state.local = QHostAddress("127.0.0.1"); state.remote = QHostAddress("127.0.0.1");
        QVERIFY(MacPfStates::permitted(state, p, false));
        state.interfaceName = "en0";
        QVERIFY(!MacPfStates::permitted(state, p, false));
        state.interfaceName = "utun42"; state.local = QHostAddress(p.ipv4); state.remote = QHostAddress("1.1.1.1");
        QVERIFY(MacPfStates::permitted(state, p, false));
        state.interfaceName = "utun43";
        QVERIFY(!MacPfStates::permitted(state, p, true));
        state.interfaceName = "all";
        QVERIFY(!MacPfStates::permitted(state, p, true));
        state.interfaceName = "en0"; state.local = QHostAddress("192.168.0.2"); state.remote = QHostAddress(p.addresses.first());
        state.direction = 2; state.protocol = 6; state.remotePort = p.port;
        QVERIFY(!MacPfStates::permitted(state, p, false)); // Old state cannot prove root ownership.
        QVERIFY(MacPfStates::permitted(state, p, true));
        state.remotePort = 80;
        QVERIFY(!MacPfStates::permitted(state, p, true));
        state.protocol = 17; state.remotePort = 443;
        QVERIFY(MacPfStates::permitted(state, p, true));
        state.direction = 1;
        QVERIFY(!MacPfStates::permitted(state, p, true));
    }

    void stateAbiDecoderHandlesBothFamiliesAndRejectsUnknownLayouts()
    {
        QByteArray wire(297, '\0');
        std::memcpy(wire.data() + 8, "en0", 4);
        qToBigEndian<quint32>(0xc0a80002, reinterpret_cast<uchar*>(wire.data() + 24));
        qToBigEndian<quint32>(0xcb00710a, reinterpret_cast<uchar*>(wire.data() + 72));
        qToBigEndian<quint16>(50000, reinterpret_cast<uchar*>(wire.data() + 40));
        qToBigEndian<quint16>(443, reinterpret_cast<uchar*>(wire.data() + 88));
        wire[282] = 2; wire[284] = 6; wire[285] = 2;
        QString error;
        MacPfStates::State state;
        QVERIFY(MacPfStates::decode(wire, state, error));
        QCOMPARE(state.local, QHostAddress("192.168.0.2")); QCOMPARE(state.remote, QHostAddress("203.0.113.10"));
        QCOMPARE(state.localPort, quint16(50000)); QCOMPARE(state.remotePort, quint16(443));
        const auto local = QHostAddress("2001:db8:1::2").toIPv6Address();
        const auto remote = QHostAddress("2001:db8::10").toIPv6Address();
        std::memcpy(wire.data() + 24, local.c, 16); std::memcpy(wire.data() + 72, remote.c, 16); wire[282] = 30;
        QVERIFY(MacPfStates::decode(wire, state, error));
        QCOMPARE(state.local, QHostAddress("2001:db8:1::2"));
        QVERIFY(!MacPfStates::decode(wire.left(296), state, error));
        wire[282] = 99;
        QVERIFY(!MacPfStates::decode(wire, state, error));
    }
    void freshInstallCanBeOffWithoutDnsOrCachedAddresses()
    {
        QTemporaryDir directory;
        NetworkGuard::Policy initial;
        initial.host = "not-resolved.invalid";
        QString error;
        const auto path = directory.filePath("boot.json");
        QVERIFY(NetworkGuard::writeBootPolicy(path, initial, false, error));
        NetworkGuard::Policy cached;
        bool enabled = true;
        QVERIFY(NetworkGuard::readBootPolicy(path, cached, enabled, error));
        QVERIFY(!enabled);
        QVERIFY(cached.addresses.isEmpty());
        QCOMPARE(cached.host, initial.host);
        QVERIFY(NetworkGuard::writeBootPolicy(path, initial, true, error));
        QVERIFY(NetworkGuard::readBootPolicy(path, cached, enabled, error));
        QVERIFY(enabled);
        const auto blocked = NetworkGuard::rules(cached, error);
        QVERIFY(blocked.contains("block drop quick all"));
        FakePf pf;
        NetworkGuard guard(std::ref(pf), directory.filePath("state.json"));
        QVERIFY2(guard.armPinned(cached, error), qPrintable(error));
        QVERIFY2(guard.verify(error), qPrintable(error));
        QVERIFY(guard.disable(error));
        QVERIFY(!blocked.contains("ocgui_ks_gateway"));
    }

    void atomicStorageCanReplaceExistingReadOnlyFile()
    {
        QTemporaryDir directory;
        const auto path = directory.filePath("boot.json");
        QString error;
        auto cached = policy();
        QVERIFY(NetworkGuard::writeBootPolicy(path, cached, false, error));
        QVERIFY(QFile::setPermissions(path, QFile::ReadOwner));
        QVERIFY2(NetworkGuard::writeBootPolicy(path, cached, true, error), qPrintable(error));
        bool enabled = false;
        QVERIFY(NetworkGuard::readBootPolicy(path, cached, enabled, error));
        QVERIFY(enabled);
        QCOMPARE(QFileInfo(path).permissions() & (QFile::ReadGroup | QFile::WriteGroup | QFile::ReadOther | QFile::WriteOther), QFile::Permissions{});
    }

    void disabledGuardDoesNotBreakInFlightConnectionOrRearm()
    {
        QTemporaryDir directory;
        FakePf pf;
        NetworkGuard guard(std::ref(pf), directory.filePath("state.json"));
        QString error;
        QVERIFY(guard.armPinned(policy(), error));
        QVERIFY(guard.disable(error));
        const auto calls = pf.calls.size();
        QVERIFY(guard.prepareConnection(QUrl("https://vpn.example.test:8443"), error));
        QVERIFY(guard.arm(QUrl("https://vpn.example.test:8443"), error));
        QVERIFY(guard.allowDtlsPort(443, error));
        QVERIFY(guard.attachTunnel("utun42", "10.23.0.2", {}, error));
        QVERIFY(guard.lockTunnel(error));
        QCOMPARE(pf.calls.size(), calls);
        QVERIFY(pf.installed.isEmpty());
        QVERIFY(!guard.isArmed());
        struct addrinfo hints{};
        hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
        struct addrinfo* result = nullptr;
        QCOMPARE(guard.resolve("127.0.0.1", "443", &hints, &result), 0);
        QVERIFY(result);
        freeaddrinfo(result);
    }

    void connectUsesArmedEndpointWithoutDnsRouteGateOrAnotherArm()
    {
        QTemporaryDir directory;
        FakePf pf;
        NetworkGuard guard(std::ref(pf), directory.filePath("state.json"));
        QString error;
        QVERIFY(guard.armPinned(policy(), error));
        QVERIFY(guard.prepareConnection(QUrl("https://vpn.example.test:8443"), error));
        QCOMPARE(pf.calls.count("-E"), 1);
        QCOMPARE(pf.calls.count(":prune-states"), 1);
        QVERIFY(guard.prepareConnection(QUrl("https://203.0.113.11:8443"), error));
        QVERIFY(pf.installed.contains("203.0.113.11"));
        QVERIFY(guard.isArmed());
    }

    void delayedBootWorkerRespectsMostRecentOff()
    {
        QTemporaryDir directory;
        FakePf pf;
        const auto bootPath = directory.filePath("boot.json");
        const auto statePath = directory.filePath("state.json");
        NetworkGuard gui(std::ref(pf), statePath, bootPath);
        NetworkGuard boot(std::ref(pf), statePath, bootPath);
        QString error;
        QVERIFY(gui.armPinned(policy(), error));
        QVERIFY(gui.disable(error));
        const auto acquisitions = pf.calls.count("-E");
        QVERIFY(boot.restoreBootProtection(error));
        QVERIFY(!boot.isArmed());
        QVERIFY(pf.installed.isEmpty());
        QCOMPARE(pf.calls.count("-E"), acquisitions);
    }

    void guiAdoptsGuardArmedAfterItStarted()
    {
        QTemporaryDir directory;
        FakePf pf;
        const auto path = directory.filePath("state.json");
        NetworkGuard gui(std::ref(pf), path);
        NetworkGuard boot(std::ref(pf), path);
        auto cached = policy();
        cached.host = "never-resolve.invalid";
        QString error;
        QVERIFY(boot.armPinned(cached, error));
        QVERIFY(gui.arm(QUrl("https://never-resolve.invalid:8443"), error));
        QVERIFY(gui.isArmed());
        QCOMPARE(pf.calls.count("-E"), 1);
        QCOMPARE(pf.calls.count(":prune-states"), 1);
        const auto before = pf.calls.count("-a " + NetworkGuard::anchor() + " -f -");
        NetworkGuard inspection(std::ref(pf), path);
        QVERIFY(inspection.verifySavedState(error));
        QCOMPARE(pf.calls.count("-a " + NetworkGuard::anchor() + " -f -"), before);
    }

    void ciscoHookCoexistsButQuickBypassIsRejected()
    {
        QTemporaryDir directory;
        FakePf pf;
        pf.root = "anchor \"cisco.anyconnect.vpn\" all\nanchor \"com.apple/*\" all\n";
        NetworkGuard guard(std::ref(pf), directory.filePath("state.json"));
        QString error;
        QVERIFY2(guard.arm(QUrl("https://203.0.113.10"), error), qPrintable(error));
        pf.ciscoRules = "pass out quick all";
        QVERIFY(!guard.verify(error));
        QVERIFY(error.contains("Cisco Secure Client"));
        pf.ciscoRules.clear();
        pf.ciscoChildren = "unexpected-child";
        QVERIFY(!guard.verify(error));
        pf.ciscoChildren.clear();
        QVERIFY(guard.verify(error));
        pf.root = "anchor \"cisco.anyconnect.vpn\" quick all\nanchor \"com.apple/*\" all\n";
        QVERIFY(!guard.verify(error));
    }

    void compatibleRulesAfterTheHookDoNotPreventSystemBlocking()
    {
        QTemporaryDir directory; FakePf pf; QString error;
        pf.root = "pass out all flags S/SA keep state\nanchor \"com.apple/*\" all\npass quick all\nanchor \"other.firewall\" quick all\n";
        NetworkGuard guard(std::ref(pf), directory.filePath("state.json"));
        QVERIFY2(guard.arm(QUrl("https://203.0.113.10"), error), qPrintable(error));
        QVERIFY(guard.isArmed()); QVERIFY(guard.verify(error));
        const auto unchanged = pf.root;
        QVERIFY(guard.disable(error)); QCOMPARE(pf.root, unchanged);
        pf.root.prepend("pass quick all\n");
        guard.requestEnabled(true);
        QVERIFY(!guard.arm(QUrl("https://203.0.113.10"), error));
        QVERIFY(!guard.isArmed()); QVERIFY(pf.installed.isEmpty());
        QVERIFY(guard.verify(error)); // Confirmed OFF even if enabling was rejected.
    }

    void offVerificationDetectsOrphanedRulesInsteadOfTrustingMemory()
    {
        QTemporaryDir directory; FakePf pf; QString error;
        NetworkGuard guard(std::ref(pf), directory.filePath("state.json"));
        QVERIFY(guard.verify(error));
        pf.installed = "block drop quick all label \"ocgui_ks_block\"";
        QVERIFY(!guard.verify(error));
        QVERIFY(error.contains("not confirmed OFF"));
        QVERIFY(guard.disable(error)); QVERIFY(guard.verify(error));
    }

    void bootUsesPinnedAddressesAndRespectsExplicitDisable()
    {
        QTemporaryDir directory;
        FakePf pf;
        QString error;
        const auto boot = directory.filePath("boot.json");
        const auto state = directory.filePath("state.json");
        auto initial = policy();
        initial.host = "never-resolve.invalid";
        QVERIFY(NetworkGuard::writeBootPolicy(boot, initial, true, error));
        NetworkGuard::Policy cached;
        bool enabled = false;
        QVERIFY(NetworkGuard::readBootPolicy(boot, cached, enabled, error));
        QVERIFY(enabled);
        QCOMPARE(cached.addresses, initial.addresses);
        NetworkGuard guard(std::ref(pf), state, boot);
        QVERIFY2(guard.armPinned(cached, error), qPrintable(error));
        QVERIFY(guard.disable(error));
        QVERIFY(NetworkGuard::readBootPolicy(boot, cached, enabled, error));
        QVERIFY(!enabled);
        // Even with no runtime state, the explicit disable survives a restart.
        NetworkGuard stopped(std::ref(pf), state, boot);
        QVERIFY(stopped.restore(error));
        QVERIFY(!stopped.isArmed());
        QVERIFY(stopped.disable(error));
        stopped.requestEnabled(true);
        QVERIFY(stopped.armPinned(cached, error));
        QVERIFY(NetworkGuard::readBootPolicy(boot, cached, enabled, error));
        QVERIFY(enabled);
    }

    void pinnedResolverNeedsNoDnsAndRejectsUnknownHosts()
    {
        struct addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        struct addrinfo* result = nullptr;
        const QStringList addresses{"203.0.113.10", "2001:db8::10"};
        QCOMPARE(NetworkGuard::resolvePinned("never-resolve.invalid", addresses,
            "never-resolve.invalid", "8443", &hints, &result), 0);
        QVERIFY(result);
        QVERIFY(result->ai_next);
        freeaddrinfo(result);
        result = nullptr;
        QCOMPARE(NetworkGuard::resolvePinned("never-resolve.invalid", addresses,
            "other.invalid", "8443", &hints, &result), EAI_NONAME);
        QVERIFY(!result);
        QCOMPARE(NetworkGuard::resolvePinned("never-resolve.invalid", addresses,
            "203.0.113.11", "8443", &hints, &result), EAI_NONAME);
        QCOMPARE(NetworkGuard::resolvePinned("never-resolve.invalid", addresses,
            "203.0.113.10", "https", &hints, &result), EAI_SERVICE);
    }

    void kernelParserAcceptsIPv4IPv6AndSpecificTunnel()
    {
        auto p = policy();
        p.interfaceName = "utun42";
        p.ipv4 = "10.23.0.2";
        p.ipv6 = "2001:db8:1::2";
        QString error;
        const auto text = NetworkGuard::rules(p, error);
        QVERIFY2(!text.isEmpty(), qPrintable(error));
        const auto result = parse(text.toUtf8());
        QCOMPARE(result.exitCode, 0);
        QVERIFY2(result.output.contains("on utun42 inet6"), qPrintable(result.error));
        QVERIFY(result.output.contains("if-bound"));
        for (const auto& line : result.output.split('\n'))
            if (line.contains("ocgui_ks_gateway")) QVERIFY(line.contains("user = 0") || line.contains("user = root"));
        QVERIFY(result.output.trimmed().endsWith("block drop quick all label \"ocgui_ks_block\""));
        QVERIFY(!result.output.contains("port = 53"));
        QVERIFY(!result.output.contains("on utun+"));
    }

    void rejectRuleInjectionAndPhysicalInterface()
    {
        auto p = policy();
        QString error;
        p.addresses << "203.0.113.11\npass quick all";
        QVERIFY(NetworkGuard::rules(p, error).isEmpty());
        p = policy();
        p.interfaceName = "en0";
        p.ipv4 = "10.23.0.2";
        QVERIFY(NetworkGuard::rules(p, error).isEmpty());
        p.interfaceName = "utun1";
        p.ipv4 = "0.0.0.0/0";
        QVERIFY(NetworkGuard::rules(p, error).isEmpty());
    }

    void rejectFilterBypasses()
    {
        QString error;
        QVERIFY(NetworkGuard::validateEnvironment("anchor \"com.apple/*\" all", {}, "lo0 (skip)\nen0", error));
        QVERIFY(!NetworkGuard::validateEnvironment("pass quick all\nanchor \"com.apple/*\" all", {}, {}, error));
        QVERIFY(!NetworkGuard::validateEnvironment({}, {}, {}, error));
        QVERIFY(!NetworkGuard::validateEnvironment("anchor \"com.apple/*\" all", "00.bypass", {}, error));
        QVERIFY(!NetworkGuard::validateEnvironment("anchor \"com.apple/*\" all", {}, "en0 (skip)", error));
    }

    void retainRulesOnDestructionAndExplicitlyReleaseOnlyOwnReference()
    {
        QTemporaryDir directory;
        FakePf pf;
        QString error;
        {
            NetworkGuard guard(std::ref(pf), directory.filePath("state.json"));
            QVERIFY2(guard.arm(QUrl("https://203.0.113.10:443"), error), qPrintable(error));
            QVERIFY(guard.isArmed());
            const auto loadIndex = pf.calls.indexOf("-a " + NetworkGuard::anchor() + " -f -");
            QVERIFY(loadIndex >= 0);
            QVERIFY(pf.calls.indexOf(":prune-states") > loadIndex);
            QVERIFY(!guard.hasTunnel());
            QVERIFY(guard.verify(error));
        }
        QVERIFY(pf.installed.contains("ocgui_ks_block"));
        QVERIFY(pf.enabled);
        NetworkGuard recovered(std::ref(pf), directory.filePath("state.json"));
        QVERIFY2(recovered.restore(error), qPrintable(error));
        QVERIFY(!recovered.hasTunnel());
        QVERIFY(recovered.disable(error));
        QVERIFY(pf.installed.isEmpty());
        QVERIFY(!QFile::exists(directory.filePath("state.json")));
        QVERIFY(pf.calls.contains("-X 123456"));
        QVERIFY(!pf.calls.contains("-d"));
        QVERIFY(!pf.calls.contains("-F all"));
        QVERIFY(!pf.calls.contains("-f /etc/pf.conf"));
    }

    void failedStateFlushNeverClaimsProtection()
    {
        QTemporaryDir directory;
        FakePf pf;
        pf.flushFails = true;
        NetworkGuard guard(std::ref(pf), directory.filePath("state.json"));
        QString error;
        QVERIFY(!guard.arm(QUrl("https://203.0.113.10"), error));
        QVERIFY(guard.isArmed());
        QVERIFY(pf.installed.contains("ocgui_ks_block"));
        QVERIFY(!guard.verify(error));
        QVERIFY(!guard.arm(QUrl("https://203.0.113.10"), error));
        QVERIFY(!pf.calls.contains("-X 123456"));
    }

    void failedInstallKeepsRecoveryIntentAndRejectsVpn()
    {
        QTemporaryDir directory;
        FakePf pf;
        pf.loadFails = true;
        NetworkGuard guard(std::ref(pf), directory.filePath("state.json"));
        QString error;
        QVERIFY(!guard.arm(QUrl("https://203.0.113.10"), error));
        QVERIFY(!guard.verify(error));
        QVERIFY(QFile::exists(directory.filePath("state.json")));
        QVERIFY(!pf.calls.contains(":prune-states"));
        QVERIFY(!pf.calls.contains("-X 123456"));
    }

    void removedOrDisabledPfIsDetected()
    {
        QTemporaryDir directory;
        FakePf pf;
        NetworkGuard guard(std::ref(pf), directory.filePath("state.json"));
        QString error;
        QVERIFY(guard.arm(QUrl("https://203.0.113.10"), error));
        pf.enabled = false;
        QVERIFY(!guard.verify(error));
        pf.enabled = true;
        pf.installed.prepend("pass quick all\n");
        QVERIFY(!guard.verify(error));
    }

    void changingGatewayDoesNotDisarm()
    {
        QTemporaryDir directory;
        FakePf pf;
        NetworkGuard guard(std::ref(pf), directory.filePath("state.json"));
        QString error;
        QVERIFY(guard.arm(QUrl("https://203.0.113.10"), error));
        QVERIFY(guard.arm(QUrl("https://203.0.113.11"), error));
        QVERIFY(pf.installed.contains("203.0.113.11"));
        QVERIFY(!pf.installed.contains("203.0.113.10"));
        QCOMPARE(pf.calls.count("-E"), 1);
        QVERIFY(guard.isArmed());
    }

    void failedRemovalDoesNotReleasePf()
    {
        QTemporaryDir directory;
        FakePf pf;
        NetworkGuard guard(std::ref(pf), directory.filePath("state.json"));
        QString error;
        QVERIFY(guard.arm(QUrl("https://203.0.113.10"), error));
        pf.removeFails = true;
        QVERIFY(!guard.disable(error));
        QVERIFY(guard.isArmed());
        QVERIFY(!pf.calls.contains("-X 123456"));
    }

    void failedReferenceReleaseCanBeRetried()
    {
        QTemporaryDir directory;
        FakePf pf;
        NetworkGuard guard(std::ref(pf), directory.filePath("state.json"));
        QString error;
        QVERIFY(guard.arm(QUrl("https://203.0.113.10"), error));
        pf.releaseFails = true;
        QVERIFY(!guard.disable(error));
        QVERIFY(!guard.isArmed());
        QVERIFY(pf.installed.isEmpty());
        QVERIFY(QFile::exists(directory.filePath("state.json")));
        pf.releaseFails = false;
        QVERIFY(guard.disable(error));
    }
};

QTEST_GUILESS_MAIN(MacKillSwitchTest)
#include "MacKillSwitchTest.moc"
