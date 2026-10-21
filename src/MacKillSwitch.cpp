// SPDX-License-Identifier: GPL-2.0-or-later
#include "MacKillSwitch.h"
#include "MacDnsBootstrap.h"
#include "MacPfStates.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHostAddress>
#include <QHostInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QMutexLocker>
#include <QLockFile>
#include <QNetworkInterface>
#include <QProcess>
#include <QProcessEnvironment>
#include <QRegularExpression>
#include <QTemporaryFile>
#include <QEventLoop>
#include <QTimer>
#ifndef Q_OS_WIN
#include <netdb.h>
#else
#include <ws2tcpip.h>
#endif

#ifdef Q_OS_MACOS
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#endif

namespace {
MacKillSwitch::Result executePf(const QStringList& args, const QByteArray& input)
{
    QProcess process;
    auto environment = QProcessEnvironment::systemEnvironment();
    environment.insert("LC_ALL", "C");
    environment.insert("LANG", "C");
    environment.insert("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
    process.setProcessEnvironment(environment);
    process.start(QStringLiteral("/sbin/pfctl"), args);
    if (!process.waitForStarted(3000))
        return {-1, {}, process.errorString()};
    process.write(input);
    process.closeWriteChannel();
    if (!process.waitForFinished(5000)) {
        process.kill();
        process.waitForFinished(1000);
        return {-1, {}, QStringLiteral("pfctl timed out; firewall state must be checked")};
    }
    return {process.exitStatus() == QProcess::NormalExit ? process.exitCode() : -1,
        QString::fromUtf8(process.readAllStandardOutput()),
        QString::fromUtf8(process.readAllStandardError())};
}

bool literalAddress(const QString& value, QAbstractSocket::NetworkLayerProtocol family)
{
    QHostAddress address;
    return !value.contains('%') && address.setAddress(value)
        && address.protocol() == family && !address.isNull()
        && !address.isLoopback() && !address.isMulticast();
}

bool stateDirectory(const QString& path, QString& error)
{
#ifdef Q_OS_MACOS
    const auto parent = QFileInfo(path).absolutePath();
    const auto bytes = QFile::encodeName(parent);
    struct stat info;
    if (::lstat(bytes.constData(), &info) != 0) {
        if (::mkdir(bytes.constData(), 0700) != 0
            || ::lstat(bytes.constData(), &info) != 0) {
            error = QStringLiteral("Cannot create the kill switch state directory");
            return false;
        }
    }
    if (!S_ISDIR(info.st_mode) || info.st_uid != ::geteuid()
        || (info.st_mode & 0022) != 0) {
        error = QStringLiteral("Kill switch state directory has unsafe ownership or permissions");
        return false;
    }
    if (QFileInfo(path).isSymLink()) {
        error = QStringLiteral("Refusing a symbolic link for kill switch state");
        return false;
    }
#else
    Q_UNUSED(path);
    error = QStringLiteral("The kill switch requires macOS");
    return false;
#endif
    return true;
}

bool savePrivateJson(const QString& path, const QJsonObject& object, QString& error)
{
    if (!stateDirectory(path, error))
        return false;
    // QSaveFile prechecks access using the real UID. Authorization Services
    // launches this GUI with real UID=user, effective UID=root, so that check
    // rejects an existing root-owned 0600 file despite valid write authority.
    // Create a private sibling and atomically rename using effective UID.
    QTemporaryFile file(QFileInfo(path).absolutePath() + "/.ocgui-state.XXXXXX");
    const auto bytes = QJsonDocument(object).toJson();
    if (!file.open() || !file.setPermissions(QFile::ReadOwner | QFile::WriteOwner)
        || file.write(bytes) != bytes.size() || !file.flush()) {
        error = QStringLiteral("Cannot write %1: %2").arg(path, file.errorString());
        return false;
    }
#ifdef Q_OS_MACOS
    if (::fsync(file.handle()) != 0
        || ::rename(QFile::encodeName(file.fileName()).constData(), QFile::encodeName(path).constData()) != 0) {
        error = QStringLiteral("Cannot commit %1: %2").arg(path, QString::fromLocal8Bit(strerror(errno)));
        return false;
    }
    file.setAutoRemove(false);
    return true;
#else
    error = QStringLiteral("The kill switch requires macOS");
    return false;
#endif
}

bool configuredTunnel(const QString& name, const QString& ipv4, const QString& ipv6, QString& error)
{
    const auto interface = QNetworkInterface::interfaceFromName(name);
    if (!QRegularExpression("^utun[0-9]{1,5}$").match(name).hasMatch()
        || !interface.isValid() || !interface.flags().testFlag(QNetworkInterface::IsUp)
        || (ipv4.isEmpty() && ipv6.isEmpty())) {
        error = QStringLiteral("The VPN tunnel interface is not up");
        return false;
    }
    for (const auto& address : {ipv4, ipv6}) {
        if (address.isEmpty())
            continue;
        bool found = false;
        for (const auto& entry : interface.addressEntries())
            found |= entry.ip() == QHostAddress(address);
        if (!found) {
            error = QStringLiteral("The VPN address was not configured on its interface");
            return false;
        }
    }
    return true;
}
}

MacKillSwitch::MacKillSwitch(Runner runner, QString statePath, QString bootPath, StatePruner statePruner,
    DnsLookup dnsLookup, QStringList dnsServers)
    : m_runner(runner ? runner : Runner(executePf))
    , m_statePruner(statePruner ? std::move(statePruner) : runner
        ? StatePruner([this](const Policy&, bool, QString& error) {
            const auto result = run({":prune-states"});
            if (result.exitCode) error = "Selective PF state cleanup failed";
            return result.exitCode == 0;
        }) : StatePruner(MacPfStates::prune))
    , m_dnsLookup(dnsLookup ? std::move(dnsLookup) : DnsLookup(MacDnsBootstrap::lookup))
    , m_dnsServers(std::move(dnsServers))
    , m_statePath(std::move(statePath))
    , m_bootPath(std::move(bootPath))
{
}

QString MacKillSwitch::anchor()
{
    // Runs before Apple's alphabetically named dynamic child anchors.
    return QStringLiteral("com.apple/000.openconnect-gui-killswitch");
}

MacKillSwitch::Result MacKillSwitch::run(const QStringList& args, const QByteArray& input)
{
    return m_runner(args, input);
}

std::unique_ptr<QLockFile> MacKillSwitch::transaction(QString& error) const
{
    if (!stateDirectory(m_statePath, error))
        return {};
    auto lock = std::make_unique<QLockFile>(m_statePath + ".lock");
    lock->setStaleLockTime(0); // Recover dead owners, never time out a live owner.
    if (!lock->tryLock(5000)) {
        error = QStringLiteral("Another instance is updating the kill switch; try again shortly");
        return {};
    }
    return lock;
}

QString MacKillSwitch::rules(const Policy& policy, QString& error)
{
    error.clear();
    if (policy.host.isEmpty() || policy.port == 0) {
        error = QStringLiteral("A VPN gateway and valid port are required");
        return {};
    }
    for (const auto& ip : policy.addresses) {
        if (!literalAddress(ip, QAbstractSocket::IPv4Protocol)
            && !literalAddress(ip, QAbstractSocket::IPv6Protocol)) {
            error = QStringLiteral("VPN gateway must be a literal IPv4 or IPv6 address");
            return {};
        }
    }
    if (policy.sessionEndpoints.size() > 16) { error = "Too many VPN session endpoints"; return {}; }
    if (!policy.interfaceName.isEmpty()) {
        if (!QRegularExpression(QStringLiteral("^utun[0-9]{1,5}$"))
                 .match(policy.interfaceName).hasMatch()
            || (policy.ipv4.isEmpty() && policy.ipv6.isEmpty())
            || (!policy.ipv4.isEmpty() && !literalAddress(policy.ipv4, QAbstractSocket::IPv4Protocol))
            || (!policy.ipv6.isEmpty() && !literalAddress(policy.ipv6, QAbstractSocket::IPv6Protocol))) {
            error = QStringLiteral("Invalid VPN interface or assigned tunnel address");
            return {};
        }
    }

    QString text = QStringLiteral(
        "pass quick on lo0 all no state label \"ocgui_ks_loop\"\n"
        // No general DNS, mDNS, LAN, or 'any utun' exception.
        "pass out quick inet proto udp from any port 68 to 255.255.255.255 port 67 no state label \"ocgui_ks_dhcp4\"\n"
        "pass in quick inet proto udp from any port 67 to any port 68 no state label \"ocgui_ks_dhcp4\"\n"
        "pass out quick inet6 proto udp from fe80::/10 port 546 to { fe80::/10, ff02::1:2 } port 547 no state label \"ocgui_ks_dhcp6\"\n"
        "pass in quick inet6 proto udp from fe80::/10 port 547 to any port 546 no state label \"ocgui_ks_dhcp6\"\n"
        "pass out quick inet6 proto icmp6 from any to { fe80::/10, ff02::/16 } icmp6-type { 133, 135, 136 } no state label \"ocgui_ks_ndp\"\n"
        "pass in quick inet6 proto icmp6 from fe80::/10 to any icmp6-type { 134, 135, 136 } no state label \"ocgui_ks_ndp\"\n");

    for (const auto& ip : policy.addresses) {
        const auto family = QHostAddress(ip).protocol() == QAbstractSocket::IPv4Protocol
            ? QStringLiteral("inet") : QStringLiteral("inet6");
        text += QStringLiteral("pass out quick %1 proto tcp from any to %2 port %3 user 0 flags S/SA keep state (if-bound) label \"ocgui_ks_gateway\"\n")
                    .arg(family, ip).arg(policy.port);
        for (quint16 port : policy.udpPorts) {
            if (!port) {
                error = QStringLiteral("Invalid DTLS port");
                return {};
            }
            text += QStringLiteral("pass out quick %1 proto udp from any to %2 port %3 user 0 keep state (if-bound) label \"ocgui_ks_gateway\"\n")
                        .arg(family, ip).arg(port);
        }
    }
    for (const auto& endpoint : policy.sessionEndpoints) {
        if (endpoint.host.isEmpty() || !endpoint.port || endpoint.addresses.size() > 32) {
            error = "Invalid VPN session endpoint"; return {};
        }
        for (const auto& ip : endpoint.addresses) {
            if (!literalAddress(ip, QAbstractSocket::IPv4Protocol) && !literalAddress(ip, QAbstractSocket::IPv6Protocol)) {
                error = "Invalid VPN session endpoint address"; return {};
            }
            const auto family = QHostAddress(ip).protocol() == QAbstractSocket::IPv4Protocol ? "inet" : "inet6";
            text += QString("pass out quick %1 proto tcp from any to %2 port %3 user 0 flags S/SA keep state (if-bound) label \"ocgui_ks_endpoint\"\n").arg(family, ip).arg(endpoint.port);
            for (auto port : endpoint.udpPorts) {
                if (!port) { error = "Invalid VPN session UDP port"; return {}; }
                text += QString("pass out quick %1 proto udp from any to %2 port %3 user 0 keep state (if-bound) label \"ocgui_ks_endpoint\"\n").arg(family, ip).arg(port);
            }
        }
    }
    if (!policy.interfaceName.isEmpty()) {
        for (const auto& ip : {policy.ipv4, policy.ipv6}) {
            if (ip.isEmpty())
                continue;
            const auto family = QHostAddress(ip).protocol() == QAbstractSocket::IPv4Protocol
                ? QStringLiteral("inet") : QStringLiteral("inet6");
            // No states can float from the tunnel to a physical interface.
            text += QStringLiteral("pass out quick on %1 %2 from %3 to any no state label \"ocgui_ks_tunnel_out\"\n")
                        .arg(policy.interfaceName, family, ip);
            text += QStringLiteral("pass in quick on %1 %2 from any to %3 no state label \"ocgui_ks_tunnel_in\"\n")
                        .arg(policy.interfaceName, family, ip);
        }
    }
    text += QStringLiteral("block drop quick all label \"ocgui_ks_block\"\n");
    return text;
}

QString MacKillSwitch::filterRules(const QString& text)
{
    QStringList result;
    for (const auto& line : text.split('\n')) {
        const auto value = line.trimmed();
        if (value.startsWith("pass ") || value.startsWith("block "))
            result << value;
    }
    return result.join('\n');
}

bool MacKillSwitch::validateEnvironment(const QString& rootRules,
    const QString& childAnchors, const QString& interfaces, QString& error)
{
    error.clear();
    bool hasAnchor = false;
    for (const auto& line : rootRules.split('\n')) {
        const auto value = line.trimmed();
        if (value.isEmpty() || value.startsWith("scrub-anchor "))
            continue;
        if (value == "anchor \"com.apple/*\" all" || value == "anchor \"com.apple/*\"") {
            hasAnchor = true;
            continue;
        }
        // Our last quick block matches every remaining packet in the standard
        // Apple anchor. Later root rules cannot override that decision. Preserve
        // those rules instead of rejecting an otherwise compatible firewall.
        if (hasAnchor) continue;
        // A non-quick filter before our hook cannot bypass our final decision.
        if ((value.startsWith("pass ") || value.startsWith("block "))
            && !QRegularExpression("\\bquick\\b").match(value).hasMatch()) continue;
        // Cisco Secure Client leaves this hook even when disconnected. Its
        // contents are separately checked by checkEnvironment(). A quick
        // root anchor is never accepted.
        if (value == "anchor \"cisco.anyconnect.vpn\" all"
            || value == "anchor \"cisco.anyconnect.vpn\"")
            continue;
        // Custom root filter rules need an operator-reviewed integration.
        error = QStringLiteral("A PF rule before the OpenConnect hook may bypass protection; inspect service diagnostics");
        return false;
    }
    if (!hasAnchor) {
        error = QStringLiteral("The active PF ruleset has no standard com.apple/* anchor");
        return false;
    }
    const auto ownName = anchor().section('/', -1);
    for (const auto& line : childAnchors.split('\n')) {
        const auto value = line.trimmed().section('/', -1);
        if (!value.isEmpty() && value != ownName && value < ownName) {
            error = QStringLiteral("Another PF anchor runs before the kill switch");
            return false;
        }
    }
    for (const auto& line : interfaces.split('\n')) {
        const auto value = line.trimmed();
        if (value.contains("skip", Qt::CaseInsensitive)
            && value.section(QRegularExpression("\\s+"), 0, 0) != "lo0") {
            error = QStringLiteral("PF is configured to skip a network interface");
            return false;
        }
    }
    return true;
}

bool MacKillSwitch::checkEnvironment(QString& error)
{
    const auto root = run({"-sr"});
    const auto children = run({"-a", "com.apple", "-s", "Anchors"});
    const auto interfaces = run({"-v", "-s", "Interfaces"});
    if (root.exitCode || children.exitCode || interfaces.exitCode) {
        error = QStringLiteral("Cannot inspect PF; administrator access is required");
        return false;
    }
    if (!validateEnvironment(root.output, children.output, interfaces.output, error))
        return false;
    if (root.output.indexOf("anchor \"cisco.anyconnect.vpn\"") >= 0
        && root.output.indexOf("anchor \"cisco.anyconnect.vpn\"") < root.output.indexOf("anchor \"com.apple/*\"")) {
        const auto cisco = run({"-a", "cisco.anyconnect.vpn", "-sr"});
        const auto nested = run({"-a", "cisco.anyconnect.vpn", "-s", "Anchors"});
        // An empty Cisco hook is harmless. Reject nested or quick passing
        // rules, which could prevent evaluation of our following anchor.
        if (cisco.exitCode || nested.exitCode || !nested.output.trimmed().isEmpty()
            || QRegularExpression("(?m)^\\s*pass\\b[^\\n]*\\bquick\\b")
                   .match(cisco.output).hasMatch()) {
            error = QStringLiteral("Cisco Secure Client has active PF bypass rules. Disconnect Cisco Secure Client before using this VPN.");
            return false;
        }
    }
    return true;
}

bool MacKillSwitch::readBootPolicy(const QString& path, Policy& policy, bool& enabled, QString& error)
{
    error.clear();
    if (!stateDirectory(path, error))
        return false;
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly) || file.size() > 65536) {
        error = QStringLiteral("Cannot read boot protection configuration");
        return false;
    }
    QJsonParseError parseError;
    const auto object = QJsonDocument::fromJson(file.readAll(), &parseError).object();
    if (parseError.error != QJsonParseError::NoError || object.value("schema").toInt() != 1
        || !object.value("enabled").isBool()) {
        error = QStringLiteral("Invalid boot protection configuration");
        return false;
    }
    policy = {};
    policy.host = object.value("host").toString();
    const auto port = object.value("port").toInt();
    if (port < 1 || port > 65535 || policy.host.isEmpty()) {
        error = QStringLiteral("Invalid boot VPN gateway");
        return false;
    }
    policy.port = quint16(port);
    policy.udpPorts << policy.port;
    for (const auto& ip : object.value("addresses").toArray())
        policy.addresses << ip.toString();
    enabled = object.value("enabled").toBool();
    if (!enabled && policy.addresses.isEmpty())
        return true; // An OFF installation needs neither DNS nor a reachable VPN.
    return !rules(policy, error).isEmpty();
}

bool MacKillSwitch::writeBootPolicy(const QString& path, const Policy& policy, bool enabled, QString& error)
{
    error.clear();
    if ((enabled || !policy.addresses.isEmpty()) && rules(policy, error).isEmpty())
        return false;
    if (policy.host.isEmpty() || policy.port == 0) {
        error = QStringLiteral("Invalid boot VPN gateway");
        return false;
    }
    if (!stateDirectory(path, error))
        return false;
    QJsonArray addresses;
    for (const auto& ip : policy.addresses)
        addresses.append(ip);
    QJsonObject object{{"schema", 1}, {"enabled", enabled}, {"host", policy.host},
        {"port", int(policy.port)}, {"addresses", addresses}};
    return savePrivateJson(path, object, error);
}

bool MacKillSwitch::save(QString& error)
{
    if (!stateDirectory(m_statePath, error))
        return false;
    QJsonArray addresses;
    for (const auto& address : m_policy.addresses)
        addresses.append(address);
    QJsonArray ports;
    for (auto port : m_policy.udpPorts)
        ports.append(int(port));
    QJsonObject object{{"schema", 1}, {"armed", m_armed.load()}, {"token", m_token},
        {"statesCleared", m_statesCleared},
        {"host", m_policy.host}, {"addresses", addresses}, {"port", int(m_policy.port)},
        {"udpPorts", ports}, {"interface", m_policy.interfaceName},
        {"ipv4", m_policy.ipv4}, {"ipv6", m_policy.ipv6}, {"rules", m_expectedRules}};
    return savePrivateJson(m_statePath, object, error);
}

bool MacKillSwitch::load(QString& error)
{
    if (!QFileInfo::exists(m_statePath))
        return true;
    if (!stateDirectory(m_statePath, error))
        return false;
    QFile file(m_statePath);
    if (!file.open(QIODevice::ReadOnly) || file.size() > 65536) {
        error = QStringLiteral("Cannot read kill switch recovery state");
        return false;
    }
    QJsonParseError parseError;
    const auto document = QJsonDocument::fromJson(file.readAll(), &parseError);
    const auto object = document.object();
    if (parseError.error != QJsonParseError::NoError || object.value("schema").toInt() != 1) {
        error = QStringLiteral("Invalid kill switch recovery state");
        return false;
    }
    m_armed = object.value("armed").toBool();
    m_statesCleared = object.value("statesCleared").toBool();
    m_token = object.value("token").toString();
    if (!m_token.isEmpty() && !QRegularExpression("^[0-9]+$").match(m_token).hasMatch()) {
        error = QStringLiteral("Invalid PF recovery token");
        return false;
    }
    m_policy = {};
    m_policy.host = object.value("host").toString();
    m_policy.port = quint16(object.value("port").toInt());
    for (const auto& value : object.value("addresses").toArray())
        m_policy.addresses << value.toString();
    for (const auto& value : object.value("udpPorts").toArray())
        m_policy.udpPorts << quint16(value.toInt());
    m_policy.interfaceName = object.value("interface").toString();
    m_hasTunnel = !m_policy.interfaceName.isEmpty();
    m_policy.ipv4 = object.value("ipv4").toString();
    m_policy.ipv6 = object.value("ipv6").toString();
    m_expectedRules = object.value("rules").toString();
    if (m_armed && rules(m_policy, error).isEmpty())
        return false;
    return true;
}

bool MacKillSwitch::restore(QString& error)
{
    QMutexLocker lock(&m_mutex);
    auto processLock = transaction(error);
    if (!processLock)
        return false;
    if (!load(error))
        return false;
    const auto actual = run({"-a", anchor(), "-sr"});
    if (actual.exitCode) {
        error = QStringLiteral("Cannot read kill switch state; administrator access is required");
        return false;
    }
    if (!m_armed && !filterRules(actual.output).isEmpty()) {
        m_armed = true;
        error = QStringLiteral("Orphaned kill switch rules found. Disable the switch to recover, then reconnect");
        return false;
    }
    if (!m_armed)
        return true;
    // Never adopt a stale/reused utun interface left by another process.
    auto next = m_policy;
    next.interfaceName.clear();
    next.ipv4.clear();
    next.ipv6.clear();
    return apply(next, true, error);
}

bool MacKillSwitch::restoreBootProtection(QString& error)
{
    QMutexLocker lock(&m_mutex);
    auto processLock = transaction(error);
    if (!processLock)
        return false;
    Policy policy;
    bool enabled = false;
    // Re-read intent UNDER the same interprocess lock as GUI mutations. A
    // delayed boot worker must never restore an old ON after the user chose OFF.
    if (!readBootPolicy(m_bootPath, policy, enabled, error))
        return false;
    m_requested = enabled;
    if (!enabled)
        return disableUnlocked(error);
    if (!load(error))
        return false;
    if (m_armed && verifyUnlocked(error))
        return true; // Preserve a live tunnel already established this boot.
    policy.interfaceName.clear();
    policy.ipv4.clear();
    policy.ipv6.clear();
    return apply(policy, true, error);
}

bool MacKillSwitch::apply(const Policy& next, bool flushStates, QString& error)
{
    Q_UNUSED(flushStates);
    const bool trustedGatewayStates = m_armed && m_statesCleared
        && (m_expectedRules.contains("user = 0") || m_expectedRules.contains("user = root"));
    const auto text = rules(next, error);
    if (text.isEmpty() || !checkEnvironment(error))
        return false;
    const auto parsed = run({"-n", "-v", "-a", anchor(), "-f", "-"}, text.toUtf8());
    const auto expected = filterRules(parsed.output);
    if (parsed.exitCode || !expected.endsWith("label \"ocgui_ks_block\"")) {
        error = QStringLiteral("PF rejected the kill switch rules: %1").arg(parsed.error.trimmed());
        return false;
    }
    if (!m_bootPath.isEmpty() && !writeBootPolicy(m_bootPath, next, true, error))
        return false;
    if (m_token.isEmpty()) {
        const auto enabled = run({"-E"});
        const auto match = QRegularExpression("Token\\s*:\\s*([0-9]+)")
                               .match(enabled.output + enabled.error);
        if (enabled.exitCode || !match.hasMatch()) {
            error = QStringLiteral("Cannot acquire the PF enable reference");
            return false;
        }
        m_token = match.captured(1);
        if (!save(error))
            return false;
    }
    // Journal the intended state BEFORE mutation, so a crash can recover it.
    m_policy = next;
    m_hasTunnel = !next.interfaceName.isEmpty();
    m_expectedRules = expected;
    m_armed = true;
    m_statesCleared = false;
    if (!save(error))
        return false;
    const auto loaded = run({"-a", anchor(), "-f", "-"}, text.toUtf8());
    if (loaded.exitCode) {
        error = QStringLiteral("Cannot install kill switch rules: %1").arg(loaded.error.trimmed());
        return false;
    }
    // Re-evaluate existing states on EVERY policy transition, including tunnel
    // removal. Delete only disallowed tuples; never globally flush PF states.
    if (!m_statePruner(next, trustedGatewayStates, error)) {
        save(error);
        error = QStringLiteral("Cannot remove disallowed PF states; rules retained: %1").arg(error);
        return false;
    }
    m_statesCleared = true;
    if (!save(error))
        return false;
    return verifyUnlocked(error);
}

QString MacKillSwitch::dnsBootstrapRules(const Policy& policy, const QStringList& servers, QString& error)
{
    const auto base = rules(policy, error);
    if (base.isEmpty() || servers.size() > 8) return {};
    QString temporary;
    for (const auto& server : servers) {
        QHostAddress address(server);
        if (address.isNull() || address.isMulticast()) { error = "Invalid system DNS server"; return {}; }
        const auto family = address.protocol() == QAbstractSocket::IPv4Protocol ? "inet" : "inet6";
        address.setScopeId({}); // The DNS socket retains the scoped interface.
        temporary += QString("pass out quick %1 proto udp from any to %2 port 53 user 0 keep state (if-bound) label \"ocgui_ks_dns\"\n").arg(family, address.toString());
        temporary += QString("pass out quick %1 proto tcp from any to %2 port 53 user 0 flags S/SA keep state (if-bound) label \"ocgui_ks_dns\"\n").arg(family, address.toString());
    }
    return temporary + base;
}

bool MacKillSwitch::arm(const QUrl& gateway, QString& error)
{
    error.clear();
    QMutexLocker lock(&m_mutex);
    if (!m_requested) return true;
    auto processLock = transaction(error);
    if (!processLock || (!m_armed && QFile::exists(m_statePath) && !load(error))) return false;
    const bool blockOnly = gateway.isEmpty();
    if (!blockOnly && (!gateway.isValid() || gateway.scheme().compare("https", Qt::CaseInsensitive)
        || gateway.host().isEmpty() || !gateway.userInfo().isEmpty() || gateway.hasQuery()
        || gateway.hasFragment() || gateway.port(443) < 1 || gateway.port(443) > 65535)) {
        error = "Kill switch requires a valid HTTPS VPN gateway"; return false;
    }
    const auto host = blockOnly ? QString("unconfigured.invalid") : gateway.host();
    const auto port = quint16(gateway.port(443));
    const bool sameGateway = m_policy.host.compare(host, Qt::CaseInsensitive) == 0 && m_policy.port == port;
    if (m_armed && sameGateway && (!m_policy.addresses.isEmpty() || blockOnly))
        return verifyUnlocked(error) && save(error);
    Policy next;
    next.host = host; next.port = port; next.udpPorts << port;
    QHostAddress literal;
    if (!blockOnly && literal.setAddress(host)) next.addresses << literal.toString();
    if (sameGateway && next.addresses.isEmpty()) next.addresses = m_policy.addresses;
    if (next.addresses.isEmpty() && !m_bootPath.isEmpty()) {
        Policy cached; bool enabled; QString ignored;
        if (readBootPolicy(m_bootPath, cached, enabled, ignored)
            && cached.host.compare(host, Qt::CaseInsensitive) == 0 && cached.port == port)
            next.addresses = cached.addresses;
    }
    if (!m_tunnel.interfaceName.isEmpty()
        && configuredTunnel(m_tunnel.interfaceName, m_tunnel.ipv4, m_tunnel.ipv6, error)) {
        next.interfaceName = m_tunnel.interfaceName;
        next.ipv4 = m_tunnel.ipv4; next.ipv6 = m_tunnel.ipv6; next.udpPorts.append(m_tunnel.udpPorts);
    }
    // Install the block before doing DNS. Changing endpoints never opens the
    // ordinary network or retains the old gateway's exception.
    if (!apply(next, true, error)) return false;
    if (blockOnly || !next.addresses.isEmpty()) return true;
    next.addresses = lookupGatewayUnlocked(host, error);
    if (!error.isEmpty()) return false;
    if (!m_requested) return true;
    return next.addresses.isEmpty() ? true : apply(next, true, error);
}

QStringList MacKillSwitch::lookupGatewayUnlocked(const QString& host, QString& error)
{
    const auto servers = m_dnsServers.isEmpty() ? MacDnsBootstrap::systemServers() : m_dnsServers;
    if (servers.isEmpty()) return {};
    const auto temporary = dnsBootstrapRules(m_policy, servers, error);
    if (temporary.isEmpty()) return {};
    const auto parsed = run({"-n", "-v", "-a", anchor(), "-f", "-"}, temporary.toUtf8());
    if (parsed.exitCode) { error = "PF rejected the temporary DNS bootstrap rules"; return {}; }
    const auto loaded = run({"-a", anchor(), "-f", "-"}, temporary.toUtf8());
    if (loaded.exitCode) { error = "Cannot install temporary DNS bootstrap rules"; return {}; }
    QString lookupError;
    QStringList addresses;
    try { addresses = m_dnsLookup(host, servers, lookupError); }
    catch (...) { lookupError = "DNS lookup failed"; }
    // Temporary DNS rules never enter the journal. Always restore the base
    // policy and prune DNS states before accepting a resolved endpoint.
    const auto base = rules(m_policy, error);
    const auto removed = run({"-a", anchor(), "-f", "-"}, base.toUtf8());
    if (removed.exitCode || !m_statePruner(m_policy, true, error)) {
        error = "Cannot confirm removal of temporary DNS bootstrap access"; return {};
    }
    if (!verifyUnlocked(error)) return {};
    return addresses;
}

void MacKillSwitch::requestEnabled(bool enabled)
{
    m_requested = enabled;
}

bool MacKillSwitch::isRequested() const
{
    return m_requested;
}

bool MacKillSwitch::prepareConnection(const QUrl& gateway, QString& error)
{
    {
        QMutexLocker lock(&m_mutex);
        m_tunnel = {};
        if (!m_armed) { error.clear(); return true; }
    }
    return arm(gateway, error);
}

bool MacKillSwitch::armPinned(const Policy& policy, QString& error)
{
    error.clear();
    QMutexLocker lock(&m_mutex);
    if (!m_requested)
        return true;
    auto processLock = transaction(error);
    if (!processLock || (!m_armed && QFile::exists(m_statePath) && !load(error)))
        return false;
    if (m_armed) {
        if (m_policy.host != policy.host || m_policy.port != policy.port) {
            error = QStringLiteral("A different VPN gateway is already protected");
            return false;
        }
        return verifyUnlocked(error);
    }
    auto next = policy;
    next.interfaceName.clear();
    next.ipv4.clear();
    next.ipv6.clear();
    return apply(next, true, error);
}

bool MacKillSwitch::attachTunnel(const QString& name, const QString& ipv4,
    const QString& ipv6, QString& error)
{
    error.clear();
    QMutexLocker lock(&m_mutex);
    m_tunnel.interfaceName = name;
    m_tunnel.ipv4 = ipv4.section('/', 0, 0);
    m_tunnel.ipv6 = ipv6.section('/', 0, 0);
    if (!m_armed || !m_requested)
        return true; // VPN setup continues when the operator turns protection off.
    auto processLock = transaction(error);
    if (!processLock || !configuredTunnel(name, m_tunnel.ipv4, m_tunnel.ipv6, error))
        return false;
    auto next = m_policy;
    next.interfaceName = m_tunnel.interfaceName;
    next.ipv4 = m_tunnel.ipv4;
    next.ipv6 = m_tunnel.ipv6;
    return apply(next, false, error);
}

bool MacKillSwitch::allowDtlsPort(quint16 port, QString& error)
{
    error.clear();
    QMutexLocker lock(&m_mutex);
    if (port && !m_tunnel.udpPorts.contains(port))
        m_tunnel.udpPorts << port;
    if (!m_armed || !m_requested)
        return true;
    auto processLock = transaction(error);
    if (!processLock)
        return false;
    if (!m_armed || !port) {
        error = QStringLiteral("Invalid DTLS exception");
        return false;
    }
    bool present = m_policy.udpPorts.contains(port);
    for (const auto& endpoint : m_policy.sessionEndpoints) present &= endpoint.udpPorts.contains(port);
    if (present)
        return true;
    auto next = m_policy;
    if (!next.udpPorts.contains(port)) next.udpPorts << port;
    for (auto& endpoint : next.sessionEndpoints)
        if (!endpoint.udpPorts.contains(port)) endpoint.udpPorts << port;
    return apply(next, false, error);
}

bool MacKillSwitch::lockTunnel(QString& error)
{
    error.clear();
    QMutexLocker lock(&m_mutex);
    m_tunnel = {};
    if (!m_armed)
        return true;
    auto processLock = transaction(error);
    if (!processLock)
        return false;
    if (!m_armed)
        return true;
    auto next = m_policy;
    next.sessionEndpoints.clear();
    next.interfaceName.clear();
    next.ipv4.clear();
    next.ipv6.clear();
    return apply(next, false, error);
}

bool MacKillSwitch::disable(QString& error)
{
    m_requested = false;
    error.clear();
    QMutexLocker lock(&m_mutex);
    auto processLock = transaction(error);
    if (!processLock)
        return false;
    return disableUnlocked(error);
}

bool MacKillSwitch::disableUnlocked(QString& error)
{
    if (!m_armed && QFile::exists(m_statePath) && !load(error))
        return false;
    const auto result = run({"-a", anchor(), "-f", "-"});
    const auto actual = run({"-a", anchor(), "-sr"});
    if (result.exitCode || actual.exitCode || !filterRules(actual.output).isEmpty()) {
        error = QStringLiteral("Could not remove the kill switch rules; do not assume network access is restored");
        return false;
    }
    if (!m_bootPath.isEmpty()) {
        auto bootPolicy = m_policy;
        bool enabled = false;
        if (bootPolicy.addresses.isEmpty()
            && !readBootPolicy(m_bootPath, bootPolicy, enabled, error))
            return false;
        if (!writeBootPolicy(m_bootPath, bootPolicy, false, error))
            return false;
    }
    m_armed = false;
    m_hasTunnel = false;
    m_statesCleared = false;
    m_expectedRules.clear();
    if (!m_token.isEmpty()) {
        const auto released = run({"-X", m_token});
        // Apple's pfctl can report an absent reference as "pf: token invalid"
        // instead of exposing DIOCSTOPREF's errno. The anchor was already read
        // back as empty above. Treat only these known C-locale errors as success;
        // permissions, timeouts and other failures retain the recovery journal.
        bool absent = released.error.contains("DIOCSTOPREF: Invalid argument")
            || released.error.contains("DIOCSTOPREF: No such file or directory")
            || released.error.split('\n').contains("pfctl: pf: token invalid");
        if (!absent && released.error.contains("pf not enabled")) {
            const auto status = run({"-s", "info"});
            absent = !status.exitCode && status.output.contains("Status: Disabled");
        }
        if (released.exitCode && !absent) {
            save(error);
            error = QStringLiteral("Rules removed, but the PF reference needs cleanup; retry disabling the switch: %1")
                .arg(released.error.trimmed());
            return false;
        }
    }
    m_token.clear();
    m_policy = {};
    if (QFileInfo::exists(m_statePath) && !QFile::remove(m_statePath)) {
        error = QStringLiteral("Rules removed, but recovery state could not be deleted");
        return false;
    }
    return true;
}

bool MacKillSwitch::verifyUnlocked(QString& error)
{
    error.clear();
    if (!m_armed) {
        const auto actual = run({"-a", anchor(), "-sr"});
        if (actual.exitCode || !filterRules(actual.output).isEmpty()) {
            error = "OpenConnect blocking is not confirmed OFF; inspect service diagnostics or disable explicitly";
            return false;
        }
        return true;
    }
    if (!m_policy.addresses.isEmpty()
        && !m_expectedRules.contains("user = 0") && !m_expectedRules.contains("user = root")) {
        error = "Legacy firewall policy requires the root-only gateway upgrade";
        return false;
    }
    if (!m_statesCleared) {
        error = QStringLiteral("Existing connection states were not cleared; protection cannot be confirmed");
        return false;
    }
    const auto status = run({"-s", "info"});
    const auto actual = run({"-a", anchor(), "-sr"});
    if (status.exitCode || !status.output.contains("Status: Enabled")
        || actual.exitCode || m_expectedRules.isEmpty()
        || filterRules(actual.output) != m_expectedRules || !checkEnvironment(error)) {
        if (error.isEmpty())
            error = QStringLiteral("PF protection could not be verified. Network protection is uncertain; reconnect or disable explicitly");
        return false;
    }
    return true;
}

bool MacKillSwitch::verify(QString& error)
{
    QMutexLocker lock(&m_mutex);
    return verifyUnlocked(error);
}

QJsonObject MacKillSwitch::diagnostics()
{
    // Read-only and available over the authenticated local socket. No journal,
    // PF enable token, profile, credentials, or environment is disclosed.
    QJsonObject report;
    const QList<QPair<QString, QStringList>> commands{
        {"rootRules", {"-sr"}}, {"childAnchors", {"-a", "com.apple", "-s", "Anchors"}},
        {"interfaces", {"-v", "-s", "Interfaces"}}};
    for (const auto& command : commands) {
        const auto result = run(command.second);
        report.insert(command.first, result.output.left(6000));
        if (result.exitCode) report.insert(command.first + "Error", result.error.left(1000));
    }
    return report;
}

bool MacKillSwitch::verifySavedState(QString& error)
{
    QMutexLocker lock(&m_mutex);
    if (!load(error))
        return false;
    if (!m_armed) {
        error = QStringLiteral("No armed kill switch state was found");
        return false;
    }
    return verifyUnlocked(error);
}

bool MacKillSwitch::isArmed() const
{
    return m_armed;
}

bool MacKillSwitch::hasTunnel() const
{
    return m_armed && m_hasTunnel;
}

bool MacKillSwitch::checkGatewayRoute(QString& error) const
{
    QMutexLocker lock(&m_mutex);
    for (const auto& ip : m_policy.addresses) {
        QProcess process;
        auto environment = QProcessEnvironment::systemEnvironment();
        environment.insert("LC_ALL", "C");
        process.setProcessEnvironment(environment);
        QStringList args{"-n", "get"};
        if (QHostAddress(ip).protocol() == QAbstractSocket::IPv6Protocol)
            args << "-inet6";
        args << ip;
        process.start("/sbin/route", args);
        if (!process.waitForStarted(2000) || !process.waitForFinished(3000)) {
            process.kill();
            process.waitForFinished(1000);
            continue;
        }
        const auto output = QString::fromUtf8(process.readAllStandardOutput());
        const auto match = QRegularExpression("(?m)^\\s*interface:\\s*(\\S+)").match(output);
        if (process.exitCode() == 0 && match.hasMatch()
            && !QRegularExpression("^(utun|tun|tap)[0-9]+$").match(match.captured(1)).hasMatch())
            return true;
    }
    error = QStringLiteral("No direct route to the VPN gateway. Disconnect other VPN clients, check Wi-Fi/Ethernet, and try Connect again. Kill switch remains enabled.");
    return false;
}

int MacKillSwitch::resolvePinned(const QString& host, const QStringList& addresses,
    const char* node, const char* service, const struct addrinfo* hints,
    struct addrinfo** result)
{
    if (!result)
        return EAI_FAIL;
    *result = nullptr;
    if (!node || !service)
        return EAI_NONAME;
    const auto requested = QString::fromUtf8(node);
    QStringList selected;
    if (requested.compare(host, Qt::CaseInsensitive) == 0) {
        selected = addresses;
    } else {
        const QHostAddress numeric(requested);
        for (const auto& ip : addresses) {
            if (!numeric.isNull() && numeric == QHostAddress(ip))
                selected << ip;
        }
    }
    if (selected.isEmpty())
        return EAI_NONAME; // Never fall back to a system DNS lookup.
    bool validPort = false;
    const auto port = QString::fromUtf8(service).toUInt(&validPort);
    if (!validPort || !port || port > 65535)
        return EAI_SERVICE;
    struct addrinfo numericHints{};
    if (hints)
        numericHints = *hints;
    numericHints.ai_flags |= AI_NUMERICHOST | AI_NUMERICSERV;
    struct addrinfo** tail = result;
    int lastError = EAI_NONAME;
    for (const auto& ip : selected) {
        struct addrinfo* entry = nullptr;
        const auto bytes = ip.toUtf8();
        const int status = ::getaddrinfo(bytes.constData(), service, &numericHints, &entry);
        if (status != 0) {
            lastError = status;
            continue;
        }
        *tail = entry;
        while (*tail)
            tail = &(*tail)->ai_next;
    }
    return *result ? 0 : lastError;
}

int MacKillSwitch::resolve(const char* node, const char* service,
    const struct addrinfo* hints, struct addrinfo** result)
{
    QMutexLocker lock(&m_mutex);
    if (!m_armed && !m_requested) {
        lock.unlock(); return ::getaddrinfo(node, service, hints, result);
    }
    if (result) *result = nullptr;
    if (!m_armed || !node) return EAI_FAIL;
    const auto host = QString::fromUtf8(node);
    bool valid = false;
    quint16 port = service ? QString::fromLatin1(service).toUShort(&valid) : 443;
    if (service && QString::fromLatin1(service) == "https") { port = 443; valid = true; }
    if ((service && !valid) || !port || host.size() > 253) return EAI_SERVICE;
    const auto numeric = QHostAddress(host);
    if (port == m_policy.port && (host.compare(m_policy.host, Qt::CaseInsensitive) == 0
            || m_policy.addresses.contains(numeric.toString())))
        return resolvePinned(m_policy.host, m_policy.addresses, node, service, hints, result);
    for (const auto& endpoint : m_policy.sessionEndpoints)
        if (port == endpoint.port && (host.compare(endpoint.host, Qt::CaseInsensitive) == 0
                || endpoint.addresses.contains(numeric.toString())))
            return resolvePinned(endpoint.host, endpoint.addresses, node, service, hints, result);
    // Only libOpenConnect's resolver callback reaches this path: a negotiated
    // gateway/redirect may have a separate hostname or port. Pin it for this
    // session, keep all normal traffic blocked, and retain TLS hostname checks.
    if (!m_requested || m_policy.sessionEndpoints.size() >= 16) return EAI_NONAME;
    QString error;
    QUrl candidate; candidate.setScheme("https"); candidate.setHost(host); candidate.setPort(port);
    if (!candidate.isValid() || candidate.host().isEmpty()
        || QUrl::toAce(candidate.host()).compare(QUrl::toAce(host), Qt::CaseInsensitive)) return EAI_NONAME;
    auto processLock = transaction(error);
    if (!processLock) return EAI_FAIL;
    Endpoint endpoint; endpoint.host = host; endpoint.port = port; endpoint.udpPorts << port;
    if (!numeric.isNull()) endpoint.addresses << numeric.toString();
    else if (host.compare(m_policy.host, Qt::CaseInsensitive) == 0) endpoint.addresses = m_policy.addresses;
    else endpoint.addresses = lookupGatewayUnlocked(host, error);
    if (!error.isEmpty() || endpoint.addresses.isEmpty() || !m_requested) return EAI_NONAME;
    auto next = m_policy; next.sessionEndpoints << endpoint;
    if (!apply(next, true, error)) return EAI_FAIL;
    return resolvePinned(endpoint.host, endpoint.addresses, node, service, hints, result);
}
