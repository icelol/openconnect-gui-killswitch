// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once

#include <QMutex>
#include <QStringList>
#include <QUrl>
#include <QJsonObject>
#include <functional>
#include <memory>
#include <atomic>
class QLockFile;
struct addrinfo;

// PF rules outlive this object and the GUI process. Only disable() removes them.
// No global ruleset reload, PF disable, or automatic fail-open cleanup is used.
class NetworkGuard {
public:
    struct Result {
        int exitCode = -1;
        QString output;
        QString error;
    };
    using Runner = std::function<Result(const QStringList&, const QByteArray&)>;

    struct Endpoint {
        QString host;
        QStringList addresses;
        quint16 port = 443;
        QList<quint16> udpPorts;
    };
    struct Policy {
        QString host;
        QStringList addresses;
        quint16 port = 443;
        QList<quint16> udpPorts;
        QString interfaceName;
        QString ipv4;
        QString ipv6;
        QList<Endpoint> sessionEndpoints;
    };
    using StatePruner = std::function<bool(const Policy&, bool, QString&)>;
    using DnsLookup = std::function<QStringList(const QString&, const QStringList&, QString&)>;

    explicit NetworkGuard(Runner runner = {},
        QString statePath = QStringLiteral("/var/run/openconnect-gui-killswitch/state.json"),
        QString bootPath = {}, StatePruner statePruner = {}, DnsLookup dnsLookup = {},
        QStringList dnsServers = {});
    ~NetworkGuard();
    // Destructor deliberately leaves the firewall armed.
    bool restore(QString& error);
    bool restoreBootProtection(QString& error);
    bool arm(const QUrl& gateway, QString& error);
    // Cached numeric endpoints: boot must not need a DNS exception.
    bool armPinned(const Policy& policy, QString& error);
    // Record UI intent immediately, before a worker can acquire the mutex.
    void requestEnabled(bool enabled);
    bool isRequested() const;
    // Connect never arms the firewall or refuses merely because a route is down.
    bool prepareConnection(const QUrl& gateway, QString& error);
    static bool readBootPolicy(const QString& path, Policy& policy, bool& enabled, QString& error);
    static bool writeBootPolicy(const QString& path, const Policy& policy, bool enabled, QString& error);
    bool attachTunnel(const QString& name, const QString& ipv4,
        const QString& ipv6, QString& error);
    bool allowDtlsPort(quint16 port, QString& error);
    bool lockTunnel(QString& error);
    bool disable(QString& error);
    bool verify(QString& error);
    bool verifySavedState(QString& error);
    bool isArmed() const;
    bool hasTunnel() const;
    bool checkGatewayRoute(QString& error) const;
    QJsonObject diagnostics();
    int resolve(const char* node, const char* service,
        const struct addrinfo* hints, struct addrinfo** result);
    static int resolvePinned(const QString& host, const QStringList& addresses,
        const char* node, const char* service, const struct addrinfo* hints,
        struct addrinfo** result);

    static QString anchor();
    static QString rules(const Policy& policy, QString& error);
    static QString dnsBootstrapRules(const Policy& policy, const QStringList& servers, QString& error);
    static bool validateEnvironment(const QString& rootRules,
        const QString& childAnchors, const QString& interfaces, QString& error);

private:
#ifdef Q_OS_WIN
    struct WindowsState;
    std::unique_ptr<WindowsState> m_windows;
#endif
    Result run(const QStringList& args, const QByteArray& input = {});
    bool checkEnvironment(QString& error);
    bool apply(const Policy& next, bool flushStates, QString& error);
    bool verifyUnlocked(QString& error);
    bool save(QString& error);
    bool load(QString& error);
    bool disableUnlocked(QString& error);
    QStringList lookupGatewayUnlocked(const QString& host, QString& error);
    static QString filterRules(const QString& text);
    std::unique_ptr<QLockFile> transaction(QString& error) const;

    Runner m_runner;
    StatePruner m_statePruner;
    DnsLookup m_dnsLookup;
    QStringList m_dnsServers;
    QString m_statePath;
    QString m_bootPath;
    mutable QMutex m_mutex;
    Policy m_policy;
    Policy m_tunnel;
    QString m_token;
    QString m_expectedRules;
    std::atomic<bool> m_armed{false};
    std::atomic<bool> m_hasTunnel{false};
    bool m_statesCleared = false;
    std::atomic<bool> m_requested{true};
};
