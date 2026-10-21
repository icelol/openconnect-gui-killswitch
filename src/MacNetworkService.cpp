// SPDX-License-Identifier: GPL-2.0-or-later
#include "MacNetworkService.h"
#include "MacBootGuard.h"
#include "MacPfStates.h"
#include "VpnProgress.h"
#include "server_storage.h"
#include "vpninfo.h"
#include <QCoreApplication>
#include <QFile>
#include <QFileInfo>
#include <QFutureWatcher>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLockFile>
#include <QRandomGenerator>
#include <QRegularExpression>
#include <QSet>
#include <QtConcurrent/QtConcurrentRun>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>
#include <csignal>
#include <cstdio>

namespace {
constexpr qint64 maxMessage = 64 * 1024;
volatile std::sig_atomic_t stopping = 0;
void requestStop(int) { stopping = 1; }
bool supportedKeys(const QJsonObject& params, const QSet<QString>& keys)
{
    for (auto it = params.begin(); it != params.end(); ++it)
        if (!keys.contains(it.key())) return false;
    return true;
}
void send(QLocalSocket* socket, const QJsonObject& message)
{
    const auto data = QJsonDocument(message).toJson(QJsonDocument::Compact) + '\n';
    if (socket->bytesToWrite() > 1024 * 1024) { socket->abort(); return; }
    socket->write(data);
}
}

QString networkServiceSocket()
{
    return "/var/run/openconnect-gui-killswitch/control.sock";
}

ServiceVpnSession::ServiceVpnSession(MacKillSwitch* guard, const QJsonObject& profile, QObject* parent)
    : QThread(parent), m_guard(guard), m_profile(profile)
{
    m_connectDeadline.setParent(this);
    m_connectDeadline.setObjectName("vpnConnectDeadline");
    m_connectDeadline.setSingleShot(true);
    m_connectDeadline.setInterval(20000);
    connect(&m_connectDeadline, &QTimer::timeout, this, [this] {
        if (m_cancelled || m_connected || awaitingInput()) return;
        error("VPN connection timed out before login completed. Check the network/TLS settings and the connection log.");
        cancel();
    });
    connect(this, &ServiceVpnSession::notification, this, [this](const QJsonObject& event) {
        const auto kind = event.value("event").toString();
        if (kind == "auth" || kind == "connected" || kind == "error") m_connectDeadline.stop();
    });
    m_connectDeadline.start();
}

ServiceVpnSession::~ServiceVpnSession() { cancel(); wait(); }

void ServiceVpnSession::cancel()
{
    m_cancelled = true;
    QMutexLocker lock(&m_lock);
    if (m_fd >= 0) { const char cmd = OC_CMD_CANCEL; ::write(m_fd, &cmd, 1); }
    m_answerReady.wakeAll();
}

void ServiceVpnSession::requestStats()
{
    QMutexLocker lock(&m_lock);
    if (m_fd >= 0) { const char cmd = OC_CMD_STATS; ::write(m_fd, &cmd, 1); }
}

bool ServiceVpnSession::awaitingInput() const
{
    QMutexLocker lock(&m_lock);
    return !m_challenge.isEmpty();
}

bool ServiceVpnSession::answer(const QString& challenge, bool accepted, const QString& answer)
{
    QMutexLocker lock(&m_lock);
    if (m_challenge.isEmpty() || challenge != m_challenge || answer.size() > 4096 || m_answered)
        return false;
    m_answer = answer;
    m_accepted = accepted;
    if (!accepted) {
        m_cancelled = true;
        if (m_fd >= 0) { const char cmd = OC_CMD_CANCEL; ::write(m_fd, &cmd, 1); }
    }
    m_answered = true;
    m_answerReady.wakeAll();
    if (accepted) m_connectDeadline.start();
    return true;
}

bool ServiceVpnSession::input(const QString& title, const QString& label, const QStringList& choices,
    bool secret, const QString& banner, const QString& message, QString& answer)
{
    QMutexLocker lock(&m_lock);
    if (m_cancelled || choices.size() > 256)
        return false;
    m_challenge = QString::number(QRandomGenerator::system()->generate64(), 16);
    m_answer.clear(); m_answered = false; m_accepted = false;
    emit notification({{"event", "auth"}, {"challenge", m_challenge}, {"title", title.left(256)},
        {"label", label.left(2048)}, {"secret", secret}, {"choices", QJsonArray::fromStringList(choices)},
        {"banner", banner.left(4096)}, {"message", message.left(4096)}});
    QDeadlineTimer deadline(120000);
    while (!m_answered && !m_cancelled && !deadline.hasExpired())
        m_answerReady.wait(&m_lock, deadline);
    const bool ok = m_answered && m_accepted && !m_cancelled;
    answer = ok ? m_answer : QString();
    m_challenge.clear(); m_answer.fill(QChar(0)); m_answer.clear();
    return ok;
}

void ServiceVpnSession::connected(const QString& dns, const QString& ip, const QString& ip6,
    const QString& cstp, const QString& dtls)
{
    m_connected = true;
    emit notification({{"event", "connected"}, {"dns", dns}, {"ip", ip}, {"ip6", ip6},
        {"cstp", cstp}, {"dtls", dtls}});
}

void ServiceVpnSession::stats(const oc_stats* value, const QString& dtls)
{
    emit notification({{"event", "stats"}, {"tx", QString::number(value->tx_bytes)},
        {"rx", QString::number(value->rx_bytes)}, {"dtls", dtls}});
}

void ServiceVpnSession::error(const QString& message)
{
    if (!m_cancelled && !m_reportedError.exchange(true)) {
        emit notification({{"event", "error"}, {"message", message.left(4096)}});
    }
}

void ServiceVpnSession::firewallError(const QString& message)
{
    emit notification({{"event", "firewallError"}, {"message", message.left(4096)}});
}

void ServiceVpnSession::progress(int level, const QString& message)
{
    if (level > PRG_INFO || m_cancelled) return;
    const auto safe = safeVpnProgress(message);
    if (safe.isEmpty()) return;
    emit notification({{"event", "progress"}, {"message", safe}, {"level", level}});
}

void ServiceVpnSession::run()
{
    auto profile = new StoredServer;
    profile->set_server_gateway(m_profile.value("gateway").toString());
    profile->set_protocol_name(m_profile.value("protocol").toString("anyconnect"));
    profile->set_proxy(false);
    profile->set_username(m_profile.value("username").toString().left(1024));
    profile->set_groupname(m_profile.value("group").toString().left(1024));
    profile->set_disable_udp(m_profile.value("disableUdp").toBool());
    profile->set_tls12_only(m_profile.value("tls12Only").toBool());
    profile->set_legacy_auth(m_profile.value("legacyAuth").toBool());
    profile->set_reconnect_timeout(qBound(1, m_profile.value("reconnectTimeout").toInt(300), 3600));
    profile->set_dtls_reconnect_timeout(qBound(1, m_profile.value("dtlsPeriod").toInt(25), 120));
    // Credentials are requested over authenticated IPC and retained only in
    // this process/session. No service-side QSettings writes or shell input.
    try {
        VpnInfo vpn("AnyConnect-compatible OpenConnect GUI VPN Agent", profile,
            static_cast<VpnCallbacks*>(this));
        profile = nullptr; // VpnInfo owns it now.
        vpn.killSwitch = m_guard;
        vpn.setUrl(QUrl(m_profile.value("gateway").toString()));
        { QMutexLocker lock(&m_lock); m_fd = vpn.get_cmd_fd(); }
        if (m_cancelled) cancel();
        if (!m_cancelled) {
            const int result = vpn.connect();
            if (result == 0 && !m_cancelled) vpn.mainloop();
            else if (!m_cancelled) error(vpn.last_err);
        }
        { QMutexLocker lock(&m_lock); m_fd = -1; }
    } catch (const std::exception& exception) {
        delete profile;
        error(QString::fromUtf8(exception.what()));
    }
    QString cleanup;
    if (!m_guard->lockTunnel(cleanup)) firewallError(cleanup);
}

MacNetworkService::MacNetworkService(MacKillSwitch* guard, uint allowedUid, const QString& socket,
    const QString& initialGateway, QObject* parent)
    : QObject(parent), m_guard(guard), m_allowedUid(allowedUid), m_socketPath(socket),
      m_gateway(initialGateway), m_desired(guard->isRequested())
{
    connect(&m_server, &QLocalServer::newConnection, this, &MacNetworkService::accept);
    connect(&m_monitor, &QTimer::timeout, this, [this] {
        if (m_session && m_vpnState == "connected") m_session->requestStats();
        if (m_busy || m_recoveryRequired || m_verification.isRunning() || !m_guard->isArmed()) return;
        auto watcher = new QFutureWatcher<QString>(this);
        connect(watcher, &QFutureWatcher<QString>::finished, this, [this, watcher] {
            const auto error = watcher->result(); watcher->deleteLater();
            if (!m_busy && m_guard->isArmed()) {
                m_verified = error.isEmpty();
                if (!error.isEmpty()) m_error = error;
                broadcast();
            }
        });
        m_verification = QtConcurrent::run([this] { QString e; m_guard->verify(e); return e; });
        watcher->setFuture(m_verification);
    });
}

MacNetworkService::~MacNetworkService()
{
    m_monitor.stop();
    if (m_session) { m_session->cancel(); m_session->wait(); }
    m_firewallTask.waitForFinished(); m_verification.waitForFinished();
    for (auto client : m_clients) { client->disconnect(this); client->abort(); }
    m_clients.clear();
    m_server.close();
}

bool MacNetworkService::validGateway(const QString& candidate, QString& error)
{
    const QUrl url(candidate);
    if (candidate.size() > 2048 || !url.isValid() || url.scheme() != "https"
        || url.host().isEmpty() || url.port(443) < 1 || url.port(443) > 65535
        || !url.userInfo().isEmpty() || url.hasQuery() || url.hasFragment()) {
        error = "Enter a valid HTTPS VPN gateway without embedded credentials, query or fragment";
        return false;
    }
    return true;
}

bool MacNetworkService::supportedProtocol(const QString& protocol)
{
    struct oc_vpn_proto* protocols = nullptr;
    bool found = false;
    if (openconnect_get_supported_protocols(&protocols) >= 0) {
        for (auto entry = protocols; entry->name; ++entry)
            found |= protocol == QString::fromUtf8(entry->name);
        openconnect_free_supported_protocols(protocols);
    }
    return found;
}

bool MacNetworkService::start(QString& error, const QString& recoveryError)
{
    const auto parent = QFileInfo(m_socketPath).absolutePath();
    struct stat directory{};
    if (::lstat(QFile::encodeName(parent).constData(), &directory) != 0
        || !S_ISDIR(directory.st_mode) || directory.st_uid != ::geteuid() || (directory.st_mode & 0022)) {
        error = "Unsafe service socket directory";
        return false;
    }
    m_instance = std::make_unique<QLockFile>(parent + "/service.lock");
    m_instance->setStaleLockTime(0);
    if (!m_instance->tryLock(0)) { error = "Network service is already running"; return false; }
    struct stat old{};
    const auto path = QFile::encodeName(m_socketPath);
    if (::lstat(path.constData(), &old) == 0) {
        if (!S_ISSOCK(old.st_mode) || (old.st_uid != ::geteuid() && old.st_uid != m_allowedUid)) {
            error = "Unsafe existing service socket"; return false;
        }
        if (::unlink(path.constData()) != 0) { error = "Cannot remove stale service socket"; return false; }
    }
    if (!m_server.listen(m_socketPath)) { error = m_server.errorString(); return false; }
    if (::chmod(path.constData(), 0600) != 0 || ::chown(path.constData(), m_allowedUid, -1) != 0) {
        error = "Cannot protect network service socket"; m_server.close(); return false;
    }
    // Recovery failures must never remove the control path needed to turn OFF.
    // Keep the failure visible; accepting IPC does not claim a working firewall.
    m_recoveryRequired = !recoveryError.isEmpty();
    m_verified = !m_recoveryRequired && m_guard->verify(error);
    if (!m_verified) m_error = recoveryError.isEmpty() ? error : recoveryError;
    m_monitor.start(3000);
    return true;
}

QJsonObject MacNetworkService::status() const
{
    auto vpn = m_vpnDetails;
    vpn.insert("state", m_vpnState);
    return {{"schema", 1}, {"capabilities", QJsonObject{{"explicitOff", true}}}, {"revision", QString::number(m_revision)},
        {"firewall", QJsonObject{{"requested", m_desired}, {"armed", m_guard->isArmed()},
            {"verified", m_verified}, {"busy", m_busy}, {"recoveryRequired", m_recoveryRequired},
            {"tunnel", m_guard->hasTunnel()}, {"error", m_error}}},
        {"vpn", vpn}};
}

void MacNetworkService::reply(QLocalSocket* socket, const QJsonValue& id,
    const QJsonObject& result, const QString& error)
{
    send(socket, {{"id", id}, {"result", result}, {"error", error}});
}

void MacNetworkService::broadcast()
{
    ++m_revision;
    const QJsonObject message{{"event", "status"}, {"status", status()}};
    for (auto client : m_clients) send(client, message);
    emit changed();
}

void MacNetworkService::accept()
{
    while (auto socket = m_server.nextPendingConnection()) {
        uid_t uid; gid_t gid;
        if (::getpeereid(int(socket->socketDescriptor()), &uid, &gid) != 0 || (uid != m_allowedUid && uid != 0)) {
            socket->abort(); socket->deleteLater(); continue;
        }
        socket->setReadBufferSize(maxMessage + 1);
        m_clients << socket;
        connect(socket, &QLocalSocket::readyRead, this, [this, socket] {
            if (socket->bytesAvailable() > maxMessage) { socket->abort(); return; }
            int messages = 0;
            while (socket->canReadLine() && ++messages <= 64) {
                QJsonParseError parse;
                const auto data = socket->readLine(maxMessage + 1);
                const auto document = QJsonDocument::fromJson(data, &parse);
                if (data.size() > maxMessage || parse.error != QJsonParseError::NoError || !document.isObject()) {
                    socket->abort(); return;
                }
                dispatch(socket, document.object());
            }
            if (socket->canReadLine()) socket->abort();
        });
        connect(socket, &QLocalSocket::disconnected, this, [this, socket] {
            m_clients.removeAll(socket);
            if (m_owner == socket && m_session && m_session->awaitingInput()) m_session->cancel();
            if (m_owner == socket && !m_pendingProfile.isEmpty()) {
                m_pendingProfile = {}; m_vpnState = "disconnected"; broadcast();
            }
            socket->deleteLater();
        });
        send(socket, {{"event", "status"}, {"status", status()}});
    }
}

void MacNetworkService::dispatch(QLocalSocket* socket, const QJsonObject& request)
{
    const auto id = request.value("id");
    const auto method = request.value("method").toString();
    const auto params = request.value("params").toObject();
    if (!id.isDouble()) { socket->abort(); return; }
    if (!request.value("params").isObject()) { reply(socket, id, {}, "params must be an object"); return; }
    QString error;
    if (method == "status") { reply(socket, id, status()); return; }
    if (method == "firewall") {
        const auto gateway = params.value("gateway").toString(m_gateway);
        if (!supportedKeys(params, {"enabled", "gateway"})) { reply(socket, id, {}, "Unsupported firewall parameter"); return; }
        const bool enabled = params.value("enabled").toBool();
        if (!params.value("enabled").isBool()
            || (enabled && !gateway.isEmpty() && !validGateway(gateway, error))) {
            reply(socket, id, {}, error.isEmpty() ? "enabled must be boolean" : error); return;
        }
        if (enabled && m_session && gateway != m_gateway) {
            reply(socket, id, {}, "Disconnect the current VPN before choosing another gateway"); return;
        }
        m_desired = params.value("enabled").toBool(); m_gateway = gateway; ++m_generation;
        m_guard->requestEnabled(m_desired); // OFF intent never waits for DNS/auth.
        std::fprintf(stderr, "Firewall request: enabled=%d\n", int(m_desired));
        reply(socket, id, {{"accepted", true}});
        changeFirewall(); return;
    }
    if (method == "connect") {
        if (m_session || !m_pendingProfile.isEmpty()) { reply(socket, id, {}, "VPN session is already running"); return; }
        if (!supportedKeys(params, {"gateway", "protocol", "proxy", "username", "group",
                "disableUdp", "tls12Only", "legacyAuth", "reconnectTimeout", "dtlsPeriod"})) {
            reply(socket, id, {}, "Unsupported VPN parameter; scripts, files and saved credentials are not accepted"); return;
        }
        if (!validGateway(params.value("gateway").toString(), error)
            || (params.contains("tls12Only") && !params.value("tls12Only").isBool())
            || (params.contains("legacyAuth") && !params.value("legacyAuth").isBool())
            || !supportedProtocol(params.value("protocol").toString("anyconnect")) || params.value("proxy").toBool()) {
            reply(socket, id, {}, error.isEmpty() ? "Select a supported OpenConnect protocol without a proxy" : error); return;
        }
        m_gateway = params.value("gateway").toString();
        m_pendingProfile = params; m_owner = socket; m_vpnState = "connecting";
        reply(socket, id, {{"accepted", true}}); broadcast();
        if (!m_busy) startVpn();
        return;
    }
    if (method == "disconnect") {
        m_pendingProfile = {};
        if (m_session) { m_vpnState = "disconnecting"; m_session->cancel(); }
        else m_vpnState = "disconnected";
        reply(socket, id, {{"accepted", true}}); broadcast(); return;
    }
    if (method == "auth") {
        const bool ok = m_owner == socket && m_session && params.value("accepted").isBool()
            && m_session->answer(params.value("challenge").toString(), params.value("accepted").toBool(),
                params.value("answer").toString());
        reply(socket, id, {}, ok ? QString() : "No matching authentication challenge"); return;
    }
    reply(socket, id, {}, "Unsupported service command");
}

void MacNetworkService::changeFirewall()
{
    if (m_busy) { broadcast(); return; }
    m_busy = true; m_verified = false; m_error.clear();
    const bool enabled = m_desired;
    const auto generation = m_generation;
    const auto gateway = m_gateway;
    auto watcher = new QFutureWatcher<QString>(this);
    connect(watcher, &QFutureWatcher<QString>::finished, this, [this, watcher, generation] {
        m_error = watcher->result(); watcher->deleteLater(); m_busy = false;
        if (generation != m_generation) { changeFirewall(); return; }
        m_verified = m_error.isEmpty();
        m_recoveryRequired = !m_error.isEmpty();
        if (!m_error.isEmpty()) { m_desired = m_guard->isArmed(); m_guard->requestEnabled(m_desired); }
        std::fprintf(stderr, "Firewall result: requested=%d armed=%d verified=%d\n",
            int(m_desired), int(m_guard->isArmed()), int(m_verified));
        broadcast();
        if (!m_pendingProfile.isEmpty()) startVpn();
    });
    m_firewallTask = QtConcurrent::run([this, enabled, gateway] {
        QString error;
        if (enabled) m_guard->arm(QUrl(gateway), error); else m_guard->disable(error);
        return error;
    });
    watcher->setFuture(m_firewallTask);
    broadcast();
}

void MacNetworkService::startVpn()
{
    if (m_pendingProfile.isEmpty() || m_session) return;
    m_session = new ServiceVpnSession(m_guard, m_pendingProfile, this);
    m_pendingProfile = {};
    connect(m_session, &ServiceVpnSession::notification, this, &MacNetworkService::sessionEvent);
    connect(m_session, &QThread::finished, this, [this] {
        auto old = m_session; m_session = nullptr; old->deleteLater();
        m_vpnState = "disconnected"; m_vpnDetails = {}; broadcast();
    });
    m_session->start();
}

void MacNetworkService::sessionEvent(const QJsonObject& event)
{
    const auto kind = event.value("event").toString();
    if (kind == "auth") {
        if (m_owner) send(m_owner, event); else if (m_session) m_session->cancel();
    } else if (kind == "progress") {
        if (m_owner) send(m_owner, event);
    } else if (kind == "connected") {
        m_vpnDetails = event; m_vpnDetails.remove("event"); m_vpnState = "connected"; broadcast();
    } else if (kind == "firewallError") {
        if (!event.value("message").toString().isEmpty()) {
            m_error = event.value("message").toString(); m_verified = false;
        }
        broadcast();
    } else {
        for (auto client : m_clients) send(client, event);
    }
}

int runNetworkService(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    if (::geteuid() != 0) { std::fprintf(stderr, "Network service requires root\n"); return 1; }
    ::signal(SIGPIPE, SIG_IGN);
    ::signal(SIGTERM, requestStop);
    ::signal(SIGINT, requestStop);
    QTimer shutdown;
    QObject::connect(&shutdown, &QTimer::timeout, &app, [&app] { if (stopping) app.quit(); });
    shutdown.start(100);
    qputenv("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
    const QString configPath = "/Library/Application Support/OpenConnect-GUI-KillSwitch/service.json";
    struct stat info{};
    if (::lstat(QFile::encodeName(configPath).constData(), &info) != 0 || !S_ISREG(info.st_mode)
        || info.st_uid != 0 || (info.st_mode & 0077)) { std::fprintf(stderr, "Unsafe service configuration\n"); return 1; }
    QFile config(configPath);
    if (!config.open(QIODevice::ReadOnly) || config.size() > 4096) return 1;
    const auto settings = QJsonDocument::fromJson(config.readAll()).object();
    const auto uid = settings.value("uid").toInt(-1);
    if (settings.value("schema").toInt() != 2 || uid < 500) return 1;
    const QString runtime = "/var/run/openconnect-gui-killswitch";
    const auto bytes = QFile::encodeName(runtime);
    if (::lstat(bytes.constData(), &info) != 0 && ::mkdir(bytes.constData(), 0755) != 0) return 1;
    if (::lstat(bytes.constData(), &info) != 0 || !S_ISDIR(info.st_mode) || info.st_uid != 0 || (info.st_mode & 0022)) return 1;
    if (::chmod(bytes.constData(), 0755) != 0) return 1;
    openconnect_init_ssl();
    MacKillSwitch guard({}, runtime + "/state.json", bootProtectionPath());
    QString error;
    // A restarted service owns no old VPN worker. Remove any stale/reused utun
    // exception before accepting commands, while preserving explicit OFF.
    QString recoveryError;
    if (!guard.restoreBootProtection(recoveryError) || !guard.lockTunnel(recoveryError))
        std::fprintf(stderr, "Cannot restore firewall; control remains available for OFF: %s\n", qPrintable(recoveryError));
    MacNetworkService service(&guard, uint(uid), networkServiceSocket());
    if (!service.start(error, recoveryError)) { std::fprintf(stderr, "%s\n", qPrintable(error)); return 1; }
    return app.exec();
}
