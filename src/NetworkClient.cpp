// SPDX-License-Identifier: GPL-2.0-or-later
#include "NetworkClient.h"
#include "NetworkService.h"
#include <QJsonDocument>
#include <QCoreApplication>
#include <cstdio>
#ifdef Q_OS_WIN
#include "WindowsSystemService.h"
#else
#include <sys/socket.h>
#include <unistd.h>
#endif

NetworkClient::NetworkClient(QObject* parent, QString socketPath, uint expectedUid)
    : QObject(parent), m_path(socketPath.isEmpty() ? networkServiceSocket() : socketPath),
      m_expectedUid(expectedUid)
{
    m_socket.setReadBufferSize(65537);
    m_clock.start();
    m_poll.setInterval(2000);
    connect(&m_poll, &QTimer::timeout, this, &NetworkClient::poll);
    m_poll.start();
    m_retry.setInterval(1000);
    connect(&m_retry, &QTimer::timeout, this, &NetworkClient::start);
    connect(&m_socket, &QLocalSocket::connected, this, [this] {
#ifdef Q_OS_WIN
        if (!WindowsSystemService::trustedServer(m_socket.socketDescriptor())) {
#else
        uid_t uid; gid_t gid;
        if (::getpeereid(int(m_socket.socketDescriptor()), &uid, &gid) != 0 || uid != m_expectedUid) {
#endif
            m_authenticated = false; m_socket.abort();
            emit unavailable("Не подтверждена подлинность системной службы");
            return;
        }
        m_authenticated = true; m_retry.stop();
        poll();
    });
    connect(&m_socket, &QLocalSocket::readyRead, this, &NetworkClient::read);
    connect(&m_socket, &QLocalSocket::disconnected, this, [this] {
        m_authenticated = false;
        m_heartbeat = 0; m_sent.clear();
        auto replies = std::move(m_replies); m_replies.clear();
        for (auto callback : replies) if (callback) callback({}, "Потеряна связь с системной службой");
        emit unavailable("Связь со службой потеряна. Состояние защиты не подтверждено.");
        emit healthChanged(false, -1);
        m_retry.start();
    });
    connect(&m_socket, &QLocalSocket::errorOccurred, this, [this](QLocalSocket::LocalSocketError) {
        m_authenticated = false;
        emit healthChanged(false, -1);
        emit unavailable("Системная служба недоступна. Установите обновление приложения.");
        if (!m_retry.isActive()) m_retry.start();
    });
}

NetworkClient::~NetworkClient()
{
    // QLocalSocket emits disconnected while its destructor closes the socket.
    // Stop callbacks before member containers or the owning window disappear.
    m_retry.stop();
    m_poll.stop();
    m_socket.disconnect(this);
    m_socket.abort();
    m_replies.clear();
    m_sent.clear();
}

void NetworkClient::loseHealth(const QString& error)
{
    emit healthChanged(false, -1);
    emit unavailable(error);
    m_socket.abort(); // Reconnect; never replay an unconfirmed mutation.
    if (!m_retry.isActive()) m_retry.start();
}

void NetworkClient::poll()
{
    if (!available()) return;
    for (auto it = m_sent.cbegin(); it != m_sent.cend(); ++it) {
        if (m_clock.elapsed() - it.value() >= (it.key() == m_heartbeat ? 6000 : 25000)) {
            loseHealth("Служба не ответила за 6 секунд. Последнее состояние сохранено; выполняется переподключение.");
            return;
        }
    }
    if (m_heartbeat) return;
    m_heartbeat = m_nextId;
    request("status", {}, [this](const QJsonObject& state, const QString& error) {
        m_heartbeat = 0;
        if (error.isEmpty() && state.value("schema").toInt() == 1) emit statusChanged(state);
        else if (!error.isEmpty()) emit unavailable(error);
    });
}

void NetworkClient::start()
{
    if (m_socket.state() != QLocalSocket::UnconnectedState) return;
    m_socket.connectToServer(m_path);
}

bool NetworkClient::available() const
{
    return m_authenticated && m_socket.state() == QLocalSocket::ConnectedState;
}

void NetworkClient::request(const QString& method, const QJsonObject& params, Reply reply)
{
    if (!available()) {
        if (reply) reply({}, "Системная служба недоступна; сетевые настройки не изменены");
        return;
    }
    const int id = m_nextId++;
    const auto message = QJsonDocument(QJsonObject{{"id", id}, {"method", method}, {"params", params}})
        .toJson(QJsonDocument::Compact) + '\n';
    if (message.size() > 65536 || m_replies.size() > 128) {
        if (reply) reply({}, "Слишком много ожидающих команд службы");
        return;
    }
    if (reply) m_replies.insert(id, std::move(reply));
    m_sent.insert(id, m_clock.elapsed());
    m_socket.write(message);
}

void NetworkClient::read()
{
    if (!m_authenticated || m_socket.bytesAvailable() > 65536) { m_socket.abort(); return; }
    while (m_socket.canReadLine()) {
        QJsonParseError error;
        const auto document = QJsonDocument::fromJson(m_socket.readLine(65537), &error);
        if (error.error != QJsonParseError::NoError || !document.isObject()) { m_socket.abort(); return; }
        const auto message = document.object();
        if (message.contains("id")) {
            const auto id = message.value("id").toInt(-1);
            if (m_sent.contains(id)) {
                const auto latency = m_clock.elapsed() - m_sent.take(id);
                emit healthChanged(true, latency);
            }
            auto callback = m_replies.take(id);
            if (callback) callback(message.value("result").toObject(), message.value("error").toString());
        } else if (message.value("event") == "status") {
            emit statusChanged(message.value("status").toObject());
        } else {
            emit notification(message);
        }
    }
}

int queryNetworkServiceStatus(int argc, char** argv, bool requireVerified)
{
    QCoreApplication app(argc, argv);
    NetworkClient client;
    bool reported = false;
    QObject::connect(&client, &NetworkClient::statusChanged, &app, [&](const QJsonObject& state) {
        if (reported) return;
        reported = true;
        const auto bytes = QJsonDocument(state).toJson(QJsonDocument::Compact);
        std::printf("%s\n", bytes.constData());
        const auto firewall = state.value("firewall").toObject();
        const bool ready = state.value("schema").toInt() == 1;
        app.exit(ready && (requireVerified
            ? firewall.value("verified").toBool() && !firewall.value("busy").toBool()
            : state.value("capabilities").toObject().value("explicitOff").toBool()) ? 0 : 1);
    });
    QTimer::singleShot(1500, &app, [&app] { app.exit(1); });
    client.start();
    return app.exec();
}

int disableNetworkServiceProtection(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    NetworkClient client;
    bool sent = false, accepted = false;
    QObject::connect(&client, &NetworkClient::statusChanged, &app, [&](const QJsonObject& state) {
        if (!sent) {
            sent = true;
            // OFF has no dependency on the selected profile, DNS, or VPN login.
            client.request("firewall", {{"enabled", false}}, [&](const QJsonObject&, const QString& error) {
                if (!error.isEmpty()) {
                    std::fprintf(stderr, "OFF request failed: %s\n", qPrintable(error));
                    app.exit(1);
                } else accepted = true;
            });
            return;
        }
        const auto firewall = state.value("firewall").toObject();
        if (accepted && state.value("schema").toInt() == 1
            && !firewall.value("busy").toBool() && !firewall.value("requested").toBool()
            && !firewall.value("armed").toBool() && firewall.value("verified").toBool()) {
            std::printf("PASS: OpenConnect blocking is OFF. Other applications' PF rules were retained.\n");
            app.exit(0);
        }
    });
    QTimer::singleShot(30000, &app, [&app] {
        std::fprintf(stderr, "OFF was not confirmed. Use Recover Kill Switch.command for administrator recovery.\n");
        app.exit(1);
    });
    client.start();
    return app.exec();
}

int queryNetworkServiceDiagnostics(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    NetworkClient client;
    bool sent = false;
    QObject::connect(&client, &NetworkClient::statusChanged, &app, [&](const QJsonObject& state) {
        if (sent) return;
        sent = true;
        client.request("diagnostics", {}, [&, state](const QJsonObject& result, const QString& error) {
            if (!error.isEmpty()) { std::fprintf(stderr, "%s\n", qPrintable(error)); app.exit(1); return; }
            auto report = state; report.insert("diagnostics", result);
            const auto bytes = QJsonDocument(report).toJson(QJsonDocument::Indented);
            std::printf("%s", bytes.constData()); app.exit(0);
        });
    });
    QTimer::singleShot(25000, &app, [&app] { app.exit(1); });
    client.start();
    return app.exec();
}
