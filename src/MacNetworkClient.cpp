// SPDX-License-Identifier: GPL-2.0-or-later
#include "MacNetworkClient.h"
#include "MacNetworkService.h"
#include <QJsonDocument>
#include <QCoreApplication>
#include <cstdio>
#include <sys/socket.h>
#include <unistd.h>

MacNetworkClient::MacNetworkClient(QObject* parent, QString socketPath, uint expectedUid)
    : QObject(parent), m_path(socketPath.isEmpty() ? networkServiceSocket() : socketPath),
      m_expectedUid(expectedUid)
{
    m_socket.setReadBufferSize(65537);
    m_retry.setInterval(1000);
    connect(&m_retry, &QTimer::timeout, this, &MacNetworkClient::start);
    connect(&m_socket, &QLocalSocket::connected, this, [this] {
        uid_t uid; gid_t gid;
        if (::getpeereid(int(m_socket.socketDescriptor()), &uid, &gid) != 0 || uid != m_expectedUid) {
            m_authenticated = false; m_socket.abort();
            emit unavailable("Не подтверждена подлинность системной службы");
            return;
        }
        m_authenticated = true; m_retry.stop();
        request("status", {}, [this](const QJsonObject& state, const QString& error) {
            if (error.isEmpty()) emit statusChanged(state); else emit unavailable(error);
        });
    });
    connect(&m_socket, &QLocalSocket::readyRead, this, &MacNetworkClient::read);
    connect(&m_socket, &QLocalSocket::disconnected, this, [this] {
        m_authenticated = false;
        auto replies = std::move(m_replies); m_replies.clear();
        for (auto callback : replies) if (callback) callback({}, "Потеряна связь с системной службой");
        emit unavailable("Связь со службой потеряна. Состояние защиты не подтверждено.");
        m_retry.start();
    });
    connect(&m_socket, &QLocalSocket::errorOccurred, this, [this](QLocalSocket::LocalSocketError) {
        m_authenticated = false;
        emit unavailable("Системная служба недоступна. Установите обновление приложения.");
        if (!m_retry.isActive()) m_retry.start();
    });
}

MacNetworkClient::~MacNetworkClient()
{
    // QLocalSocket emits disconnected while its destructor closes the socket.
    // Stop callbacks before member containers or the owning window disappear.
    m_retry.stop();
    m_socket.disconnect(this);
    m_socket.abort();
    m_replies.clear();
}

void MacNetworkClient::start()
{
    if (m_socket.state() != QLocalSocket::UnconnectedState) return;
    m_socket.connectToServer(m_path);
}

bool MacNetworkClient::available() const
{
    return m_authenticated && m_socket.state() == QLocalSocket::ConnectedState;
}

void MacNetworkClient::request(const QString& method, const QJsonObject& params, Reply reply)
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
    m_socket.write(message);
}

void MacNetworkClient::read()
{
    if (!m_authenticated || m_socket.bytesAvailable() > 65536) { m_socket.abort(); return; }
    while (m_socket.canReadLine()) {
        QJsonParseError error;
        const auto document = QJsonDocument::fromJson(m_socket.readLine(65537), &error);
        if (error.error != QJsonParseError::NoError || !document.isObject()) { m_socket.abort(); return; }
        const auto message = document.object();
        if (message.contains("id")) {
            auto callback = m_replies.take(message.value("id").toInt(-1));
            if (callback) callback(message.value("result").toObject(), message.value("error").toString());
        } else if (message.value("event") == "status") {
            emit statusChanged(message.value("status").toObject());
        } else {
            emit notification(message);
        }
    }
}

int queryNetworkServiceStatus(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    MacNetworkClient client;
    QObject::connect(&client, &MacNetworkClient::statusChanged, &app, [&app](const QJsonObject& state) {
        const auto bytes = QJsonDocument(state).toJson(QJsonDocument::Compact);
        std::printf("%s\n", bytes.constData());
        const auto firewall = state.value("firewall").toObject();
        app.exit(state.value("schema").toInt() == 1 && firewall.value("verified").toBool()
            && !firewall.value("busy").toBool() ? 0 : 1);
    });
    QTimer::singleShot(1500, &app, [&app] { app.exit(1); });
    client.start();
    return app.exec();
}
