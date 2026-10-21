// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include <QJsonObject>
#include <QLocalSocket>
#include <QTimer>
#include <QHash>
#include <QElapsedTimer>
#include <functional>
int queryNetworkServiceStatus(int argc, char** argv, bool requireVerified = true);
int disableNetworkServiceProtection(int argc, char** argv);
int queryNetworkServiceDiagnostics(int argc, char** argv);

class MacNetworkClient : public QObject {
    Q_OBJECT
public:
    using Reply = std::function<void(const QJsonObject&, const QString&)>;
    explicit MacNetworkClient(QObject* parent = nullptr, QString socketPath = {}, uint expectedUid = 0);
    ~MacNetworkClient() override;
    void start();
    void request(const QString& method, const QJsonObject& params = {}, Reply reply = {});
    bool available() const;
signals:
    void statusChanged(const QJsonObject& status);
    void notification(const QJsonObject& event);
    void unavailable(const QString& error);
    void healthChanged(bool responding, qint64 latencyMs);
private:
    friend class KillSwitchUiTest;
    void read();
    void poll();
    void loseHealth(const QString& error);
    QLocalSocket m_socket;
    QTimer m_retry;
    QTimer m_poll;
    QElapsedTimer m_clock;
    QString m_path;
    uint m_expectedUid;
    bool m_authenticated = false;
    int m_nextId = 1;
    QHash<int, Reply> m_replies;
    QHash<int, qint64> m_sent;
    int m_heartbeat = 0;
};
