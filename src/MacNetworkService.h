// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include "MacKillSwitch.h"
#include "VpnCallbacks.h"
#include <QFuture>
#include <QJsonObject>
#include <QLocalServer>
#include <QLocalSocket>
#include <QPointer>
#include <QThread>
#include <QTimer>
#include <QWaitCondition>
#include <atomic>
#include <memory>
class QLockFile;
class VpnInfo;

QString networkServiceSocket();
int runNetworkService(int argc, char** argv);

class ServiceVpnSession : public QThread, public VpnCallbacks {
    Q_OBJECT
public:
    ServiceVpnSession(MacKillSwitch* guard, const QJsonObject& profile, QObject* parent = nullptr);
    ~ServiceVpnSession() override;
    void cancel();
    void requestStats();
    bool answer(const QString& challenge, bool accepted, const QString& answer);
    bool awaitingInput() const;
    bool input(const QString&, const QString&, const QStringList&, bool,
        const QString&, const QString&, QString&) override;
    void connected(const QString&, const QString&, const QString&, const QString&, const QString&) override;
    void stats(const oc_stats*, const QString&) override;
    void error(const QString&) override;
    void firewallError(const QString&) override;
signals:
    void notification(const QJsonObject& event);
protected:
    void run() override;
private:
    MacKillSwitch* m_guard;
    QJsonObject m_profile;
    mutable QMutex m_lock;
    QWaitCondition m_answerReady;
    QString m_challenge, m_answer;
    bool m_answered = false, m_accepted = false;
    bool m_reportedError = false;
    int m_fd = -1;
    std::atomic<bool> m_cancelled{false};
};

class MacNetworkService : public QObject {
    Q_OBJECT
public:
    MacNetworkService(MacKillSwitch* guard, uint allowedUid, const QString& socket,
        const QString& initialGateway = {}, QObject* parent = nullptr);
    ~MacNetworkService() override;
    bool start(QString& error);
    QJsonObject status() const;
    static bool validGateway(const QString& candidate, QString& error);
    static bool supportedProtocol(const QString& protocol);
signals:
    void changed();
private:
    friend class KillSwitchUiTest;
    void accept();
    void dispatch(QLocalSocket*, const QJsonObject&);
    void reply(QLocalSocket*, const QJsonValue& id, const QJsonObject& result, const QString& error = {});
    void broadcast();
    void changeFirewall();
    void startVpn();
    void sessionEvent(const QJsonObject&);
    MacKillSwitch* m_guard;
    uint m_allowedUid;
    QString m_socketPath;
    QLocalServer m_server;
    std::unique_ptr<QLockFile> m_instance;
    QList<QLocalSocket*> m_clients;
    QPointer<QLocalSocket> m_owner;
    QJsonObject m_pendingProfile, m_vpnDetails;
    ServiceVpnSession* m_session = nullptr;
    QString m_vpnState = "disconnected", m_error, m_gateway;
    bool m_desired = false, m_busy = false, m_verified = false;
    quint64 m_generation = 0, m_revision = 0;
    QFuture<QString> m_firewallTask, m_verification;
    QTimer m_monitor;
};
