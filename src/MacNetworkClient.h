// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include <QJsonObject>
#include <QLocalSocket>
#include <QTimer>
#include <QHash>
#include <functional>
int queryNetworkServiceStatus(int argc, char** argv);

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
private:
    void read();
    QLocalSocket m_socket;
    QTimer m_retry;
    QString m_path;
    uint m_expectedUid;
    bool m_authenticated = false;
    int m_nextId = 1;
    QHash<int, Reply> m_replies;
};
