// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include <QStringList>
struct oc_stats;

// Implemented by the headless system service. No QWidget or GUI privileges.
class VpnCallbacks {
public:
    virtual ~VpnCallbacks() = default;
    virtual bool input(const QString& title, const QString& label, const QStringList& choices,
        bool secret, const QString& banner, const QString& message, QString& answer) = 0;
    virtual void connected(const QString& dns, const QString& ip, const QString& ip6,
        const QString& cstp, const QString& dtls) = 0;
    virtual void stats(const oc_stats* statistics, const QString& dtls) = 0;
    virtual void error(const QString& message) = 0;
    virtual void firewallError(const QString& message) = 0;
    virtual void progress(int, const QString&) { }
};
