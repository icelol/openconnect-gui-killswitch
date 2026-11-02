// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include <QByteArray>
#include <QStringList>
namespace WindowsDnsBootstrap {
QStringList systemServers();
QStringList lookup(const QString& host, const QStringList& servers, QString& error);
// Internal transport seam for local fixtures. The service always uses lookup(),
// with DNS port 53 and a fixed 2500 ms total budget; these are not IPC options.
QStringList lookupWithDeadline(const QString& host, const QStringList& servers, QString& error, quint16 port, int timeoutMs);
QStringList response(const QByteArray& wire, quint16 id, const QString& host, quint16 type, bool& truncated);
}
