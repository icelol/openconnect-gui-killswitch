// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include <QByteArray>
#include <QStringList>
namespace WindowsDnsBootstrap {
QStringList systemServers();
QStringList lookup(const QString& host, const QStringList& servers, QString& error);
QStringList response(const QByteArray& wire, quint16 id, const QString& host, quint16 type, bool& truncated);
}
