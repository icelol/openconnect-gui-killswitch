// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include <QStringList>

namespace MacDnsBootstrap {
QStringList systemServers();
QStringList lookup(const QString& host, const QStringList& servers, QString& error);
}
