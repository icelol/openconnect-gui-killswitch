// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include <QJsonObject>
#include <QString>
#include <functional>
#include <QtGlobal>

namespace WindowsSystemService {
QString directory();
QString allowedUser();
bool isSystem();
bool protectDirectory(QString& error);
bool trustedFile(const QString& path);
bool trustedClient(qintptr pipe);
bool trustedServer(qintptr pipe);
int dispatch(const std::function<int()>& run);
bool stopping();
int install();
int uninstall();
int recover();
void hardenLibrarySearch();
}
