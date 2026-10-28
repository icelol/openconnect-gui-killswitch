// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include <QJsonObject>
#include <QString>
#include <QtGlobal>
#include <functional>

namespace WindowsSystemService {
QString directory();
QString allowedUser();
bool isSystem();
bool protectDirectory(QString& error);
bool protectFile(const QString& path, QString& error);
bool prepareEnvironment(QString& error);
bool trustedFile(const QString& path);
bool trustedClient(qintptr pipe);
bool trustedServer(qintptr pipe);
int dispatch(const std::function<int()>& run);
bool stopping();
int install();
int stop();
int checkInterfaceClosed();
int uninstall();
int recover();
void hardenLibrarySearch();
}
