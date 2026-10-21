/*
 * Copyright (C) 2014 Red Hat
 * Copyright (C) 2016 by Lubomír Carik <Lubomir.Carik@gmail.com>
 *
 * This file is part of openconnect-gui.
 *
 * openconnect-gui is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "common.h"
#include "config.h"
#include "dialog/MyInputDialog.h"
#include "dialog/mainwindow.h"
#include "openconnect-gui.h"

#include "FileLogger.h"
#include "logger.h"
#include "MacBootGuard.h"
#include "NetworkService.h"
#include "NetworkClient.h"
#ifdef Q_OS_WIN
#include "WindowsSystemService.h"
#endif

extern "C" {
#include <gnutls/pkcs11.h>
}

#include <QApplication>
#if !defined(_WIN32) && !defined(PROJ_GNUTLS_DEBUG)
#include <QMessageBox>
#endif
#include <QCommandLineParser>
#include <OcSettings.h>
#include <QtSingleApplication>

#ifdef __MACH__
#include <Security/Security.h>
#include <mach-o/dyld.h>
#endif

#include <csignal>
#include <cstdio>

static void log_callback(int level, const char* str)
{
    Logger::instance().addMessage(QString(str).trimmed(),
        Logger::MessageType::DEBUG,
        Logger::ComponentType::GNUTLS);
}


int pin_callback(void* userdata, int attempt, const char* token_url,
    const char* token_label, unsigned flags, char* pin,
    size_t pin_max)
{
    QString type = QObject::tr("user");
    if (flags & GNUTLS_PIN_SO) {
        type = QObject::tr("security officer");
    }

    QString outtext = QObject::tr("Please enter the %1 PIN for %2.").arg(type).arg(token_label);
    if (flags & GNUTLS_PKCS11_PIN_FINAL_TRY) {
        outtext += QObject::tr(" This is the FINAL try!");
    }
    if (flags & GNUTLS_PKCS11_PIN_COUNT_LOW) {
        outtext += QObject::tr(" Only few tries before token lock!");
    }

    MainWindow* w = (MainWindow*)userdata;
    MyInputDialog dialog(w, QLatin1String(token_url), outtext, QLineEdit::Password);
    dialog.show();

    QString text;
    bool ok = dialog.result(text);
    if (ok == false) {
        return -1;
    }

    snprintf(pin, pin_max, "%s", text.toUtf8().data());
    return 0;
}

int main(int argc, char* argv[])
{
#ifdef Q_OS_WIN
    WindowsSystemService::hardenLibrarySearch();
    for (int i = 1; i < argc; ++i) {
        const auto command = QString::fromLocal8Bit(argv[i]);
        if (command == "--install-service" || command == "--uninstall-service" || command == "--recover-killswitch") {
            QCoreApplication app(argc, argv);
            return command == "--install-service" ? WindowsSystemService::install()
                : command == "--uninstall-service" ? WindowsSystemService::uninstall() : WindowsSystemService::recover();
        }
    }
#endif
    // Headless launchd mode must not initialize AppKit, user settings, or the
    // single-instance GUI. Its only persistent data are public gateway IPs.
    for (int i = 1; i < argc; ++i) {
        const auto arg = QString::fromLocal8Bit(argv[i]);
        if (arg == "--service-status") return queryNetworkServiceStatus(argc, argv);
        if (arg == "--service-diagnostics") return queryNetworkServiceDiagnostics(argc, argv);
        if (arg == "--service-ready") return queryNetworkServiceStatus(argc, argv, false);
        if (arg == "--service-disable") return disableNetworkServiceProtection(argc, argv);
        if (arg == "--network-service") return runNetworkService(argc, argv);
#ifndef Q_OS_WIN
        if (arg == "--boot-guard" || arg == "--prepare-boot" || arg == "--check-boot"
            || arg == "--check-tun" || arg == "--verify-guard" || arg == "--check-storage" || arg == "--check-pf-abi"
            || arg == "--migrate-preferences")
            return runBootProtection(argc, argv);
#endif
    }
#ifdef Q_OS_MACOS
    if (::geteuid() == 0) {
        std::fprintf(stderr, "Run the GUI as the desktop user. The network service owns root operations.\n");
        return 1;
    }
#endif
    bool haveTray = false;
    bool preview = false;
    for (int i = 1; i < argc; ++i)
        preview |= QString::fromLocal8Bit(argv[i]) == "--preview";

    qputenv("LOG2FILE", "1");

    qRegisterMetaType<Logger::Message>();

    QCoreApplication::setApplicationName(APP_NAME);
    QCoreApplication::setApplicationVersion(PROJECT_VERSION);
    QCoreApplication::setOrganizationName(PRODUCT_NAME_COMPANY);
    QCoreApplication::setOrganizationDomain(PRODUCT_NAME_COMPANY_DOMAIN);

    QtSingleApplication app(argc, argv);
    app.setProperty("previewMode", preview);
    if (app.isRunning() && !preview) {
#ifdef Q_OS_MACOS
        app.sendMessage("Wake up!");
        return 0;
#else
        OcSettings settings;
        if (settings.value("Settings/singleInstanceMode", true).toBool()) {
            app.sendMessage("Wake up!");
            return 0;
        }
#endif
    }
    app.setApplicationDisplayName(APP_NAME);
    app.setQuitOnLastWindowClosed(false);

    if (QSystemTrayIcon::isSystemTrayAvailable()) {
        haveTray=true;
    }

    std::unique_ptr<FileLogger> fileLog;
    if (!preview) fileLog = std::make_unique<FileLogger>();
    Logger::instance().addMessage(QString("%1 (%2) logging started...").arg(app.applicationDisplayName()).arg(app.applicationVersion()));

    gnutls_global_init();
#ifndef _WIN32
    signal(SIGPIPE, SIG_IGN);
#endif
    openconnect_init_ssl();

    QCommandLineParser parser;
    parser.setApplicationDescription(
        QObject::tr("OpenConnect is a VPN client, that utilizes TLS and DTLS "
                    "for secure session establishment, and is compatible "
                    "with many VPN protocols."));
    parser.addHelpOption();
    parser.addVersionOption();
    parser.addOption({"preview", QObject::tr("Preview the interface without administrator access or network changes")});
    parser.addOption({"preview-screenshot", QObject::tr("Save a UI rendering in preview mode and exit"), "path"});
    parser.addOption({ { "s", "server" },
        QObject::tr("auto-connect to existing profile <name>"),
        QObject::tr("name")

    });

    parser.process(app);
    const auto screenshotPath = parser.value("preview-screenshot");
    if (!screenshotPath.isEmpty() && !preview)
        parser.showHelp(1);

    const QString profileName{ parser.value(QLatin1String("server")) };
    MainWindow mainWindow(nullptr, haveTray, profileName);
    app.setActivationWindow(&mainWindow);
#ifdef PROJ_PKCS11
    gnutls_pkcs11_set_pin_function(pin_callback, &mainWindow);
#endif
    gnutls_global_set_log_function(log_callback);
#ifdef PROJ_GNUTLS_DEBUG
    gnutls_global_set_log_level(3);
#endif

    mainWindow.show();
    mainWindow.setWindowTitle(APP_NAME);
    if (preview)
        mainWindow.setWindowTitle(QStringLiteral(APP_NAME) + " (preview)");
    if (!screenshotPath.isEmpty()) {
        QTimer::singleShot(200, &mainWindow, [&mainWindow, &app, screenshotPath] {
            app.exit(mainWindow.grab().save(screenshotPath) ? 0 : 1);
        });
    }

    QObject::connect(&app, &QtSingleApplication::messageReceived,
        [](const QString& message) {
            Logger::instance().addMessage(message);
        });
    return app.exec();
}
