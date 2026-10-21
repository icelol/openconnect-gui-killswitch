// SPDX-License-Identifier: GPL-2.0-or-later
#include "MacKillSwitch.h"
#include "MacNetworkService.h"
#include "MacNetworkClient.h"
#include "dialog/mainwindow.h"
#include "dialog/MyInputDialog.h"
#include "FileLogger.h"
#include <QCheckBox>
#include <QComboBox>
#include <QLabel>
#include <QPromise>
#include <QPushButton>
#include <QSettings>
#include <QTemporaryDir>
#include <QProcess>
#include <QtConcurrent/QtConcurrentRun>
#include <QtTest>
#include <unistd.h>

namespace {
struct Firewall {
    QString installed;
    QString root = "anchor \"com.apple/*\" all";
    bool enabled = false;
    MacKillSwitch::Result operator()(const QStringList& args, const QByteArray& data)
    {
        if (args.contains("-n")) {
            QProcess p;
            p.start("/sbin/pfctl", args);
            if (!p.waitForStarted()) return {1, {}, p.errorString()};
            p.write(data);
            p.closeWriteChannel();
            p.waitForFinished();
            return {p.exitCode(), QString::fromUtf8(p.readAllStandardOutput()), QString::fromUtf8(p.readAllStandardError())};
        }
        if (args == QStringList{"-sr"}) return {0, root, {}};
        if (args == QStringList{"-a", "com.apple", "-s", "Anchors"}) return {0, {}, {}};
        if (args == QStringList{"-v", "-s", "Interfaces"}) return {0, "lo0 (skip)\nen0", {}};
        if (args == QStringList{"-s", "info"}) return {0, enabled ? "Status: Enabled" : "Status: Disabled", {}};
        if (args == QStringList{"-a", MacKillSwitch::anchor(), "-sr"}) return {0, installed, {}};
        if (args == QStringList{"-a", MacKillSwitch::anchor(), "-f", "-"}) {
            // PF parser's canonical form was passed through -n immediately
            // before loading. For these tests the textual parser output is
            // needed by verify(), so canonicalize without mutating live PF.
            const auto parsed = (*this)({"-n", "-v", "-a", MacKillSwitch::anchor(), "-f", "-"}, data);
            installed = parsed.output.trimmed();
            return {parsed.exitCode, {}, parsed.error};
        }
        if (args == QStringList{"-E"}) { enabled = true; return {0, {}, "Token : 123456"}; }
        if (args == QStringList{"-X", "123456"}) { enabled = false; return {0, {}, {}}; }
        if (args == QStringList{":prune-states"}) return {0, {}, {}};
        return {1, {}, "unexpected invocation"};
    }
};
}

class KillSwitchUiTest : public QObject {
    Q_OBJECT
    QTemporaryDir settingsDirectory;
private slots:
    void initTestCase()
    {
        QCoreApplication::setApplicationName("OpenConnect UI test");
        QSettings::setDefaultFormat(QSettings::IniFormat);
        QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, settingsDirectory.path());
        OcSettings settings;
        settings.setValue("server:Example VPN/server", "https://vpn.example.test");
        settings.setValue("server:Example VPN/protocol-name", "anyconnect");
    }

    void switchCanTurnOffWhileVpnWorkerIsRunning()
    {
        QTemporaryDir directory;
        Firewall pf;
        auto guard = new MacKillSwitch(std::ref(pf), directory.filePath("state.json"));
        MainWindow window(nullptr, false, {}, guard);
        window.show();
        auto checkbox = window.findChild<QCheckBox*>("killSwitchCheckBox");
        auto connectButton = window.findChild<QPushButton*>("connectionButton");
        QTRY_VERIFY(connectButton->isEnabled());
        // Mimic a VPN worker that remains active during authentication/session.
        QPromise<void> worker;
        worker.start();
        window.futureWatcher.setFuture(worker.future());
        window.changeStatus(STATUS_CONNECTING);
        window.refreshKillSwitch();
        QVERIFY(window.futureWatcher.isRunning());
        QVERIFY(checkbox->isEnabled());
        QSignalBlocker blocked(checkbox);
        checkbox->setChecked(true);
        blocked.unblock();
        guard->requestEnabled(true);
        QString error;
        QVERIFY(guard->arm(QUrl("https://203.0.113.10"), error));
        window.refreshKillSwitch();
        QVERIFY(connectButton->isEnabled());
        checkbox->click();
        QTRY_VERIFY(!window.m_killSwitchBusy);
        QVERIFY(!guard->isArmed());
        QVERIFY(pf.installed.isEmpty());
        QVERIFY(!checkbox->isChecked());
        QVERIFY(window.futureWatcher.isRunning());
        QVERIFY(connectButton->isEnabled());
        worker.finish();
        window.futureWatcher.waitForFinished();
    }

    void logFailureDoesNotPreventGuiStartupAndWritableLoggingWorks()
    {
        FileLogger unavailable(nullptr, "/dev/null/not-a-directory");
        QVERIFY(!unavailable.available());
        QTemporaryDir directory;
        const auto filename = QCoreApplication::applicationName() + ".log";
        QVERIFY(QDir(directory.path()).mkdir(filename));
        FileLogger cannotOpenFile(nullptr, directory.path());
        QVERIFY(!cannotOpenFile.available());
        QVERIFY(QDir(directory.filePath(filename)).removeRecursively());
        FileLogger available(nullptr, directory.path());
        QVERIFY(available.available());
        Logger::instance().addMessage("non-sensitive diagnostic test line");
        QFile file(directory.filePath(QCoreApplication::applicationName() + ".log"));
        QVERIFY(file.open(QIODevice::ReadOnly));
        QVERIFY(file.readAll().contains("non-sensitive diagnostic test line"));
    }

    void changingMindDuringEnableFinishesOff()
    {
        QTemporaryDir directory;
        Firewall pf;
        MainWindow window(nullptr, false, {}, new MacKillSwitch(std::ref(pf), directory.filePath("state.json")));
        window.show();
        auto checkbox = window.findChild<QCheckBox*>("killSwitchCheckBox");
        QTRY_VERIFY(window.findChild<QPushButton*>("connectionButton")->isEnabled());
        checkbox->click();
        QVERIFY(window.m_killSwitchBusy);
        QVERIFY(checkbox->isEnabled());
        checkbox->click();
        QTRY_VERIFY(!window.m_killSwitchBusy);
        QVERIFY(!window.m_killSwitch->isArmed());
        QVERIFY(!checkbox->isChecked());
        QVERIFY(pf.installed.isEmpty());
    }

    void authenticationDialogLeavesSystemSwitchAccessible()
    {
        QTemporaryDir directory;
        Firewall pf;
        MainWindow window(nullptr, false, {}, new MacKillSwitch(std::ref(pf), directory.filePath("state.json")));
        window.show();
        auto input = QtConcurrent::run([&] {
            MyInputDialog dialog(&window, "Test authentication", "Password", QLineEdit::Password);
            dialog.show();
            QString unused;
            return dialog.result(unused);
        });
        QTimer::singleShot(100, &window, [&] {
            auto prompt = window.findChild<QInputDialog*>();
            QVERIFY(prompt);
            QCOMPARE(prompt->windowModality(), Qt::NonModal);
            QVERIFY(window.findChild<QCheckBox*>("killSwitchCheckBox")->isEnabled());
            emit window.cancelAuthDialogs();
        });
        QTRY_VERIFY(input.isFinished());
        QVERIFY(!input.result());
    }

    void firstConnectAndRetrySendOneCommandWithoutDuplicateSessionError()
    {
        QTemporaryDir directory;
        Firewall pf;
        MacKillSwitch guard(std::ref(pf), directory.filePath("state.json"));
        guard.requestEnabled(false);
        const auto socket = directory.filePath("control.sock");
        MacNetworkService service(&guard, getuid(), socket, "https://203.0.113.10");
        QString error;
        QVERIFY(service.start(error));
        service.m_monitor.stop();
        service.m_busy = true; // Hold the request before any real VPN worker starts.
        OcSettings settings;
        const auto profile = QString("First connection regression");
        settings.setValue("server:" + profile + "/server", "https://203.0.113.10");
        settings.setValue("server:" + profile + "/protocol-name", "anyconnect");
        settings.sync();
        auto client = new MacNetworkClient(nullptr, socket, getuid());
        MainWindow window(nullptr, false, {}, nullptr, client);
        window.show();
        auto button = window.findChild<QPushButton*>("connectionButton");
        auto profiles = window.findChild<QComboBox*>("serverList");
        QTRY_VERIFY(client->available());
        QTRY_COMPARE(window.m_remoteVpnState, int(STATUS_DISCONNECTED));
        QTRY_VERIFY(profiles->findText(profile) >= 0);
        profiles->setCurrentText(profile);
        QObject::disconnect(&window, &MainWindow::connectionErrorChanged, &window, nullptr);
        QSignalSpy failures(&window, &MainWindow::connectionErrorChanged);
        auto fence = [&] {
            // Drain queued button handlers, then request a reply on the same
            // socket so all preceding connect/cancel responses are consumed.
            QCoreApplication::sendPostedEvents(nullptr, QEvent::MetaCall);
            bool received = false;
            client->request("status", {}, [&](const QJsonObject&, const QString&) { received = true; });
            QTRY_VERIFY(received);
        };
        for (int attempt = 0; attempt < 3; ++attempt) {
            QTRY_COMPARE(button->text(), QString("Connect"));
            button->click();
            fence();
            QCOMPARE(failures.count(), 0);
            QCOMPARE(service.status().value("vpn").toObject().value("state").toString(), QString("connecting"));
            QCOMPARE(button->text(), QString("Cancel"));
            // Enter, a tray action or an already queued second click must not
            // start another session while the first is being authenticated.
            window.on_connectClicked();
            window.on_connectClicked();
            fence();
            QCOMPARE(failures.count(), 0);
            button->click();
            fence();
            QCOMPARE(failures.count(), 0);
            QTRY_COMPARE(service.status().value("vpn").toObject().value("state").toString(), QString("disconnected"));
        }
        settings.remove("server:" + profile);
    }

    void remoteSwitchAndDisconnectAreIndependentAndGuiCanReconnect()
    {
        QTemporaryDir directory;
        Firewall pf;
        MacKillSwitch guard(std::ref(pf), directory.filePath("state.json"));
        guard.requestEnabled(false);
        const auto socket = directory.filePath("control.sock");
        MacNetworkService service(&guard, getuid(), socket, "https://203.0.113.10");
        QString error;
        QVERIFY2(service.start(error), qPrintable(error));
        {
            auto client = new MacNetworkClient(nullptr, socket, getuid());
            MainWindow window(nullptr, false, {}, nullptr, client);
            window.show();
            window.findChild<QComboBox*>("serverList")->setCurrentText("https://203.0.113.10");
            QTRY_VERIFY(client->available());
            auto toggle = window.findChild<QCheckBox*>("killSwitchCheckBox");
            QTRY_VERIFY(window.findChild<QLabel*>("killSwitchStatusLabel")->text().startsWith("Выключено"));
            // Reloading profiles on startup may have replaced the editable text.
            window.findChild<QComboBox*>("serverList")->setCurrentText("https://203.0.113.10");
            toggle->click();
            QTRY_VERIFY(guard.isArmed());
            QTRY_VERIFY(service.status().value("firewall").toObject().value("verified").toBool());
            QVERIFY(window.findChild<QPushButton*>("connectionButton")->isEnabled());
            // The engine event is injected; no real VPN or credentials are used.
            service.sessionEvent({{"event", "connected"}, {"ip", "10.23.0.2"}});
            QTRY_COMPARE(window.findChild<QPushButton*>("connectionButton")->text(), QString("Disconnect"));
            window.findChild<QPushButton*>("connectionButton")->click();
            QTRY_COMPARE(service.status().value("vpn").toObject().value("state").toString(), QString("disconnected"));
            QVERIFY(guard.isArmed());
        }
        QVERIFY(guard.isArmed()); // Closing the GUI did not release the firewall.
        MacNetworkClient replacement(nullptr, socket, getuid());
        QSignalSpy snapshots(&replacement, &MacNetworkClient::statusChanged);
        replacement.start(); QTRY_VERIFY(!snapshots.isEmpty());
        QVERIFY(snapshots.last().at(0).toJsonObject().value("firewall").toObject().value("armed").toBool());
        replacement.request("firewall", {{"enabled", false}, {"gateway", "https://203.0.113.10"}});
        QTRY_VERIFY(!guard.isArmed());
        QVERIFY(pf.installed.isEmpty());
    }

    void ipcRejectsUnsafeParametersAndFakeServerIdentity()
    {
        QTemporaryDir directory;
        Firewall pf;
        MacKillSwitch guard(std::ref(pf), directory.filePath("state.json"));
        guard.requestEnabled(false);
        const auto socket = directory.filePath("control.sock");
        MacNetworkService service(&guard, getuid(), socket, "https://203.0.113.10");
        QString error;
        QVERIFY(service.start(error));
        MacNetworkClient client(nullptr, socket, getuid());
        client.start(); QTRY_VERIFY(client.available());
        QString rejected;
        client.request("exec", {{"command", "must-never-run"}}, [&](const QJsonObject&, const QString& e) { rejected = e; });
        QTRY_VERIFY(!rejected.isEmpty());
        rejected.clear();
        client.request("firewall", {{"enabled", true}, {"gateway", "http://unsafe.invalid"}},
            [&](const QJsonObject&, const QString& e) { rejected = e; });
        QTRY_VERIFY(!rejected.isEmpty());
        QVERIFY(!guard.isArmed()); QVERIFY(pf.installed.isEmpty());
        for (const auto& params : {QJsonObject{{"gateway", "https://user:password@203.0.113.10"}},
                QJsonObject{{"gateway", "https://203.0.113.10"}, {"vpncScript", "/tmp/do-not-execute"}},
                QJsonObject{{"gateway", "https://203.0.113.10"}, {"protocol", "unknown-protocol"}},
                QJsonObject{{"gateway", "https://203.0.113.10"}, {"proxy", true}}}) {
            rejected.clear();
            client.request("connect", params, [&](const QJsonObject&, const QString& e) { rejected = e; });
            QTRY_VERIFY(!rejected.isEmpty());
            QCOMPARE(service.status().value("vpn").toObject().value("state").toString(), QString("disconnected"));
        }
        MacNetworkClient untrusted(nullptr, socket, getuid() + 1);
        QSignalSpy failure(&untrusted, &MacNetworkClient::unavailable);
        untrusted.start(); QTRY_VERIFY(!failure.isEmpty()); QVERIFY(!untrusted.available());
    }

    void enabledKillSwitchAcceptsDifferentGatewaysAndAllCompiledProtocols()
    {
        QTemporaryDir directory; Firewall pf; QString error;
        MacKillSwitch guard(std::ref(pf), directory.filePath("state.json"));
        QVERIFY(guard.arm(QUrl(), error));
        const auto socket = directory.filePath("control.sock");
        MacNetworkService service(&guard, getuid(), socket);
        QVERIFY(service.start(error)); service.m_monitor.stop();
        service.m_busy = true; // No live worker, credentials or network used.
        MacNetworkClient client(nullptr, socket, getuid());
        client.start(); QTRY_VERIFY(client.available());
        struct oc_vpn_proto* protocols = nullptr;
        QVERIFY(openconnect_get_supported_protocols(&protocols) > 0);
        QStringList supported;
        for (auto p = protocols; p->name; ++p) supported << QString::fromUtf8(p->name);
        openconnect_free_supported_protocols(protocols);
        for (const auto& protocol : supported) {
            bool replied = false; QString failure;
            client.request("connect", {{"gateway", "https://another.example.test:8443/group"}, {"protocol", protocol}},
                [&](const QJsonObject&, const QString& e) { failure = e; replied = true; });
            QTRY_VERIFY(replied); QVERIFY2(failure.isEmpty(), qPrintable(failure));
            QCOMPARE(service.m_pendingProfile.value("protocol").toString(), protocol);
            QVERIFY(guard.isArmed());
            replied = false;
            client.request("disconnect", {}, [&](const QJsonObject&, const QString&) { replied = true; });
            QTRY_VERIFY(replied);
            QVERIFY(guard.isArmed());
        }
    }

    void recoveryFailureKeepsOffControlAvailableAndIgnoresInvalidProfile()
    {
        QTemporaryDir directory; Firewall pf; QString error;
        const auto state = directory.filePath("state.json"), boot = directory.filePath("boot.json");
        {
            MacKillSwitch previous(std::ref(pf), state, boot);
            QVERIFY(previous.arm(QUrl("https://203.0.113.10"), error));
        }
        // Another app changes PF while this client's protection was persisted ON.
        pf.root += "\npass quick all";
        MacKillSwitch guard(std::ref(pf), state, boot);
        QVERIFY(!guard.restoreBootProtection(error));
        QVERIFY(!error.isEmpty());
        const auto recoveryError = error;
        MacNetworkService service(&guard, getuid(), directory.filePath("control.sock"));
        QVERIFY2(service.start(error, recoveryError), qPrintable(error));
        service.m_monitor.stop();
        auto client = new MacNetworkClient(nullptr, directory.filePath("control.sock"), getuid());
        MainWindow window(nullptr, false, {}, nullptr, client);
        window.show();
        QTRY_VERIFY(client->available());
        QTRY_VERIFY(!service.status().value("firewall").toObject().value("verified").toBool());
        window.findChild<QComboBox*>("serverList")->setCurrentText("http://invalid-for-connect");
        auto off = window.findChild<QPushButton*>("killSwitchOffButton");
        QVERIFY(off && off->isEnabled());
        off->click();
        QTRY_VERIFY(!guard.isArmed());
        QTRY_VERIFY(service.status().value("firewall").toObject().value("verified").toBool());
        QVERIFY(pf.installed.isEmpty());
        QVERIFY(service.status().value("firewall").toObject().value("error").toString().isEmpty());
        bool enabled = true; MacKillSwitch::Policy policy;
        QVERIFY(MacKillSwitch::readBootPolicy(boot, policy, enabled, error));
        QVERIFY(!enabled);
        // Recovery did not replace the other application's root policy.
        QVERIFY(pf.root.endsWith("pass quick all"));
    }

    void explicitOffWorksWithUncheckedToggleAfterFailedRecovery()
    {
        QTemporaryDir directory; Firewall pf; QString error;
        MacKillSwitch guard(std::ref(pf), directory.filePath("state.json"));
        MacNetworkService service(&guard, getuid(), directory.filePath("control.sock"));
        QVERIFY(service.start(error, "Injected recovery failure"));
        auto client = new MacNetworkClient(nullptr, directory.filePath("control.sock"), getuid());
        MainWindow window(nullptr, false, {}, nullptr, client);
        window.show(); QTRY_VERIFY(client->available());
        QTRY_VERIFY(!window.findChild<QCheckBox*>("killSwitchCheckBox")->isChecked());
        window.findChild<QPushButton*>("killSwitchOffButton")->click();
        QTRY_VERIFY(service.status().value("firewall").toObject().value("verified").toBool());
        QVERIFY(!guard.isArmed());
        QVERIFY(service.status().value("firewall").toObject().value("error").toString().isEmpty());
    }

    void monitorDoesNotHideAStartupRecoveryFailure()
    {
        QTemporaryDir directory; Firewall pf; QString error;
        MacKillSwitch guard(std::ref(pf), directory.filePath("state.json"));
        QVERIFY(guard.arm(QUrl("https://203.0.113.10"), error));
        MacNetworkService service(&guard, getuid(), directory.filePath("control.sock"));
        QVERIFY(service.start(error, "Injected startup recovery failure"));
        QVERIFY(service.m_recoveryRequired);
        QVERIFY(QMetaObject::invokeMethod(&service.m_monitor, "timeout", Qt::DirectConnection));
        QVERIFY(!service.m_verification.isRunning());
        const auto state = service.status().value("firewall").toObject();
        QVERIFY(!state.value("verified").toBool());
        QVERIFY(!state.value("error").toString().isEmpty());
    }

    void malformedOrOversizedIpcMessagesCannotChangeFirewall()
    {
        QTemporaryDir directory;
        Firewall pf;
        MacKillSwitch guard(std::ref(pf), directory.filePath("state.json"));
        guard.requestEnabled(false);
        const auto socket = directory.filePath("control.sock");
        MacNetworkService service(&guard, getuid(), socket, "https://203.0.113.10");
        QString error;
        QVERIFY(service.start(error));
        for (const auto& data : {QByteArray("{broken-json}\n"), QByteArray(65537, 'x')}) {
            QLocalSocket client;
            client.connectToServer(socket);
            QTRY_COMPARE(client.state(), QLocalSocket::ConnectedState);
            client.write(data); client.flush();
            QTRY_COMPARE(client.state(), QLocalSocket::UnconnectedState);
            QVERIFY(pf.installed.isEmpty()); QVERIFY(!guard.isArmed());
        }
    }

    void authChallengeCanBeCancelledWithoutAnyVpnOrFirewallMutation()
    {
        QTemporaryDir directory;
        Firewall pf;
        MacKillSwitch guard(std::ref(pf), directory.filePath("state.json"));
        ServiceVpnSession session(&guard, {});
        QSignalSpy challenges(&session, &ServiceVpnSession::notification);
        auto pending = QtConcurrent::run([&] {
            QString answer;
            return session.input("Пароль VPN", "Password", {}, true, {}, {}, answer);
        });
        QTRY_VERIFY(!challenges.isEmpty());
        const auto challenge = challenges.first().at(0).toJsonObject().value("challenge").toString();
        QVERIFY(!session.answer("wrong-challenge", true, "not-a-secret"));
        QVERIFY(session.answer(challenge, false, {}));
        QTRY_VERIFY(pending.isFinished()); QVERIFY(!pending.result());
        QVERIFY(pf.installed.isEmpty());
    }
};

QTEST_MAIN(KillSwitchUiTest)
#include "KillSwitchUiTest.moc"
