// SPDX-License-Identifier: GPL-2.0-or-later
#include "MacKillSwitch.h"
#include "MacNetworkService.h"
#include "MacNetworkClient.h"
#include "dialog/mainwindow.h"
#include "dialog/MyInputDialog.h"
#include "FileLogger.h"
#include "server_storage.h"
#include "VpnProgress.h"
#include <QCheckBox>
#include <QComboBox>
#include <QLabel>
#include <QPromise>
#include <QPushButton>
#include <QSettings>
#include <QTemporaryDir>
#include <QProcess>
#include <QMessageBox>
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
        QCOMPARE(settings.format(), QSettings::IniFormat);
        QVERIFY(settings.fileName().startsWith(settingsDirectory.path() + '/'));
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
                QJsonObject{{"gateway", "https://203.0.113.10"}, {"tls12Only", "not-a-boolean"}},
                QJsonObject{{"gateway", "https://203.0.113.10"}, {"legacyAuth", "not-a-boolean"}},
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
            client.request("connect", {{"gateway", "https://another.example.test:8443/group"}, {"protocol", protocol}, {"tls12Only", true}},
                [&](const QJsonObject&, const QString& e) { failure = e; replied = true; });
            QTRY_VERIFY(replied); QVERIFY2(failure.isEmpty(), qPrintable(failure));
            QCOMPARE(service.m_pendingProfile.value("protocol").toString(), protocol);
            QVERIFY(service.m_pendingProfile.value("tls12Only").toBool());
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
        pf.root.prepend("pass quick all\n");
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
        QVERIFY(pf.root.startsWith("pass quick all"));
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

    void profileTlsCompatibilityIsOptionalAndStoredPerProfile()
    {
        StoredServer profile;
        QVERIFY(!profile.get_tls12_only());
        QVERIFY(!profile.get_legacy_auth());
        profile.set_label("TLS profile regression");
        profile.set_server_gateway("https://vpn.example.test");
        profile.set_protocol_name("anyconnect");
        profile.set_tls12_only(true); profile.set_legacy_auth(true); profile.save();
        QString name = "TLS profile regression";
        StoredServer loaded; QVERIFY(loaded.load(name));
        QVERIFY(loaded.get_tls12_only());
        QVERIFY(loaded.get_legacy_auth());
        StoredServer independent; QVERIFY(!independent.get_tls12_only());
    }

    void serviceProgressOmitsAuthenticationSecretsAndReachesGuiLog()
    {
        QTemporaryDir directory; Firewall pf;
        MacKillSwitch guard(std::ref(pf), directory.filePath("state.json"));
        ServiceVpnSession session(&guard, {});
        QSignalSpy events(&session, &ServiceVpnSession::notification);
        for (const auto& value : {"Cookie: sensitive-test-value", "Authorization: Bearer sensitive-test-value", "Password=sensitive-test-value"})
            session.progress(PRG_INFO, value);
        QCOMPARE(events.count(), 0);
        session.progress(PRG_DEBUG, "not forwarded"); QCOMPARE(events.count(), 0);
        session.progress(PRG_INFO, "TLS negotiation in progress"); QCOMPARE(events.count(), 1);
        QCOMPARE(events.last().first().toJsonObject().value("message").toString(), QString("TLS negotiation in progress"));
        QVERIFY(!safeVpnProgress("https://vpn.example.test/?session=sensitive-test-value").contains("sensitive-test-value"));
        MacNetworkService service(&guard, getuid(), directory.filePath("control.sock"));
        QString error; QVERIFY(service.start(error));
        service.m_monitor.stop(); service.m_busy = true; // Hold before real worker/network.
        auto client = new MacNetworkClient(nullptr, directory.filePath("control.sock"), getuid());
        MainWindow window(nullptr, false, {}, nullptr, client);
        window.show(); QTRY_VERIFY(client->available());
        client->request("connect", {{"gateway", "https://vpn.example.test"}, {"protocol", "anyconnect"}});
        QTRY_VERIFY(!service.m_pendingProfile.isEmpty());
        service.sessionEvent(events.last().first().toJsonObject());
        auto logged = [] {
            for (const auto& entry : Logger::instance().getMessages())
                if (entry.text == "TLS negotiation in progress") return true;
            return false;
        };
        QTRY_VERIFY(logged());
    }

    void stalledPreLoginConnectionProducesAnErrorInsteadOfInfiniteCancel()
    {
        QTemporaryDir directory; Firewall pf;
        MacKillSwitch guard(std::ref(pf), directory.filePath("state.json"));
        ServiceVpnSession session(&guard, {});
        QSignalSpy events(&session, &ServiceVpnSession::notification);
        auto deadline = session.findChild<QTimer*>("vpnConnectDeadline"); QVERIFY(deadline);
        deadline->start(20);
        QTRY_VERIFY(!events.isEmpty());
        QCOMPARE(events.last().first().toJsonObject().value("event").toString(), QString("error"));
        QVERIFY(events.last().first().toJsonObject().value("message").toString().contains("timed out"));
    }

    void connectionDeadlineDoesNotCancelAnOpenPasswordPrompt()
    {
        QTemporaryDir directory; Firewall pf;
        MacKillSwitch guard(std::ref(pf), directory.filePath("state.json"));
        ServiceVpnSession session(&guard, {});
        QSignalSpy events(&session, &ServiceVpnSession::notification);
        auto pending = QtConcurrent::run([&] { QString answer; return session.input("Password", "Password", {}, true, {}, {}, answer); });
        QTRY_VERIFY(session.awaitingInput());
        QTRY_VERIFY(!events.isEmpty());
        const auto challenge = events.first().first().toJsonObject().value("challenge").toString();
        auto deadline = session.findChild<QTimer*>("vpnConnectDeadline"); QVERIFY(deadline);
        deadline->start(20);
        QTest::qWait(50);
        QVERIFY(!pending.isFinished());
        for (const auto& event : events) QVERIFY(event.first().toJsonObject().value("event").toString() != "error");
        QVERIFY(session.answer(challenge, false, {}));
        QTRY_VERIFY(pending.isFinished()); QVERIFY(!pending.result());
    }

    void answeringPasswordAllowsSlowServerAndShowsAuthenticationPhase()
    {
        QTemporaryDir directory; Firewall pf;
        MacKillSwitch guard(std::ref(pf), directory.filePath("state.json"));
        ServiceVpnSession session(&guard, {});
        QSignalSpy events(&session, &ServiceVpnSession::notification);
        auto pending = QtConcurrent::run([&] { QString answer; return session.input("Password", "Password", {}, true, {}, {}, answer); });
        QTRY_VERIFY(!events.isEmpty());
        const auto challenge = events.first().first().toJsonObject().value("challenge").toString();
        QVERIFY(session.answer(challenge, true, "non-secret-regression-value"));
        auto deadline = session.findChild<QTimer*>("vpnConnectDeadline"); QVERIFY(deadline);
        QCOMPARE(deadline->interval(), 90000);
        QVERIFY(deadline->isActive());
        QTRY_VERIFY(pending.isFinished()); QVERIFY(pending.result());
        session.phase("tunnel");
        QTRY_COMPARE(deadline->interval(), 60000);
        session.cancel(); QVERIFY(!deadline->isActive());
    }

    void serviceIndicatorPollsRecoversAndVpnErrorsLeaveControlsAccessible()
    {
        QTemporaryDir directory; Firewall pf; QString error;
        MacKillSwitch guard(std::ref(pf), directory.filePath("state.json")); guard.requestEnabled(false);
        const auto socket = directory.filePath("control.sock");
        MacNetworkService service(&guard, getuid(), socket);
        QVERIFY(service.start(error)); service.m_monitor.stop();
        auto client = new MacNetworkClient(nullptr, socket, getuid());
        MainWindow window(nullptr, false, {}, nullptr, client); window.show();
        auto indicator = window.findChild<QLabel*>("serviceStatusLabel"); QVERIFY(indicator);
        QTRY_VERIFY(window.m_serviceResponding);
        QVERIFY(indicator->text().contains("Служба: отвечает"));
        QVERIFY(indicator->text().contains(service.status().value("service").toObject().value("version").toString()));
        QSignalSpy snapshots(client, &MacNetworkClient::statusChanged);
        const auto before = snapshots.count();
        client->poll(); QTRY_VERIFY(snapshots.count() > before);
        service.m_vpnState = "connecting"; service.m_vpnDetails = {{"phase", "authenticating"}}; service.broadcast();
        QTRY_VERIFY(window.findChild<QLabel*>("vpnPhaseLabel")->text().contains("авторизации"));
        emit window.connectionErrorChanged("VPN server did not complete authentication within 90 seconds.");
        QTRY_VERIFY(window.findChild<QLabel*>("vpnErrorLabel")->isVisible());
        QVERIFY(!window.findChild<QMessageBox*>());
        QVERIFY(window.findChild<QCheckBox*>("killSwitchCheckBox")->isEnabled());
        QVERIFY(window.findChild<QPushButton*>("killSwitchOffButton")->isEnabled());
        // Simulate a live socket that has stopped answering its heartbeat.
        client->m_sent.insert(900001, -7000); client->m_heartbeat = 900001;
        client->poll();
        QVERIFY(!window.m_serviceResponding);
        QVERIFY(indicator->text().contains("нет ответа"));
        QTRY_VERIFY_WITH_TIMEOUT(window.m_serviceResponding, 4000);
        QVERIFY(indicator->text().contains("Служба: отвечает"));
    }

    void failedEnableLeavesVerifiedOffAndDiagnosticsCannotExecuteCommands()
    {
        QTemporaryDir directory; Firewall pf; QString error;
        pf.root.prepend("pass quick all\n");
        MacKillSwitch guard(std::ref(pf), directory.filePath("state.json")); guard.requestEnabled(false);
        const auto socket = directory.filePath("control.sock");
        MacNetworkService service(&guard, getuid(), socket); QVERIFY(service.start(error));
        auto client = new MacNetworkClient(nullptr, socket, getuid());
        MainWindow window(nullptr, false, {}, nullptr, client); window.show();
        QTRY_VERIFY(window.m_serviceResponding);
        client->request("firewall", {{"enabled", true}, {"gateway", "https://203.0.113.10"}});
        QTRY_VERIFY(!service.status().value("firewall").toObject().value("error").toString().isEmpty());
        const auto state = service.status().value("firewall").toObject();
        QVERIFY(state.value("verified").toBool()); QVERIFY(!state.value("armed").toBool());
        QVERIFY(!state.value("recoveryRequired").toBool());
        QTRY_VERIFY(window.findChild<QLabel*>("killSwitchStatusLabel")->text().startsWith("Блокировка выключена"));
        QJsonObject diagnostic;
        client->request("diagnostics", {{"command", "not-executed"}}, [&](const QJsonObject& value, const QString&) { diagnostic = value; });
        QTRY_VERIFY(diagnostic.contains("rootRules"));
        QCOMPARE(diagnostic.value("rootRules").toString(), pf.root);
        QVERIFY(!QJsonDocument(diagnostic).toJson().contains("token"));
        QVERIFY(pf.installed.isEmpty());
    }
};

QTEST_MAIN(KillSwitchUiTest)
#include "KillSwitchUiTest.moc"
