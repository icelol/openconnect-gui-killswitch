// SPDX-License-Identifier: GPL-2.0-or-later
#include "MacBootGuard.h"
#include "MacKillSwitch.h"
#include "MacPfStates.h"
#include "MacPreferencesMigration.h"
#include <QCoreApplication>
#include <QFile>
#include <QHostInfo>
#include <QNetworkInterface>
#include <QProcess>
#include <QTextStream>
#include <QTemporaryDir>
extern "C" {
#include <openconnect.h>
}
#ifdef Q_OS_MACOS
#include <unistd.h>
#endif

QString bootProtectionPath()
{
    return QStringLiteral("/Library/Application Support/OpenConnect-GUI-KillSwitch/boot.json");
}

namespace {
void quietProgress(void*, int, const char*, ...) {}

// macOS may start PF with an empty root ruleset. In that case only, load
// the administrator's existing /etc/pf.conf. Never replace a live ruleset.
bool bootstrapEmptyPf(QString& error)
{
    auto run = [](const QStringList& args, QString& output) {
        QProcess process;
        process.start("/sbin/pfctl", args);
        if (!process.waitForStarted(3000) || !process.waitForFinished(5000)) {
            process.kill();
            process.waitForFinished(1000);
            return false;
        }
        output = QString::fromUtf8(process.readAllStandardOutput()).trimmed();
        return process.exitStatus() == QProcess::NormalExit && process.exitCode() == 0;
    };
    QString filter, nat, anchors, ignored;
    if (!run({"-sr"}, filter) || !run({"-sn"}, nat) || !run({"-s", "Anchors"}, anchors)) {
        error = "Cannot inspect PF before boot protection";
        return false;
    }
    if (!filter.isEmpty())
        return true;
    if (!nat.isEmpty() || !anchors.isEmpty()) {
        error = "PF has NAT or anchors but no root hook; refusing to replace its configuration";
        return false;
    }
    if (!run({"-n", "-f", "/etc/pf.conf"}, ignored)
        || !run({"-f", "/etc/pf.conf"}, ignored)) {
        error = "Cannot initialize the empty PF ruleset from /etc/pf.conf";
        return false;
    }
    return true;
}
}

int runBootProtection(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    QTextStream out(stdout), err(stderr);
#ifndef Q_OS_MACOS
    err << "Boot protection requires macOS\n";
    return 1;
#else
    if (::geteuid() != 0) {
        err << "Administrator access is required for boot protection\n";
        return 1;
    }
    const auto arguments = app.arguments();
    QString error;
    if (arguments.contains("--migrate-preferences")) {
        bool valid = false;
        const int index = arguments.indexOf("--migrate-preferences") + 1;
        const auto uid = arguments.value(index).toUInt(&valid);
        if (!valid || !migrateLegacyPreferences(uid, error)) { err << error << '\n'; return 1; }
        out << "PASS: application preferences migrated to desktop user without logging values\n";
        return 0;
    }
    if (arguments.contains("--check-pf-abi")) {
        QList<MacPfStates::State> states;
        if (!MacPfStates::read(states, error)) { err << error << '\n'; return 1; }
        out << "PASS: macOS PF state ABI; " << states.size() << " states inspected without mutation\n";
        return 0;
    }
    if (arguments.contains("--check-storage")) {
        // Reproduce Authorization Services: real desktop UID, effective root.
        // Only a private temporary file is changed; no live policy or PF calls.
        QTemporaryDir directory("/private/tmp/ocgui-storage-check.XXXXXX");
        MacKillSwitch::Policy test;
        test.host = "storage-check.invalid";
        const auto path = directory.filePath("boot.json");
        if (!directory.isValid() || !MacKillSwitch::writeBootPolicy(path, test, false, error)) {
            err << error << '\n';
            return 1;
        }
        QProcess console;
        console.start("/usr/bin/stat", {"-f", "%u", "/dev/console"});
        if (!console.waitForFinished(3000))
            return 1;
        bool valid;
        const auto uid = QString::fromUtf8(console.readAllStandardOutput()).trimmed().toUInt(&valid);
        if (!valid || uid < 500 || ::setreuid(uid, 0) != 0)
            return 1;
        const bool saved = MacKillSwitch::writeBootPolicy(path, test, true, error)
            && MacKillSwitch::writeBootPolicy(path, test, false, error);
        ::setreuid(0, 0);
        if (!saved) {
            err << error << '\n';
            return 1;
        }
        out << "PASS: protected settings toggle ON/OFF with desktop real UID and effective root\n";
        return 0;
    }
    if (arguments.contains("--check-tun")) {
        openconnect_init_ssl();
        auto vpn = openconnect_vpninfo_new("OpenConnect interface check", nullptr,
            nullptr, nullptr, quietProgress, nullptr);
        if (!vpn)
            return 1;
        const int result = openconnect_setup_tun_device(vpn, "/usr/bin/true", nullptr);
        const auto name = openconnect_get_ifname(vpn);
        const bool ok = result == 0 && name && QString::fromUtf8(name).startsWith("utun");
        openconnect_vpninfo_free(vpn);
        out << (ok ? "PASS: automatic utun allocation; no routes or VPN credentials used\n"
                   : "FAIL: automatic utun allocation\n");
        return ok ? 0 : 1;
    }
    MacKillSwitch::Policy policy;
    bool enabled = true;
    if (arguments.contains("--prepare-boot")) {
        // Installation must work offline and must not activate protection.
        if (QFile::exists(bootProtectionPath())) {
            if (!MacKillSwitch::readBootPolicy(bootProtectionPath(), policy, enabled, error)) {
                err << error << '\n';
                return 1;
            }
        } else {
            policy.host = "unconfigured.invalid";
            policy.port = 443;
            policy.udpPorts = {443};
            // Fresh installs leave the normal network available. Only an
            // explicit switch in the GUI may enable boot protection.
            if (!MacKillSwitch::writeBootPolicy(bootProtectionPath(), policy, false, error)) {
                err << error << '\n';
                return 1;
            }
        }
        out << "Boot protection configuration is ready; no credentials stored\n";
        return 0;
    }
    if (!MacKillSwitch::readBootPolicy(bootProtectionPath(), policy, enabled, error)) {
        err << error << '\n';
        return 1;
    }
    if (!enabled) {
        out << "Boot protection was explicitly disabled\n";
        return 0;
    }
    if (arguments.contains("--check-boot")) {
        out << "Boot protection is configured for " << policy.host << '\n';
        return 0;
    }
    if (arguments.contains("--verify-guard")) {
        MacKillSwitch guard;
        if (!guard.verifySavedState(error)) {
            err << error << '\n';
            return 1;
        }
        out << "PASS: active PF protection matches its saved policy\n";
        return 0;
    }
    if (!bootstrapEmptyPf(error)) {
        err << error << '\n';
        return 1;
    }
    MacKillSwitch guard({}, "/var/run/openconnect-gui-killswitch/state.json", bootProtectionPath());
    if (!guard.restoreBootProtection(error) || !guard.verify(error)) {
        err << error << '\n';
        return 1;
    }
    out << (guard.isArmed() ? "Boot kill switch armed; only VPN gateway and link setup are allowed\n"
                           : "Boot protection was explicitly disabled\n");
    return 0;
#endif
}
