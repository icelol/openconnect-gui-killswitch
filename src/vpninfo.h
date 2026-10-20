/*
 * Copyright (C) 2014 Red Hat
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

#pragma once

#include <QString>
#include <QUrl>
#include "common.h"

class MainWindow;
class StoredServer;
class MacKillSwitch;
class VpnCallbacks;

class VpnInfo {
public:
    VpnInfo(QString name, StoredServer* ss, MainWindow* m);
    VpnInfo(QString name, StoredServer* ss, VpnCallbacks* callbacks);
    ~VpnInfo();

    void setUrl(const QUrl& url);
    int connect();
    void mainloop();
    void get_info(QString& dns, QString& ip, QString& ip6);
    void get_cipher_info(QString& cstp, QString& dtls);
    SOCKET get_cmd_fd() const;
    void reset_vpn();
    bool get_minimize() const;
    bool is_username_form_option(struct oc_auth_form* form, struct oc_form_opt* opt);
    bool is_password_form_option(struct oc_auth_form* form, struct oc_form_opt* opt);

    QString last_err;
    QUrl mUrl;
    MainWindow* m;
    StoredServer* ss;
    struct openconnect_info* vpninfo;
    unsigned int authgroup_set;
    unsigned int password_set;
    unsigned int form_attempt;
    unsigned int form_pass_attempt;

    void logVpncScriptOutput();
    QByteArray generateUniqueInterfaceName();
    MacKillSwitch* killSwitch = nullptr;
    bool killSwitchFailed = false;
    bool attachKillSwitchTunnel();
    VpnCallbacks* callbacks = nullptr;
    bool requestInput(const QString& title, const QString& label, const QStringList& choices,
        bool secret, const QString& banner, const QString& message, QString& answer);
    void notifyError(const QString& error);
    void notifyFirewallError(const QString& error);
    void notifyStats(const struct oc_stats* stats, const QString& dtls);
    void notifyConnected(QString& dns, QString& ip, QString& ip6, QString& cstp, QString& dtls);

private:
    void initialize(QString name, StoredServer* ss, MainWindow* m, VpnCallbacks* callbacks);
    SOCKET cmd_fd;
};
