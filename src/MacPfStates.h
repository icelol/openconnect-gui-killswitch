// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include "NetworkGuard.h"
#include <QHostAddress>

// The only state mutation is deletion of a particular interface/protocol/tuple.
// There is deliberately no global state-flush operation or fallback.
class MacPfStates {
public:
    struct State {
        QByteArray wire;
        QString interfaceName;
        QHostAddress local, remote;
        quint16 localPort = 0, remotePort = 0;
        quint8 protocol = 0, family = 0, direction = 0;
    };
    static bool decode(const QByteArray& wire, State& state, QString& error);
    static bool permitted(const State& state, const NetworkGuard::Policy& policy,
        bool trustedGatewayStates);
    static QByteArray killRequest(const State& state, QString& error);
    static bool read(QList<State>& states, QString& error);
    static bool prune(const NetworkGuard::Policy& policy, bool trustedGatewayStates, QString& error);
};
