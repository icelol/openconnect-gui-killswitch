// SPDX-License-Identifier: GPL-2.0-or-later
#include "MacPfStates.h"
#include <QtEndian>
#include <array>
#include <cstring>
#include <limits>
#ifdef Q_OS_MACOS
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace {
// macOS PF wire ABI, independently checked against Mullvad pfctl-rs at
// d688958c9f51dbc86c939b9163e07631d3e1ece8/src/ffi/pfvar.rs.
// SDKs omit these private headers. pfsync_state is a PACKED 297-byte record;
// pfioc_states is 16 bytes; pfioc_state_kill is 216 bytes, aligned to 8.
// Attribution/license: docs/third-party/pfctl-rs-MIT.txt.
constexpr int stateBytes = 297;
struct GetStates { int length; void* buffer; };
struct alignas(8) KillState { unsigned char bytes[216]{}; };
static_assert(sizeof(GetStates) == 16 && offsetof(GetStates, buffer) == 8);
static_assert(sizeof(KillState) == 216);

QHostAddress address(const unsigned char* bytes, unsigned family)
{
    if (family == 2)
        return QHostAddress(qFromBigEndian<quint32>(bytes));
    Q_IPV6ADDR ip;
    std::memcpy(ip.c, bytes, 16);
    return QHostAddress(ip);
}

bool exact(const QHostAddress& address, const QString& assigned)
{
    return !assigned.isEmpty() && address == QHostAddress(assigned);
}

#ifdef Q_OS_MACOS
struct Device {
    int fd = ::open("/dev/pf", O_RDWR | O_CLOEXEC);
    ~Device() { if (fd >= 0) ::close(fd); }
};

bool getStates(int fd, QList<MacPfStates::State>& states, QString& error)
{
    for (int attempt = 0; attempt < 4; ++attempt) {
        GetStates query{};
        if (::ioctl(fd, _IOWR('D', 25, GetStates), &query) != 0 || query.length < 0
            || query.length > 64 * 1024 * 1024) {
            error = "Cannot enumerate PF states: " + QString::fromLocal8Bit(strerror(errno));
            return false;
        }
        const int capacity = query.length + 128 * stateBytes;
        QByteArray buffer(capacity, '\0');
        query = {capacity, buffer.data()};
        if (::ioctl(fd, _IOWR('D', 25, GetStates), &query) != 0) {
            error = "Cannot read PF states: " + QString::fromLocal8Bit(strerror(errno));
            return false;
        }
        if (query.length >= capacity)
            continue;
        if (query.length < 0 || query.length % stateBytes) {
            error = "Unsupported macOS PF state ABI; no states were removed";
            return false;
        }
        states.clear();
        for (int offset = 0; offset < query.length; offset += stateBytes) {
            MacPfStates::State state;
            if (!MacPfStates::decode(buffer.mid(offset, stateBytes), state, error))
                return false;
            states << state;
        }
        return true;
    }
    error = "PF state table changed too quickly to inspect safely";
    return false;
}

bool kill(int fd, const MacPfStates::State& state, QString& error)
{
    const auto bytes = MacPfStates::killRequest(state, error);
    if (bytes.isEmpty()) return false;
    KillState request;
    std::memcpy(request.bytes, bytes.constData(), sizeof(request));
    if (::ioctl(fd, _IOWR('D', 41, KillState), &request) != 0) {
        error = "Cannot remove a disallowed PF state: " + QString::fromLocal8Bit(strerror(errno));
        return false;
    }
    return true;
}
#endif
}

bool MacPfStates::decode(const QByteArray& wire, State& state, QString& error)
{
    if (wire.size() != stateBytes) {
        error = "Invalid macOS PF state size";
        return false;
    }
    const auto data = reinterpret_cast<const unsigned char*>(wire.constData());
    const auto family = data[282];
    if ((family != 2 && family != 30) || (data[285] != 1 && data[285] != 2)
        || std::memchr(data + 8, '\0', 16) == nullptr) {
        error = "Unrecognized macOS PF state; protection cannot be confirmed";
        return false;
    }
    state = {};
    state.wire = wire;
    state.family = family;
    state.direction = data[285];
    state.protocol = data[284];
    state.interfaceName = QString::fromLatin1(reinterpret_cast<const char*>(data + 8));
    state.local = address(data + 24, family);
    state.remote = address(data + 72, family);
    state.localPort = qFromBigEndian<quint16>(data + 40);
    state.remotePort = qFromBigEndian<quint16>(data + 88);
    return true;
}

bool MacPfStates::permitted(const State& state, const MacKillSwitch::Policy& policy,
    bool trustedGatewayStates)
{
    if (state.local.isLoopback() && state.remote.isLoopback())
        return state.interfaceName == "lo0" || state.interfaceName == "all" || state.interfaceName.isEmpty();
    if (!policy.interfaceName.isEmpty() && state.interfaceName == policy.interfaceName
        && (exact(state.local, policy.ipv4) || exact(state.local, policy.ipv6)))
        return true;
    if (state.protocol == 17 && state.localPort == 68 && state.remotePort == 67
        && state.remote == QHostAddress("255.255.255.255"))
        return true;
    // Existing floating gateway states cannot prove root ownership. Only retain
    // states created after this daemon already verified the root-only policy.
    if (!trustedGatewayStates || state.direction != 2 || state.interfaceName.isEmpty()
        || state.interfaceName == "all")
        return false;
    bool gateway = false;
    for (const auto& ip : policy.addresses)
        gateway |= state.remote == QHostAddress(ip);
    if (gateway && ((state.protocol == 6 && state.remotePort == policy.port)
        || (state.protocol == 17 && policy.udpPorts.contains(state.remotePort)))) return true;
    for (const auto& endpoint : policy.sessionEndpoints) {
        bool matches = false;
        for (const auto& ip : endpoint.addresses) matches |= state.remote == QHostAddress(ip);
        if (matches && ((state.protocol == 6 && state.remotePort == endpoint.port)
            || (state.protocol == 17 && endpoint.udpPorts.contains(state.remotePort)))) return true;
    }
    return false;
}

QByteArray MacPfStates::killRequest(const State& state, QString& error)
{
    State decoded;
    if (!decode(state.wire, decoded, error)) return {};
    QByteArray request(216, '\0');
    auto out = reinterpret_cast<unsigned char*>(request.data());
    const auto raw = reinterpret_cast<const unsigned char*>(state.wire.constData());
    out[0] = decoded.family;
    out[1] = decoded.protocol;
    out[2] = raw[291]; // proto_variant
    std::memcpy(out + 136, raw + 8, 16);
    // Apple pfioctl_ioc_state_kill matches src/dst in the ORIGINAL direction:
    // PF_OUT: lan -> ext_lan; PF_IN: ext_lan -> lan. Reversing this for inbound
    // states would leave old inbound connections alive despite the block rule.
    const int source = decoded.direction == 2 ? 24 : 72;
    const int destination = decoded.direction == 2 ? 72 : 24;
    for (const auto& offsets : {std::pair<int,int>{8,source}, {72,destination}}) {
        std::memcpy(out + offsets.first, raw + offsets.second, 16);
        std::memset(out + offsets.first + 16, 0xff, decoded.family == 2 ? 4 : 16);
        if (decoded.protocol == 6 || decoded.protocol == 17) {
            // pf_rule_xport.range.port[0/1], PF_OP_EQ. Bound the deletion to
            // these ports as well as the interface, protocol and both IPs.
            std::memcpy(out + offsets.first + 52, raw + offsets.second + 16, 2);
            std::memcpy(out + offsets.first + 54, raw + offsets.second + 16, 2);
            out[offsets.first + 56] = 2;
        }
    }
    return request;
}

bool MacPfStates::read(QList<State>& states, QString& error)
{
#ifdef Q_OS_MACOS
    Device device;
    if (device.fd >= 0)
        return getStates(device.fd, states, error);
    error = "Cannot open /dev/pf for state inspection: " + QString::fromLocal8Bit(strerror(errno));
#else
    error = "PF state management requires macOS";
#endif
    return false;
}

bool MacPfStates::prune(const MacKillSwitch::Policy& policy, bool trustedGatewayStates, QString& error)
{
#ifdef Q_OS_MACOS
    Device device;
    if (device.fd < 0) {
        error = "Cannot open /dev/pf for selective state cleanup";
        return false;
    }
    for (int pass = 0; pass < 3; ++pass) {
        QList<State> states;
        if (!getStates(device.fd, states, error))
            return false;
        bool removed = false;
        for (const auto& state : states) {
            if (!permitted(state, policy, trustedGatewayStates)) {
                if (!kill(device.fd, state, error))
                    return false;
                removed = true;
            }
        }
        if (!removed)
            return true; // Read-back proved no disallowed surviving states.
    }
    error = "Disallowed PF states survived selective removal; protection is not confirmed";
#else
    error = "PF state management requires macOS";
#endif
    return false;
}
