// SPDX-License-Identifier: GPL-2.0-or-later
#include "NetworkGuard.h"
#include "WindowsDnsBootstrap.h"
#include "WindowsSystemService.h"
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHostAddress>
#include <QJsonArray>
#include <QJsonDocument>
#include <QMutexLocker>
#include <QNetworkInterface>
#include <QSaveFile>
#include <QSet>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <array>
#include <cstring>
// clang-format off
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fwpmu.h>
#include "WindowsWfpConstants.h"
#include <iphlpapi.h>
#include <netioapi.h>
#include <sddl.h>
// clang-format on
#include <vector>

namespace {
// Stable project-owned keys; no filters from another provider are mutated.
const GUID providerKey{ 0xe17433be, 0xa4d4, 0x4c79, { 0x91, 0x40, 0x8b, 0x9a, 0x54, 0xe2, 0x77, 0x61 } };
const GUID sublayerKey{ 0xd754b232, 0x635f, 0x478c, { 0xa4, 0xd6, 0xb8, 0xb5, 0x0b, 0x5b, 0xc2, 0x11 } };
const std::array<GUID, 4> layers{ FWPM_LAYER_ALE_AUTH_CONNECT_V4, FWPM_LAYER_ALE_AUTH_CONNECT_V6,
    FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4, FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6 };
bool status(DWORD result, QString& error, const char* operation)
{
    if (!result)
        return true;
    error = QString("WFP %1 failed (0x%2)").arg(operation).arg(qulonglong(result), 8, 16, QChar('0'));
    return false;
}
struct Blob {
    FWP_BYTE_BLOB* value = nullptr;
    ~Blob()
    {
        if (value)
            FwpmFreeMemory0(reinterpret_cast<void**>(&value));
    }
};
struct SystemAccess {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    FWP_BYTE_BLOB blob{};
    SystemAccess()
    {
        if (ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:(A;;0x00000001;;;SY)", SDDL_REVISION_1, &descriptor, nullptr)) {
            blob.size = GetSecurityDescriptorLength(descriptor);
            blob.data = static_cast<UINT8*>(descriptor);
        }
    }
    ~SystemAccess()
    {
        if (descriptor)
            LocalFree(descriptor);
    }
};
struct Transaction {
    HANDLE engine;
    bool open;
    Transaction(HANDLE handle, QString& error)
        : engine(handle)
        , open(status(FwpmTransactionBegin0(handle, 0), error, "transaction"))
    {
    }
    ~Transaction()
    {
        if (open)
            FwpmTransactionAbort0(engine);
    }
    bool commit(QString& error)
    {
        if (!open)
            return false;
        const auto r = FwpmTransactionCommit0(engine);
        if (!r)
            open = false;
        return status(r, error, "commit");
    }
};
struct Conditions {
    std::vector<FWPM_FILTER_CONDITION0> values;
    FWP_BYTE_ARRAY16 v6{};
    FWP_V6_ADDR_AND_MASK mask{};
    UINT64 luid = 0;
    void number(const GUID& key, UINT32 value, FWP_DATA_TYPE type = FWP_UINT32, FWP_MATCH_TYPE match = FWP_MATCH_EQUAL)
    {
        FWPM_FILTER_CONDITION0 c{};
        c.fieldKey = key;
        c.matchType = match;
        c.conditionValue.type = type;
        if (type == FWP_UINT8)
            c.conditionValue.uint8 = UINT8(value);
        else if (type == FWP_UINT16)
            c.conditionValue.uint16 = UINT16(value);
        else
            c.conditionValue.uint32 = value;
        values.push_back(c);
    }
    bool address(const GUID& key, const QString& value)
    {
        QHostAddress address(value);
        if (address.isNull())
            return false;
        if (address.protocol() == QAbstractSocket::IPv4Protocol)
            number(key, address.toIPv4Address());
        else {
            const auto bytes = address.toIPv6Address();
            std::memcpy(v6.byteArray16, bytes.c, 16);
            FWPM_FILTER_CONDITION0 c{};
            c.fieldKey = key;
            c.matchType = FWP_MATCH_EQUAL;
            c.conditionValue.type = FWP_BYTE_ARRAY16_TYPE;
            c.conditionValue.byteArray16 = &v6;
            values.push_back(c);
        }
        return true;
    }
    void app(FWP_BYTE_BLOB* app)
    {
        FWPM_FILTER_CONDITION0 c{};
        c.fieldKey = FWPM_CONDITION_ALE_APP_ID;
        c.matchType = FWP_MATCH_EQUAL;
        c.conditionValue.type = FWP_BYTE_BLOB_TYPE;
        c.conditionValue.byteBlob = app;
        values.push_back(c);
    }
    void user(FWP_BYTE_BLOB* sd)
    {
        FWPM_FILTER_CONDITION0 c{};
        c.fieldKey = FWPM_CONDITION_ALE_USER_ID;
        c.matchType = FWP_MATCH_EQUAL;
        c.conditionValue.type = FWP_SECURITY_DESCRIPTOR_TYPE;
        c.conditionValue.sd = sd;
        values.push_back(c);
    }
    void prefix(const QString& ip, UINT8 length)
    {
        const auto bytes = QHostAddress(ip).toIPv6Address();
        std::memcpy(mask.addr, bytes.c, 16);
        mask.prefixLength = length;
        FWPM_FILTER_CONDITION0 c{};
        c.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
        c.matchType = FWP_MATCH_EQUAL;
        c.conditionValue.type = FWP_V6_ADDR_MASK;
        c.conditionValue.v6AddrMask = &mask;
        values.push_back(c);
    }
    void networkInterface(const GUID& key, UINT64 value)
    {
        luid = value;
        FWPM_FILTER_CONDITION0 c{};
        c.fieldKey = key;
        c.matchType = FWP_MATCH_EQUAL;
        c.conditionValue.type = FWP_UINT64;
        c.conditionValue.uint64 = &luid;
        values.push_back(c);
    }
};
bool filter(HANDLE engine, const GUID& layer, bool persistent, FWP_ACTION_TYPE action,
    UINT64 weight, Conditions& conditions, const wchar_t* name, QString& error, UINT64* id = nullptr)
{
    FWPM_FILTER0 item{};
    item.providerKey = const_cast<GUID*>(&providerKey);
    item.subLayerKey = sublayerKey;
    item.layerKey = layer;
    item.displayData.name = const_cast<wchar_t*>(name);
    item.flags = persistent ? FWPM_FILTER_FLAG_PERSISTENT : 0;
    item.action.type = action;
    item.weight.type = FWP_UINT64;
    item.weight.uint64 = &weight;
    item.numFilterConditions = UINT32(conditions.values.size());
    item.filterCondition = conditions.values.data();
    UINT64 result = 0;
    const auto ok = status(FwpmFilterAdd0(engine, &item, nullptr, &result), error, "add filter");
    if (id)
        *id = result;
    return ok;
}
QList<quint64> owned(HANDLE engine, QString& error, int* blocks = nullptr)
{
    QList<quint64> result;
    if (blocks)
        *blocks = 0;
    FWPM_PROVIDER0* provider = nullptr;
    const auto found = FwpmProviderGetByKey0(engine, &providerKey, &provider);
    if (found == FWP_E_PROVIDER_NOT_FOUND)
        return result;
    if (!status(found, error, "read provider"))
        return result;
    FwpmFreeMemory0(reinterpret_cast<void**>(&provider));
    for (const auto& layer : layers) {
        FWPM_FILTER_ENUM_TEMPLATE0 request{};
        request.providerKey = const_cast<GUID*>(&providerKey);
        request.layerKey = layer;
        request.enumType = FWP_FILTER_ENUM_FULLY_CONTAINED;
        request.actionMask = 0xffffffff;
        HANDLE enumeration = nullptr;
        if (!status(FwpmFilterCreateEnumHandle0(engine, &request, &enumeration), error, "enumerate"))
            return {};
        bool done = false;
        while (!done) {
            FWPM_FILTER0** entries = nullptr;
            UINT32 count = 0;
            const auto code = FwpmFilterEnum0(engine, enumeration, 128, &entries, &count);
            if (!status(code, error, "read filters")) {
                FwpmFilterDestroyEnumHandle0(engine, enumeration);
                return {};
            }
            for (UINT32 i = 0; i < count; ++i) {
                if (entries[i]->providerKey && IsEqualGUID(*entries[i]->providerKey, providerKey)) {
                    result << entries[i]->filterId;
                    if (blocks && entries[i]->action.type == FWP_ACTION_BLOCK && !entries[i]->numFilterConditions
                        && (entries[i]->flags & FWPM_FILTER_FLAG_PERSISTENT))
                        ++*blocks;
                }
            }
            if (entries)
                FwpmFreeMemory0(reinterpret_cast<void**>(&entries));
            done = count < 128;
            if (result.size() > 2048) {
                error = "Unexpected number of owned WFP filters";
                break;
            }
        }
        FwpmFilterDestroyEnumHandle0(engine, enumeration);
        if (!error.isEmpty())
            return {};
    }
    return result;
}
bool literal(const QString& text)
{
    QHostAddress ip(text);
    return !text.contains('%') && !ip.isNull() && !ip.isLoopback() && !ip.isMulticast();
}
bool tunnel(const NetworkGuard::Policy& policy, UINT64& luid, QString& error)
{
    NET_LUID result{};
    const auto alias = policy.interfaceName.toStdWString();
    MIB_IF_ROW2 row{};
    if (alias.empty() || ConvertInterfaceAliasToLuid(alias.c_str(), &result) != NO_ERROR) {
        error = "VPN adapter was not found";
        return false;
    }
    row.InterfaceLuid = result;
    if (GetIfEntry2(&row) != NO_ERROR || row.OperStatus != IfOperStatusUp) {
        error = "VPN adapter is not up";
        return false;
    }
    bool found4 = policy.ipv4.isEmpty(), found6 = policy.ipv6.isEmpty();
    // Qt's Windows interface name can be a GUID rather than the friendly alias.
    for (const auto& adapter : QNetworkInterface::allInterfaces()) {
        if (adapter.humanReadableName() != policy.interfaceName && adapter.index() != int(row.InterfaceIndex))
            continue;
        for (const auto& address : adapter.addressEntries()) {
            found4 |= !policy.ipv4.isEmpty() && address.ip() == QHostAddress(policy.ipv4);
            found6 |= !policy.ipv6.isEmpty() && address.ip() == QHostAddress(policy.ipv6);
        }
    }
    if (!found4 || !found6 || (policy.ipv4.isEmpty() && policy.ipv6.isEmpty())) {
        error = "VPN addresses were not assigned to the expected adapter";
        return false;
    }
    luid = result.Value;
    return true;
}
}

struct NetworkGuard::WindowsState {
    HANDLE persistent = nullptr, dynamic = nullptr;
    QList<quint64> permits;
    ~WindowsState()
    {
        if (dynamic)
            FwpmEngineClose0(dynamic);
        if (persistent)
            FwpmEngineClose0(persistent);
    }
    bool open(QString& error)
    {
        if (persistent && dynamic)
            return true;
        if (!persistent && !status(FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &persistent), error, "open engine"))
            return false;
        FWPM_SESSION0 session{};
        session.flags = FWPM_SESSION_FLAG_DYNAMIC;
        return dynamic || status(FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &dynamic), error, "open dynamic session");
    }
    bool objects(QString& error)
    {
        if (!open(error))
            return false;
        FWPM_PROVIDER0 provider{};
        provider.providerKey = providerKey;
        provider.flags = FWPM_PROVIDER_FLAG_PERSISTENT;
        provider.serviceName = const_cast<wchar_t*>(L"OpenConnectKillSwitch");
        provider.displayData.name = const_cast<wchar_t*>(L"OpenConnect Kill Switch");
        auto code = FwpmProviderAdd0(persistent, &provider, nullptr);
        if (code != FWP_E_ALREADY_EXISTS && !status(code, error, "provider"))
            return false;
        FWPM_SUBLAYER0 layer{};
        layer.subLayerKey = sublayerKey;
        layer.providerKey = const_cast<GUID*>(&providerKey);
        layer.flags = FWPM_SUBLAYER_FLAG_PERSISTENT;
        layer.weight = 0xefff;
        layer.displayData.name = const_cast<wchar_t*>(L"OpenConnect network protection");
        code = FwpmSubLayerAdd0(persistent, &layer, nullptr);
        return code == FWP_E_ALREADY_EXISTS || status(code, error, "sublayer");
    }
    bool base(QString& error)
    {
        if (!objects(error))
            return false;
        int count = 0;
        owned(persistent, error, &count);
        if (!error.isEmpty())
            return false;
        if (count == 4)
            return true;
        if (count) {
            error = "Incomplete persistent WFP policy; disable explicitly to recover";
            return false;
        }
        Transaction transaction(persistent, error);
        if (!transaction.open)
            return false;
        wchar_t system[MAX_PATH]{};
        if (!GetSystemDirectoryW(system, MAX_PATH)) {
            error = "Cannot locate System32";
            return false;
        }
        Blob dhcp;
        const auto path = (QString::fromWCharArray(system) + "/svchost.exe").toStdWString();
        if (!status(FwpmGetAppIdFromFileName0(path.c_str(), &dhcp.value), error, "DHCP app identity"))
            return false;
        for (size_t i = 0; i < layers.size(); ++i) {
            Conditions all;
            if (!filter(persistent, layers[i], true, FWP_ACTION_BLOCK, 1, all, L"OpenConnect block outside VPN", error))
                return false;
            Conditions loop;
            loop.number(FWPM_CONDITION_FLAGS, FWP_CONDITION_FLAG_IS_LOOPBACK, FWP_UINT32, FWP_MATCH_FLAGS_ALL_SET);
            if (!filter(persistent, layers[i], true, FWP_ACTION_PERMIT, 100, loop, L"OpenConnect loopback bootstrap", error))
                return false;
            Conditions ports;
            ports.app(dhcp.value);
            ports.number(FWPM_CONDITION_IP_PROTOCOL, IPPROTO_UDP, FWP_UINT8);
            ports.number(FWPM_CONDITION_IP_LOCAL_PORT, i % 2 ? 546 : 68, FWP_UINT16);
            ports.number(FWPM_CONDITION_IP_REMOTE_PORT, i % 2 ? 547 : 67, FWP_UINT16);
            if (!filter(persistent, layers[i], true, FWP_ACTION_PERMIT, 100, ports, L"OpenConnect system DHCP bootstrap", error))
                return false;
            if (i % 2) {
                const QList<UINT16> types = i < 2 ? QList<UINT16>{ 133, 135, 136 } : QList<UINT16>{ 134, 135, 136 };
                const QStringList scopes = i < 2 ? QStringList{ "fe80::", "ff02::" } : QStringList{ "fe80::" };
                for (const auto& scope : scopes)
                    for (auto type : types) {
                        Conditions ndp;
                        ndp.prefix(scope, scope == "fe80::" ? 10 : 16);
                        ndp.number(FWPM_CONDITION_IP_PROTOCOL, IPPROTO_ICMPV6, FWP_UINT8);
                        ndp.number(FWPM_CONDITION_IP_LOCAL_PORT, type, FWP_UINT16);
                        if (!filter(persistent, layers[i], true, FWP_ACTION_PERMIT, 100, ndp, L"OpenConnect IPv6 neighbor bootstrap", error))
                            return false;
                    }
            }
        }
        return transaction.commit(error);
    }
    bool endpoint(const QString& ip, quint16 port, UINT8 protocol, FWP_BYTE_BLOB* app, QString& error, QList<quint64>& ids)
    {
        if (!literal(ip) || !port) {
            error = "Invalid VPN endpoint address or port";
            return false;
        }
        SystemAccess system;
        if (!system.descriptor) {
            error = "Cannot constrain the endpoint to LocalSystem";
            return false;
        }
        Conditions conditions;
        conditions.address(FWPM_CONDITION_IP_REMOTE_ADDRESS, ip);
        conditions.app(app);
        conditions.user(&system.blob);
        conditions.number(FWPM_CONDITION_IP_PROTOCOL, protocol, FWP_UINT8);
        conditions.number(FWPM_CONDITION_IP_REMOTE_PORT, port, FWP_UINT16);
        UINT64 id = 0;
        const auto index = QHostAddress(ip).protocol() == QAbstractSocket::IPv4Protocol ? 0 : 1;
        if (!filter(dynamic, layers[index], false, FWP_ACTION_PERMIT, 200, conditions, L"OpenConnect service endpoint", error, &id))
            return false;
        ids << id;
        return true;
    }
    bool replace(const Policy& policy, const QStringList& dns, QString& error)
    {
        if (!open(error))
            return false;
        Transaction transaction(dynamic, error);
        if (!transaction.open)
            return false;
        for (auto id : permits) {
            const auto code = FwpmFilterDeleteById0(dynamic, id);
            if (code != FWP_E_FILTER_NOT_FOUND && !status(code, error, "remove permit"))
                return false;
        }
        QList<quint64> next;
        Blob app;
        const auto path = QDir::toNativeSeparators(QCoreApplication::applicationFilePath()).toStdWString();
        if (!status(FwpmGetAppIdFromFileName0(path.c_str(), &app.value), error, "service app identity"))
            return false;
        auto endpoints = policy.sessionEndpoints;
        endpoints.prepend({ policy.host, policy.addresses, policy.port, policy.udpPorts });
        for (const auto& endpoint : endpoints)
            for (const auto& ip : endpoint.addresses) {
                if (!this->endpoint(ip, endpoint.port, IPPROTO_TCP, app.value, error, next))
                    return false;
                for (auto port : endpoint.udpPorts)
                    if (!this->endpoint(ip, port, IPPROTO_UDP, app.value, error, next))
                        return false;
            }
        for (auto server : dns) {
            QHostAddress ip(server);
            if (ip.isLoopback())
                continue;
            ip.setScopeId({});
            if (!endpoint(ip.toString(), 53, IPPROTO_UDP, app.value, error, next)
                || !endpoint(ip.toString(), 53, IPPROTO_TCP, app.value, error, next))
                return false;
        }
        if (!policy.interfaceName.isEmpty()) {
            UINT64 luid = 0;
            if (!tunnel(policy, luid, error))
                return false;
            for (size_t i = 0; i < layers.size(); ++i) {
                const auto ip = i % 2 ? policy.ipv6 : policy.ipv4;
                if (ip.isEmpty())
                    continue;
                Conditions conditions;
                conditions.networkInterface(i < 2 ? FWPM_CONDITION_IP_NEXTHOP_INTERFACE : FWPM_CONDITION_IP_ARRIVAL_INTERFACE, luid);
                conditions.address(FWPM_CONDITION_IP_LOCAL_ADDRESS, ip);
                UINT64 id = 0;
                if (!filter(dynamic, layers[i], false, FWP_ACTION_PERMIT, 150, conditions, L"OpenConnect exact VPN adapter", error, &id))
                    return false;
                next << id;
            }
        }
        if (!transaction.commit(error))
            return false;
        permits = next;
        return true;
    }
    bool remove(QString& error)
    {
        if (!open(error))
            return false;
        // First close all dynamic permits owned by this process. A stopped or
        // crashed previous service already lost its permits in the WFP engine.
        if (!permits.isEmpty()) {
            Transaction transaction(dynamic, error);
            if (!transaction.open)
                return false;
            for (auto id : permits) {
                const auto code = FwpmFilterDeleteById0(dynamic, id);
                if (code != FWP_E_FILTER_NOT_FOUND && !status(code, error, "remove dynamic filter"))
                    return false;
            }
            if (!transaction.commit(error))
                return false;
            permits.clear();
        }
        Transaction transaction(persistent, error);
        if (!transaction.open)
            return false;
        const auto ids = owned(persistent, error);
        if (!error.isEmpty())
            return false;
        for (auto id : ids)
            if (!status(FwpmFilterDeleteById0(persistent, id), error, "remove owned filter"))
                return false;
        const auto sub = FwpmSubLayerDeleteByKey0(persistent, &sublayerKey);
        if (sub != FWP_E_SUBLAYER_NOT_FOUND && !status(sub, error, "remove sublayer"))
            return false;
        const auto provider = FwpmProviderDeleteByKey0(persistent, &providerKey);
        if (provider != FWP_E_PROVIDER_NOT_FOUND && !status(provider, error, "remove provider"))
            return false;
        return transaction.commit(error);
    }
};

NetworkGuard::NetworkGuard(Runner runner, QString statePath, QString bootPath, StatePruner prune, DnsLookup lookup, QStringList servers)
    : m_windows(std::make_unique<WindowsState>())
    , m_dnsLookup(lookup ? std::move(lookup) : DnsLookup(WindowsDnsBootstrap::lookup))
    , m_dnsServers(std::move(servers))
    , m_statePath(std::move(statePath))
    , m_bootPath(std::move(bootPath))
{
    Q_UNUSED(runner);
    Q_UNUSED(prune);
    m_requested = false;
}
NetworkGuard::~NetworkGuard() = default;
QString NetworkGuard::anchor() { return "OpenConnectKillSwitch WFP provider"; }
void NetworkGuard::requestEnabled(bool enabled) { m_requested = enabled; }
bool NetworkGuard::isRequested() const { return m_requested; }
bool NetworkGuard::isArmed() const { return m_armed; }
bool NetworkGuard::hasTunnel() const { return m_hasTunnel; }

bool NetworkGuard::save(QString& error)
{
    if (!WindowsSystemService::trustedFile(QFileInfo(m_statePath).absolutePath())) {
        error = "Unsafe WFP state directory";
        return false;
    }
    QJsonArray addresses;
    for (const auto& ip : m_policy.addresses)
        addresses << ip;
    QJsonObject object{ { "schema", 2 }, { "enabled", bool(m_requested) }, { "host", m_policy.host }, { "port", int(m_policy.port) }, { "addresses", addresses } };
    QSaveFile file(m_statePath);
    const auto data = QJsonDocument(object).toJson();
    if (!file.open(QIODevice::WriteOnly) || file.write(data) != data.size() || !file.commit()) {
        error = "Cannot persist the Windows kill switch setting";
        return false;
    }
    return WindowsSystemService::protectFile(m_statePath, error);
}
bool NetworkGuard::restore(QString& error) { return restoreBootProtection(error); }
bool NetworkGuard::restoreBootProtection(QString& error)
{
    QMutexLocker lock(&m_mutex);
    error.clear();
    if (!m_windows->open(error))
        return false;
    const auto existing = owned(m_windows->persistent, error);
    if (!error.isEmpty())
        return false;
    m_armed = !existing.isEmpty();
    m_requested = bool(m_armed);
    if (!QFile::exists(m_statePath)) {
        if (m_armed) {
            error = "Orphaned WFP protection found; disable explicitly to recover";
            return false;
        }
        m_requested = false;
        return true;
    }
    if (!WindowsSystemService::trustedFile(m_statePath)) {
        error = "Unsafe Windows service state";
        return false;
    }
    QFile file(m_statePath);
    if (!file.open(QIODevice::ReadOnly) || file.size() > 65536) {
        error = "Cannot read Windows service state";
        return false;
    }
    QJsonParseError parse;
    const auto object = QJsonDocument::fromJson(file.readAll(), &parse).object();
    if (parse.error != QJsonParseError::NoError || object.value("schema").toInt() != 2 || !object.value("enabled").isBool()) {
        error = "Invalid Windows service state";
        return false;
    }
    m_requested = object.value("enabled").toBool();
    m_policy = {};
    m_policy.host = object.value("host").toString();
    const auto port = object.value("port").toInt(443);
    if (port < 1 || port > 65535) {
        error = "Invalid saved VPN port";
        return false;
    }
    m_policy.port = quint16(port);
    m_policy.udpPorts << quint16(port);
    for (const auto& ip : object.value("addresses").toArray()) {
        if (!literal(ip.toString())) {
            error = "Invalid saved VPN address";
            return false;
        }
        m_policy.addresses << ip.toString();
    }
    if (!m_requested)
        return disableUnlocked(error);
    return apply(m_policy, false, error);
}
bool NetworkGuard::apply(const Policy& policy, bool, QString& error)
{
    for (const auto& ip : policy.addresses)
        if (!literal(ip)) {
            error = "Invalid gateway address";
            return false;
        }
    m_policy = policy;
    if (!save(error) || !m_windows->base(error))
        return false;
    m_armed = true;
    if (!m_windows->replace(m_policy, {}, error))
        return false;
    m_hasTunnel = !m_policy.interfaceName.isEmpty();
    return verifyUnlocked(error);
}
bool NetworkGuard::arm(const QUrl& gateway, QString& error)
{
    QMutexLocker lock(&m_mutex);
    error.clear();
    if (!m_requested)
        return true;
    if (!gateway.isEmpty() && (!gateway.isValid() || gateway.scheme() != "https" || gateway.host().isEmpty() || !gateway.userInfo().isEmpty() || gateway.hasQuery() || gateway.hasFragment() || gateway.port(443) < 1 || gateway.port(443) > 65535)) {
        error = "Enter a valid HTTPS VPN gateway";
        return false;
    }
    Policy next;
    next.host = gateway.isEmpty() ? "unconfigured.invalid" : gateway.host();
    next.port = quint16(gateway.port(443));
    next.udpPorts << next.port;
    if (next.host == m_policy.host && next.port == m_policy.port)
        next.addresses = m_policy.addresses;
    if (QHostAddress ip(next.host); !ip.isNull())
        next.addresses = { ip.toString() };
    if (!m_tunnel.interfaceName.isEmpty()) {
        UINT64 luid = 0;
        if (tunnel(m_tunnel, luid, error)) {
            next.interfaceName = m_tunnel.interfaceName;
            next.ipv4 = m_tunnel.ipv4;
            next.ipv6 = m_tunnel.ipv6;
        } else
            error.clear();
    }
    if (!apply(next, false, error) || gateway.isEmpty() || !next.addresses.isEmpty())
        return error.isEmpty();
    next.addresses = lookupGatewayUnlocked(next.host, error);
    if (!error.isEmpty() || !m_requested)
        return error.isEmpty();
    return next.addresses.isEmpty() || apply(next, false, error);
}
bool NetworkGuard::prepareConnection(const QUrl& gateway, QString& error)
{
    {
        QMutexLocker lock(&m_mutex);
        m_tunnel = {};
        if (!m_armed) {
            error.clear();
            return true;
        }
    }
    return arm(gateway, error);
}
QStringList NetworkGuard::lookupGatewayUnlocked(const QString& host, QString& error)
{
    const auto servers = m_dnsServers.isEmpty() ? WindowsDnsBootstrap::systemServers() : m_dnsServers;
    if (servers.isEmpty()) {
        error = "No system DNS servers are available";
        return {};
    }
    if (!m_windows->replace(m_policy, servers, error))
        return {};
    QString lookupError;
    QStringList addresses;
    try {
        addresses = m_dnsLookup(host, servers, lookupError);
    } catch (...) {
        lookupError = "DNS lookup failed";
    }
    if (!m_windows->replace(m_policy, {}, error))
        return {};
    error = lookupError;
    return addresses;
}
bool NetworkGuard::attachTunnel(const QString& name, const QString& ipv4, const QString& ipv6, QString& error)
{
    QMutexLocker lock(&m_mutex);
    error.clear();
    m_tunnel.interfaceName = name;
    m_tunnel.ipv4 = ipv4.section('/', 0, 0);
    m_tunnel.ipv6 = ipv6.section('/', 0, 0);
    UINT64 luid = 0;
    if (!tunnel(m_tunnel, luid, error))
        return false;
    if (!m_armed || !m_requested)
        return true;
    auto next = m_policy;
    next.interfaceName = name;
    next.ipv4 = m_tunnel.ipv4;
    next.ipv6 = m_tunnel.ipv6;
    return apply(next, false, error);
}
bool NetworkGuard::allowDtlsPort(quint16 port, QString& error)
{
    QMutexLocker lock(&m_mutex);
    error.clear();
    if (!port) {
        error = "Invalid DTLS port";
        return false;
    }
    if (!m_armed || !m_requested)
        return true;
    auto next = m_policy;
    if (!next.udpPorts.contains(port))
        next.udpPorts << port;
    for (auto& endpoint : next.sessionEndpoints)
        if (!endpoint.udpPorts.contains(port))
            endpoint.udpPorts << port;
    return apply(next, false, error);
}
bool NetworkGuard::lockTunnel(QString& error)
{
    QMutexLocker lock(&m_mutex);
    error.clear();
    m_tunnel = {};
    if (!m_armed)
        return true;
    auto next = m_policy;
    next.interfaceName.clear();
    next.ipv4.clear();
    next.ipv6.clear();
    next.sessionEndpoints.clear();
    return apply(next, false, error);
}
bool NetworkGuard::disable(QString& error)
{
    m_requested = false;
    QMutexLocker lock(&m_mutex);
    error.clear();
    return disableUnlocked(error);
}
bool NetworkGuard::disableUnlocked(QString& error)
{
    m_requested = false;
    if (!save(error) || !m_windows->remove(error))
        return false;
    m_armed = false;
    m_hasTunnel = false;
    m_policy = {};
    return verifyUnlocked(error);
}
bool NetworkGuard::verifyUnlocked(QString& error)
{
    error.clear();
    if (!m_windows->open(error))
        return false;
    int blocks = 0;
    const auto filters = owned(m_windows->persistent, error, &blocks);
    if (!error.isEmpty())
        return false;
    if (!m_armed) {
        if (!filters.isEmpty()) {
            error = "OpenConnect filtering is not confirmed OFF";
            return false;
        }
        return true;
    }
    if (blocks != 4 || filters.size() != 21 + m_windows->permits.size()) {
        error = "The complete IPv4/IPv6 policy could not be verified";
        return false;
    }
    if (m_hasTunnel) {
        UINT64 luid = 0;
        if (!tunnel(m_policy, luid, error))
            return false;
    }
    return true;
}
bool NetworkGuard::verify(QString& error)
{
    QMutexLocker lock(&m_mutex);
    return verifyUnlocked(error);
}
bool NetworkGuard::verifySavedState(QString& error) { return restoreBootProtection(error) && verify(error); }
bool NetworkGuard::checkGatewayRoute(QString& error) const
{
    error.clear();
    return true;
}
QJsonObject NetworkGuard::diagnostics()
{
    QMutexLocker lock(&m_mutex);
    QString error;
    int blocks = 0;
    QList<quint64> filters;
    if (m_windows->open(error))
        filters = owned(m_windows->persistent, error, &blocks);
    return { { "backend", "Windows Filtering Platform" }, { "ownedFilterCount", filters.size() },
        { "persistentBlockLayers", blocks }, { "dynamicPermitCount", m_windows->permits.size() }, { "error", error } };
}
int NetworkGuard::resolvePinned(const QString& host, const QStringList& addresses, const char* node, const char* service,
    const struct addrinfo* hints, struct addrinfo** result)
{
    if (!result || !node || !service)
        return EAI_FAIL;
    *result = nullptr;
    QStringList chosen;
    if (QString::fromUtf8(node).compare(host, Qt::CaseInsensitive) == 0)
        chosen = addresses;
    else
        for (const auto& ip : addresses)
            if (QHostAddress(QString::fromUtf8(node)) == QHostAddress(ip))
                chosen << ip;
    struct addrinfo defaults{};
    if (hints)
        defaults = *hints;
    defaults.ai_flags |= AI_NUMERICHOST | AI_NUMERICSERV;
    struct addrinfo** tail = result;
    for (const auto& ip : chosen) {
        struct addrinfo* entry = nullptr;
        const auto bytes = ip.toLatin1();
        if (::getaddrinfo(bytes.constData(), service, &defaults, &entry))
            continue;
        *tail = entry;
        while (*tail)
            tail = &(*tail)->ai_next;
    }
    return *result ? 0 : EAI_NONAME;
}
int NetworkGuard::resolve(const char* node, const char* service, const struct addrinfo* hints, struct addrinfo** result)
{
    QMutexLocker lock(&m_mutex);
    if (!m_armed && !m_requested) {
        lock.unlock();
        return ::getaddrinfo(node, service, hints, result);
    }
    if (result)
        *result = nullptr;
    if (!m_armed || !node || !service)
        return EAI_FAIL;
    const auto host = QString::fromUtf8(node);
    bool valid = false;
    auto port = QString::fromLatin1(service).toUShort(&valid);
    if (!valid || !port)
        return EAI_SERVICE;
    if (port == m_policy.port && (host.compare(m_policy.host, Qt::CaseInsensitive) == 0 || m_policy.addresses.contains(host)))
        return resolvePinned(m_policy.host, m_policy.addresses, node, service, hints, result);
    for (const auto& endpoint : m_policy.sessionEndpoints)
        if (port == endpoint.port && (host.compare(endpoint.host, Qt::CaseInsensitive) == 0 || endpoint.addresses.contains(host)))
            return resolvePinned(endpoint.host, endpoint.addresses, node, service, hints, result);
    if (!m_requested || m_policy.sessionEndpoints.size() >= 16 || host.size() > 253)
        return EAI_NONAME;
    QString error;
    Endpoint endpoint;
    endpoint.host = host;
    endpoint.port = port;
    endpoint.udpPorts << port;
    if (literal(host))
        endpoint.addresses << host;
    else
        endpoint.addresses = lookupGatewayUnlocked(host, error);
    if (!error.isEmpty() || endpoint.addresses.isEmpty() || !m_requested)
        return EAI_NONAME;
    auto next = m_policy;
    next.sessionEndpoints << endpoint;
    if (!apply(next, false, error))
        return EAI_FAIL;
    return resolvePinned(host, endpoint.addresses, node, service, hints, result);
}
