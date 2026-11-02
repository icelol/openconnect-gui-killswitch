// SPDX-License-Identifier: GPL-2.0-or-later
#include "WindowsDnsBootstrap.h"
#include <QHostAddress>
#include <QNetworkDatagram>
#include <QTcpServer>
#include <QTcpSocket>
#include <QUdpSocket>
#include <QtEndian>
#include <QtTest>
#include <chrono>
#include <future>

namespace {
void word(QByteArray& bytes, quint16 value)
{
    char data[2];
    qToBigEndian(value, reinterpret_cast<uchar*>(data));
    bytes.append(data, 2);
}
QByteArray name(const QByteArray& value)
{
    QByteArray bytes;
    for (const auto& label : value.split('.')) {
        bytes += char(label.size());
        bytes += label;
    }
    return bytes + '\0';
}
QByteArray packet(quint16 type = 1, quint16 flags = 0x8180, quint16 answers = 1)
{
    QByteArray bytes;
    for (auto value : { quint16(0x1234), flags, quint16(1), answers, quint16(0), quint16(0) })
        word(bytes, value);
    bytes += name("vpn.example.net");
    word(bytes, type);
    word(bytes, 1);
    return bytes;
}
void record(QByteArray& bytes, const QByteArray& owner, quint16 type, const QByteArray& data)
{
    bytes += owner;
    word(bytes, type);
    word(bytes, 1);
    bytes += QByteArray(4, '\0');
    word(bytes, quint16(data.size()));
    bytes += data;
}
QStringList parse(const QByteArray& bytes, quint16 type = 1)
{
    bool truncated = false;
    return WindowsDnsBootstrap::response(bytes, 0x1234, "VPN.Example.Net", type, truncated);
}
}

class WindowsDnsBootstrapTest : public QObject {
    Q_OBJECT
private slots:
    void compressedIpv4()
    {
        auto bytes = packet();
        record(bytes, QByteArray::fromHex("c00c"), 1, QByteArray::fromHex("c0000201"));
        QCOMPARE(parse(bytes), QStringList{ "192.0.2.1" });
    }
    void ipv6()
    {
        auto bytes = packet(28);
        record(bytes, QByteArray::fromHex("c00c"), 28, QByteArray::fromHex("20010db8000000000000000000000001"));
        QCOMPARE(parse(bytes, 28), QStringList{ "2001:db8::1" });
        QVERIFY(parse(bytes).isEmpty());
    }
    void bindsIdQuestionAndClass()
    {
        auto bytes = packet();
        record(bytes, QByteArray::fromHex("c00c"), 1, QByteArray::fromHex("c0000201"));
        auto wrongId = bytes;
        wrongId[0] = 0;
        QVERIFY(parse(wrongId).isEmpty());
        auto wrongName = bytes;
        wrongName[13] = 'x';
        QVERIFY(parse(wrongName).isEmpty());
        auto wrongClass = bytes;
        wrongClass[12 + name("vpn.example.net").size() + 3] = 3;
        QVERIFY(parse(wrongClass).isEmpty());
        auto notResponse = bytes;
        notResponse[2] = 1;
        QVERIFY(parse(notResponse).isEmpty());
        auto serverError = bytes;
        serverError[3] = char(0x82);
        QVERIFY(parse(serverError).isEmpty());
    }
    void followsCnameButRejectsUnrelatedAnswer()
    {
        auto bytes = packet(1, 0x8180, 3);
        record(bytes, name("irrelevant.example.net"), 1, QByteArray::fromHex("c6336409"));
        record(bytes, QByteArray::fromHex("c00c"), 5, name("edge.example.net"));
        record(bytes, name("edge.example.net"), 1, QByteArray::fromHex("c0000202"));
        QCOMPARE(parse(bytes), QStringList{ "192.0.2.2" });
    }
    void rejectsCompressionLoopAndTruncation()
    {
        auto bytes = packet();
        const auto at = bytes.size();
        QByteArray loop;
        word(loop, quint16(0xc000 | at));
        record(bytes, loop, 1, QByteArray::fromHex("c0000201"));
        QVERIFY(parse(bytes).isEmpty());
        auto valid = packet();
        record(valid, QByteArray::fromHex("c00c"), 1, QByteArray::fromHex("c0000201"));
        for (int i = 0; i < valid.size(); ++i)
            QVERIFY(parse(valid.left(i)).isEmpty());
        QVERIFY(parse(QByteArray(8193, '\0')).isEmpty());
    }
    void refusesLoopbackMulticastAndBadCnameLength()
    {
        for (const auto& address : { "7f000001", "e0000001" }) {
            auto bytes = packet();
            record(bytes, QByteArray::fromHex("c00c"), 1, QByteArray::fromHex(address));
            QVERIFY(parse(bytes).isEmpty());
        }
        auto bytes = packet(1, 0x8180, 2);
        record(bytes, QByteArray::fromHex("c00c"), 5, name("edge.example.net") + 'x');
        record(bytes, name("edge.example.net"), 1, QByteArray::fromHex("c0000202"));
        QVERIFY(parse(bytes).isEmpty());
    }
    void validatesBeforeRequestingTcpFallback()
    {
        bool truncated = false;
        const auto bytes = packet(1, 0x8380, 0);
        QVERIFY(WindowsDnsBootstrap::response(bytes, 0x1234, "vpn.example.net", 1, truncated).isEmpty());
        QVERIFY(truncated);
        truncated = true;
        WindowsDnsBootstrap::response(bytes, 0x9999, "vpn.example.net", 1, truncated);
        QVERIFY(!truncated);
    }
    void repeatedTruncationCannotExtendLookupBudget()
    {
        // Loopback only, ephemeral port, no system resolver/firewall changes.
        // A configured resolver can replay valid TC packets and hold TCP open.
        // All waits and queued datagrams must share one total lookup deadline.
        QTcpServer tcpServer;
        QVERIFY(tcpServer.listen(QHostAddress::LocalHost, 0));
        QUdpSocket dns;
        const auto port = tcpServer.serverPort();
        QVERIFY(dns.bind(QHostAddress::LocalHost, port));
        int fallbackConnections = 0;
        connect(&tcpServer, &QTcpServer::newConnection, this, [&] {
            while (auto socket = tcpServer.nextPendingConnection()) {
                socket->setParent(&tcpServer); // Deliberately never respond.
                ++fallbackConnections;
            }
        });
        connect(&dns, &QUdpSocket::readyRead, this, [&] {
            while (dns.hasPendingDatagrams()) {
                const auto request = dns.receiveDatagram();
                auto response = request.data();
                if (response.size() < 12)
                    continue;
                response[2] = char(0x83); // Valid response, recursive, TC set.
                response[3] = char(0x80);
                for (int replay = 0; replay < 16; ++replay)
                    dns.writeDatagram(response, request.senderAddress(), request.senderPort());
            }
        });
        QElapsedTimer elapsed;
        elapsed.start();
        auto lookup = std::async(std::launch::async, [&] {
            QString error;
            const auto addresses = WindowsDnsBootstrap::lookupWithDeadline(
                "vpn.example.net", { "127.0.0.1" }, error, port, 200);
            return qMakePair(addresses, error);
        });
        QTRY_VERIFY_WITH_TIMEOUT(lookup.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready, 1200);
        const auto result = lookup.get();
        QVERIFY(result.first.isEmpty());
        QVERIFY(!result.second.isEmpty());
        QVERIFY(elapsed.elapsed() < 1000);
        QVERIFY(fallbackConnections > 0);
        QVERIFY(fallbackConnections <= 2); // At most one fallback per A/AAAA.
    }
    void validTcpFallbackStillResolves()
    {
        QTcpServer tcpServer;
        QVERIFY(tcpServer.listen(QHostAddress::LocalHost, 0));
        QUdpSocket dns;
        const auto port = tcpServer.serverPort();
        QVERIFY(dns.bind(QHostAddress::LocalHost, port));
        connect(&dns, &QUdpSocket::readyRead, this, [&] {
            while (dns.hasPendingDatagrams()) {
                const auto request = dns.receiveDatagram();
                auto response = request.data();
                if (response.size() < 12)
                    continue;
                response[2] = char(0x83);
                response[3] = char(0x80);
                dns.writeDatagram(response, request.senderAddress(), request.senderPort());
            }
        });
        connect(&tcpServer, &QTcpServer::newConnection, this, [&] {
            while (auto socket = tcpServer.nextPendingConnection()) {
                socket->setParent(&tcpServer);
                connect(socket, &QTcpSocket::readyRead, this, [socket] {
                    auto request = socket->property("request").toByteArray() + socket->readAll();
                    socket->setProperty("request", request);
                    if (request.size() < 2)
                        return;
                    const auto size = qFromBigEndian<quint16>(reinterpret_cast<const uchar*>(request.constData()));
                    if (request.size() < size + 2 || size < 16)
                        return;
                    auto answer = request.mid(2, size);
                    const auto type = qFromBigEndian<quint16>(reinterpret_cast<const uchar*>(answer.constData() + answer.size() - 4));
                    answer[2] = char(0x81);
                    answer[3] = char(0x80);
                    answer[7] = 1;
                    record(answer, QByteArray::fromHex("c00c"), type, QByteArray::fromHex(type == 1
                        ? "c0000201" : "20010db8000000000000000000000001"));
                    QByteArray frame;
                    word(frame, quint16(answer.size()));
                    socket->write(frame + answer);
                });
            }
        });
        auto lookup = std::async(std::launch::async, [&] {
            QString error;
            return WindowsDnsBootstrap::lookupWithDeadline("vpn.example.net", { "127.0.0.1" }, error, port, 2000);
        });
        QTRY_VERIFY_WITH_TIMEOUT(lookup.wait_for(std::chrono::milliseconds(0)) == std::future_status::ready, 3000);
        const auto addresses = lookup.get();
        QVERIFY(addresses.contains("192.0.2.1"));
        QVERIFY(addresses.contains("2001:db8::1"));
        QCOMPARE(addresses.size(), 2);
    }
};
QTEST_GUILESS_MAIN(WindowsDnsBootstrapTest)
#include "WindowsDnsBootstrapTest.moc"
