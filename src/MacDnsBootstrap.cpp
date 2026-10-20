// SPDX-License-Identifier: GPL-2.0-or-later
#include "MacDnsBootstrap.h"
#include <QDnsLookup>
#include <QEventLoop>
#include <QHostAddress>
#include <QProcess>
#include <QRegularExpression>
#include <QTimer>

QStringList MacDnsBootstrap::systemServers()
{
    QProcess process;
    process.start("/usr/sbin/scutil", {"--dns"});
    if (!process.waitForStarted(1000) || !process.waitForFinished(1500)) {
        process.kill(); process.waitForFinished(500); return {};
    }
    QStringList result;
    const QString output = QString::fromUtf8(process.readAllStandardOutput());
    auto matches = QRegularExpression("nameserver\\[[0-9]+\\]\\s*:\\s*([^\\s]+)").globalMatch(output);
    while (matches.hasNext() && result.size() < 8) {
        QHostAddress address(matches.next().captured(1));
        if (!address.isNull() && !address.isMulticast() && !result.contains(address.toString()))
            result << address.toString();
    }
    return result;
}

QStringList MacDnsBootstrap::lookup(const QString& host, const QStringList& servers, QString& error)
{
    if (servers.isEmpty()) { error = "No system DNS servers are available"; return {}; }
    QEventLoop loop;
    QTimer deadline;
    deadline.setSingleShot(true);
    QObject::connect(&deadline, &QTimer::timeout, &loop, &QEventLoop::quit);
    QList<QDnsLookup*> queries;
    QStringList result;
    int pending = 0;
    for (const auto& server : servers.mid(0, 4)) {
        for (const auto type : {QDnsLookup::A, QDnsLookup::AAAA}) {
            auto query = new QDnsLookup(type, host, QHostAddress(server), &loop);
            ++pending; queries << query;
            QObject::connect(query, &QDnsLookup::finished, &loop, [&, query] {
                if (query->error() == QDnsLookup::NoError)
                    for (const auto& record : query->hostAddressRecords())
                        if (!record.value().isNull() && !record.value().isMulticast()
                            && !record.value().isLoopback()) result << record.value().toString();
                if (--pending == 0) loop.quit();
            });
        }
    }
    deadline.start(3000);
    for (auto query : queries) query->lookup();
    loop.exec();
    for (auto query : queries) { query->disconnect(&loop); query->abort(); }
    result.removeDuplicates();
    if (result.isEmpty()) error = "VPN hostname could not be resolved using the system DNS servers";
    return result;
}
