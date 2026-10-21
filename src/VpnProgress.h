// SPDX-License-Identifier: GPL-2.0-or-later
#pragma once
#include <QRegularExpression>
#include <QString>

inline QString safeVpnProgress(const QString& message)
{
    QString safe = message.left(2048);
    if (QRegularExpression("(?i)\\b(password|passwd|cookie|set-cookie|authorization|bearer|token|samlresponse)(?:\\s*[:=]|\\s+)")
            .match(safe).hasMatch()) return {};
    safe.replace(QRegularExpression("(https?://[^\\s?#]+)[?#][^\\s]*"), "\\1?[redacted]");
    return safe;
}
