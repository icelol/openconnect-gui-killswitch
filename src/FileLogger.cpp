#include "FileLogger.h"

#include <QApplication>
#include <QDateTime>
#include <QDir>
#include <QDebug>

#include <spdlog/spdlog.h>

namespace spd = spdlog;

FileLogger::FileLogger(QObject* parent, const QString& logPath, const size_t logSize, const size_t logCount)
    : QObject(parent)
    , m_logPath{ logPath.isEmpty()
#ifdef Q_OS_MACOS
        ? QDir(QDir::homePath()).filePath("Library/Logs/OpenConnect-GUI-KillSwitch")
#else
        ? QDir(QStandardPaths::writableLocation(QStandardPaths::AppLocalDataLocation)).filePath("logs")
#endif
        : logPath }
    , m_logSize{ logSize }
    , m_logCount{ logCount }
{

    QDir dir;
    if (!dir.mkpath(m_logPath)) {
        qWarning() << "File logging disabled: cannot create log directory" << m_logPath;
        return;
    }
    try {
        m_logger = spd::rotating_logger_mt("openconnect-logger-" + std::to_string(quintptr(this)),
#ifdef Q_OS_WIN
            QString("%1/%2.log").arg(m_logPath).arg(qApp->applicationName()).toStdWString(),
#else
            QString("%1/%2.log").arg(m_logPath).arg(qApp->applicationName()).toStdString(),
#endif
            logSize,
            logCount);
        spd::set_pattern("%v");
    } catch (const spd::spdlog_ex& ex) {
        // Diagnostics must never prevent the normal-user control panel from
        // opening, including when a v5 root GUI left root-owned files behind.
        qWarning("File logging disabled: %s", ex.what());
        return;
    }

    connect(&Logger::instance(), &Logger::newLogMessage, this, &FileLogger::addLogMessage);
}

FileLogger::~FileLogger()
{
    Logger::instance().addMessage(QString("...logging finished"));
    if (m_logger) spd::drop(m_logger->name());
}

void FileLogger::addLogMessage(const Logger::Message& message)
{
    if (!m_logger) return;
    QDateTime dt;
    dt.setMSecsSinceEpoch(message.timeStamp);

    m_logger->log(spdlog::level::off,
        "{:<24} | {:>4} | {}",
        dt.toString("yyyy-MM-dd hh:mm:ss.ms").toStdString(),
        QString::number((long long)message.threadId, 16).toStdString(),
        message.text.toStdString());
    m_logger->flush();
}
