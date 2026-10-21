// SPDX-License-Identifier: GPL-2.0-or-later
#include "WindowsSystemService.h"
#include "NetworkGuard.h"
#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QSaveFile>
#include <QStandardPaths>
#include <QThread>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <ntsecapi.h>
#include <shlobj.h>
#include <atomic>
#include <cstdio>
#include <vector>

namespace {
constexpr wchar_t name[] = L"OpenConnectKillSwitch";
SERVICE_STATUS_HANDLE statusHandle = nullptr;
std::atomic<bool> stopRequested{false};
std::function<int()> serviceLoop;
int serviceResult = 1;
QString ownerSid;

struct Handle {
    HANDLE value = nullptr;
    ~Handle() { if (value && value != INVALID_HANDLE_VALUE) CloseHandle(value); }
};
QString tokenSid(HANDLE token)
{
    DWORD length = 0; GetTokenInformation(token, TokenUser, nullptr, 0, &length);
    std::vector<unsigned char> data(length);
    if (!length || !GetTokenInformation(token, TokenUser, data.data(), length, &length)) return {};
    LPWSTR text = nullptr;
    if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(data.data())->User.Sid, &text)) return {};
    const auto result = QString::fromWCharArray(text); LocalFree(text); return result;
}
QString currentSid()
{
    Handle token;
    return OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token.value) ? tokenSid(token.value) : QString();
}
QString desktopSid()
{
    DWORD pid = 0;
    if (const auto shell = GetShellWindow()) GetWindowThreadProcessId(shell, &pid);
    if (!pid) return currentSid();
    Handle process{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid)}, token;
    return process.value && OpenProcessToken(process.value, TOKEN_QUERY, &token.value) ? tokenSid(token.value) : QString();
}
void report(DWORD state, DWORD error = NO_ERROR)
{
    SERVICE_STATUS status{}; status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    status.dwCurrentState = state; status.dwWin32ExitCode = error;
    status.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN : 0;
    status.dwWaitHint = state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING ? 30000 : 0;
    if (statusHandle) SetServiceStatus(statusHandle, &status);
}
DWORD WINAPI control(DWORD command, DWORD, void*, void*)
{
    if (command == SERVICE_CONTROL_STOP || command == SERVICE_CONTROL_SHUTDOWN) {
        stopRequested = true; report(SERVICE_STOP_PENDING);
    }
    return NO_ERROR;
}
void WINAPI serviceMain(DWORD, LPWSTR*)
{
    statusHandle = RegisterServiceCtrlHandlerExW(name, control, nullptr);
    if (!statusHandle) return;
    report(SERVICE_START_PENDING); report(SERVICE_RUNNING);
    serviceResult = serviceLoop();
    report(SERVICE_STOPPED, serviceResult ? ERROR_SERVICE_SPECIFIC_ERROR : NO_ERROR);
}
bool stopService(SC_HANDLE service)
{
    SERVICE_STATUS state{};
    ControlService(service, SERVICE_CONTROL_STOP, &state);
    for (int i = 0; i < 150; ++i) {
        if (!QueryServiceStatus(service, &state)) return false;
        if (state.dwCurrentState == SERVICE_STOPPED) return true;
        QThread::msleep(100);
    }
    return false;
}
}

QString WindowsSystemService::directory()
{
    wchar_t path[MAX_PATH]{};
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, SHGFP_TYPE_CURRENT, path))) return {};
    return QDir(QString::fromWCharArray(path)).filePath("OpenConnect-GUI-KillSwitch");
}

void WindowsSystemService::hardenLibrarySearch()
{
    SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    SetDllDirectoryW(L"");
}

bool WindowsSystemService::isSystem() { return currentSid() == "S-1-5-18"; }

bool WindowsSystemService::trustedFile(const QString& path)
{
    const auto native = QDir::toNativeSeparators(path).toStdWString();
    const auto attrs = GetFileAttributesW(native.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES || (attrs & FILE_ATTRIBUTE_REPARSE_POINT)) return false;
    PSID owner = nullptr; PACL acl = nullptr; PSECURITY_DESCRIPTOR descriptor = nullptr;
    const auto result = GetNamedSecurityInfoW(const_cast<wchar_t*>(native.c_str()), SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr, &acl, nullptr, &descriptor);
    if (result != ERROR_SUCCESS || !descriptor || !acl) { if (descriptor) LocalFree(descriptor); return false; }
    PSID system = nullptr, admins = nullptr;
    ConvertStringSidToSidW(L"S-1-5-18", &system); ConvertStringSidToSidW(L"S-1-5-32-544", &admins);
    bool safe = owner && system && admins && (EqualSid(owner, system) || EqualSid(owner, admins));
    for (DWORD i = 0; safe && i < acl->AceCount; ++i) {
        void* raw = nullptr;
        if (!GetAce(acl, i, &raw)) { safe = false; break; }
        const auto header = static_cast<ACE_HEADER*>(raw);
        if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) continue;
        const auto ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
        const auto sid = reinterpret_cast<PSID>(const_cast<DWORD*>(&ace->SidStart));
        const DWORD mutation = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES
            | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_ALL | GENERIC_WRITE;
        if ((ace->Mask & mutation) && !EqualSid(sid, system) && !EqualSid(sid, admins)) safe = false;
    }
    if (system) LocalFree(system); if (admins) LocalFree(admins); LocalFree(descriptor);
    return safe;
}

bool WindowsSystemService::protectDirectory(QString& error)
{
    const auto path = QDir::toNativeSeparators(directory()).toStdWString();
    if (path.empty()) { error = "Cannot locate ProgramData"; return false; }
    if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES && !trustedFile(QString::fromStdWString(path))) {
        error = "The service directory has unsafe ownership or permissions"; return false;
    }
    PSECURITY_DESCRIPTOR sd = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
            SDDL_REVISION_1, &sd, nullptr)) return false;
    SECURITY_ATTRIBUTES attributes{sizeof(attributes), sd, FALSE};
    const bool created = CreateDirectoryW(path.c_str(), &attributes) || GetLastError() == ERROR_ALREADY_EXISTS;
    LocalFree(sd);
    if (!created || !trustedFile(QString::fromStdWString(path))) {
        error = "Cannot create a protected service directory"; return false;
    }
    return true;
}

QString WindowsSystemService::allowedUser()
{
    if (!ownerSid.isEmpty()) return ownerSid;
    const auto path = QDir(directory()).filePath("service.json");
    if (!trustedFile(path)) return {};
    QFile file(path); if (!file.open(QIODevice::ReadOnly) || file.size() > 4096) return {};
    ownerSid = QJsonDocument::fromJson(file.readAll()).object().value("userSid").toString();
    return ownerSid;
}

bool WindowsSystemService::trustedClient(qintptr descriptor)
{
    const auto pipe = reinterpret_cast<HANDLE>(descriptor);
    const auto allowed = allowedUser();
    // Reading precedes impersonation: Windows impersonates the last message's
    // authenticated token, not a claimed process ID supplied by the client.
    if (!ImpersonateNamedPipeClient(pipe)) return false;
    Handle token;
    bool accepted = false;
    if (OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &token.value)) {
        const auto sid = tokenSid(token.value);
        PSID admins = nullptr; BOOL administrator = FALSE;
        if (ConvertStringSidToSidW(L"S-1-5-32-544", &admins)) {
            CheckTokenMembership(token.value, admins, &administrator); LocalFree(admins);
        }
        TOKEN_STATISTICS statistics{}; DWORD bytes = sizeof(statistics);
        if ((sid == allowed || sid == "S-1-5-18" || administrator)
            && GetTokenInformation(token.value, TokenStatistics, &statistics, bytes, &bytes)) {
            PSECURITY_LOGON_SESSION_DATA session = nullptr;
            if (LsaGetLogonSessionData(&statistics.AuthenticationId, &session) == 0 && session) {
                // Reject network/SMB and delegated-credential logons. Local
                // scheduled tasks of the designated account have the same
                // authority as that account's GUI, which intentionally can OFF.
                accepted = session->LogonType == Interactive || session->LogonType == RemoteInteractive
                    || session->LogonType == CachedInteractive || session->LogonType == Batch
                    || ((sid == "S-1-5-18" || administrator) && session->LogonType == Service);
                LsaFreeReturnBuffer(session);
            }
        }
    }
    if (!RevertToSelf()) TerminateProcess(GetCurrentProcess(), ERROR_ACCESS_DENIED);
    return accepted;
}

bool WindowsSystemService::trustedServer(qintptr descriptor)
{
    ULONG pid = 0;
    if (!GetNamedPipeServerProcessId(reinterpret_cast<HANDLE>(descriptor), &pid)) return false;
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) return false;
    SC_HANDLE service = OpenServiceW(manager, name, SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG);
    SERVICE_STATUS_PROCESS status{}; DWORD bytes = 0;
    bool matches = service && QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
        reinterpret_cast<BYTE*>(&status), sizeof(status), &bytes) && status.dwProcessId == pid;
    // SCM configuration and the pipe's kernel-reported PID are authoritative.
    // Ordinary users need not gain TOKEN_QUERY access to a SYSTEM process.
    DWORD size = 0;
    if (matches) {
        QueryServiceConfigW(service, nullptr, 0, &size);
        std::vector<unsigned char> config(size);
        auto settings = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(config.data());
        matches = size && QueryServiceConfigW(service, settings, size, &size)
            && _wcsicmp(settings->lpServiceStartName, L"LocalSystem") == 0;
    }
    if (service) CloseServiceHandle(service); CloseServiceHandle(manager);
    return matches;
}

bool WindowsSystemService::stopping() { return stopRequested; }
int WindowsSystemService::dispatch(const std::function<int()>& run)
{
    if (!isSystem()) return 1;
    // SCM has no terminal. Keep bounded, administrator-only startup diagnostics;
    // credentials and VPN forms are never written here.
    QString error;
    if (!protectDirectory(error)) return 1;
    const auto log = QDir(directory()).filePath("service.log");
    if (QFile::exists(log) && !trustedFile(log)) return 1;
    if (QFile(log).size() > 1024 * 1024) {
        const auto previous = log + ".previous";
        if (QFile::exists(previous) && !trustedFile(previous)) return 1;
        QFile::remove(previous);
        if (!QFile::rename(log, previous)) return 1;
    }
    if (!_wfreopen(QDir::toNativeSeparators(log).toStdWString().c_str(), L"a", stderr)) return 1;
    std::setvbuf(stderr, nullptr, _IONBF, 0);
    hardenLibrarySearch(); serviceLoop = run;
    SERVICE_TABLE_ENTRYW table[]{{const_cast<LPWSTR>(name), serviceMain}, {nullptr, nullptr}};
    if (!StartServiceCtrlDispatcherW(table)) return 1;
    return serviceResult;
}

int WindowsSystemService::stop()
{
    if (!IsUserAnAdmin()) return 1;
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) return 1;
    SC_HANDLE service = OpenServiceW(manager, name, SERVICE_STOP | SERVICE_QUERY_STATUS);
    const bool ok = service ? stopService(service) : GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST;
    if (service) CloseServiceHandle(service);
    CloseServiceHandle(manager);
    // Persistent filters and the user's saved ON/OFF intent are retained.
    return ok ? 0 : 1;
}

int WindowsSystemService::install()
{
    if (!IsUserAnAdmin()) return 1;
    wchar_t programFiles[MAX_PATH]{};
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_PROGRAM_FILES, nullptr, SHGFP_TYPE_CURRENT, programFiles))) return 1;
    const auto expected = QDir(QString::fromWCharArray(programFiles)).filePath("OpenConnect-GUI-KillSwitch");
    if (QDir::cleanPath(QCoreApplication::applicationDirPath()).compare(QDir::cleanPath(expected), Qt::CaseInsensitive)
        || !trustedFile(expected) || !trustedFile(QCoreApplication::applicationFilePath())) {
        std::fprintf(stderr, "Install the protected runtime in Program Files before registering the service\n"); return 1;
    }
    QString error;
    if (!protectDirectory(error)) { std::fprintf(stderr, "%s\n", qPrintable(error)); return 1; }
    const auto existing = allowedUser();
    const auto sid = existing.isEmpty() ? desktopSid() : existing;
    if (sid.isEmpty()) return 1;
    QSaveFile file(QDir(directory()).filePath("service.json"));
    const auto json = QJsonDocument(QJsonObject{{"schema", 1}, {"userSid", sid}}).toJson();
    if (!file.open(QIODevice::WriteOnly) || file.write(json) != json.size() || !file.commit()) return 1;
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE | SC_MANAGER_CONNECT);
    if (!manager) return 1;
    const auto command = (QString('"') + QDir::toNativeSeparators(QCoreApplication::applicationFilePath())
        + "\" --network-service").toStdWString();
    SC_HANDLE service = OpenServiceW(manager, name, SERVICE_ALL_ACCESS);
    if (service) {
        if (!stopService(service) || !ChangeServiceConfigW(service, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL, command.c_str(), nullptr, nullptr, L"BFE\0Tcpip\0", L"LocalSystem", nullptr, nullptr)) {
            CloseServiceHandle(service); CloseServiceHandle(manager); return 1;
        }
    } else service = CreateServiceW(manager, name, L"OpenConnect VPN and Kill Switch", SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, command.c_str(), nullptr, nullptr,
        L"BFE\0Tcpip\0", L"LocalSystem", nullptr);
    if (!service) { CloseServiceHandle(manager); return 1; }
    SC_ACTION actions[]{{SC_ACTION_RESTART, 1000}, {SC_ACTION_RESTART, 5000}, {SC_ACTION_RESTART, 15000}};
    SERVICE_FAILURE_ACTIONSW failure{86400, nullptr, nullptr, 3, actions};
    ChangeServiceConfig2W(service, SERVICE_CONFIG_FAILURE_ACTIONS, &failure);
    const bool started = StartServiceW(service, 0, nullptr) || GetLastError() == ERROR_SERVICE_ALREADY_RUNNING;
    CloseServiceHandle(service); CloseServiceHandle(manager);
    return started ? 0 : 1;
}

int WindowsSystemService::recover()
{
    if (!IsUserAnAdmin()) return 1;
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    SC_HANDLE service = manager ? OpenServiceW(manager, name, SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_START) : nullptr;
    SERVICE_STATUS state{};
    const bool restart = service && QueryServiceStatus(service, &state) && state.dwCurrentState != SERVICE_STOPPED;
    if (service && !stopService(service)) { CloseServiceHandle(service); CloseServiceHandle(manager); return 1; }
    NetworkGuard guard({}, QDir(directory()).filePath("state.json"));
    QString error;
    const bool ok = guard.disable(error) && guard.verify(error);
    if (service) { if (restart) StartServiceW(service, 0, nullptr); CloseServiceHandle(service); }
    if (manager) CloseServiceHandle(manager);
    return ok ? 0 : 1;
}

int WindowsSystemService::uninstall()
{
    if (!IsUserAnAdmin()) return 1;
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) return 1;
    SC_HANDLE service = OpenServiceW(manager, name, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    bool ok = true;
    if (service) {
        ok = stopService(service) && DeleteService(service);
        CloseServiceHandle(service);
    } else ok = GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST;
    CloseServiceHandle(manager);
    return ok && recover() == 0 ? 0 : 1;
}
