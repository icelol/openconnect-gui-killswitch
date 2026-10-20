// SPDX-License-Identifier: GPL-2.0-or-later
#include "MacPreferencesMigration.h"
#ifdef Q_OS_MACOS
#include <CoreFoundation/CoreFoundation.h>
#include <QByteArray>
#include <QRandomGenerator>
#include <fcntl.h>
#include <pwd.h>
#include <sys/stat.h>
#include <unistd.h>
#include <algorithm>
#include <array>

namespace {
struct Fd {
    int value;
    ~Fd() { if (value >= 0) ::close(value); }
};
constexpr char name[] = "com.openconnect-gui-team.OpenConnect-GUI-KillSwitch.plist";
bool safeDirectory(int fd, uint uid)
{
    struct stat info{};
    return fd >= 0 && !::fstat(fd, &info) && S_ISDIR(info.st_mode)
        && info.st_uid == uid && !(info.st_mode & 0022);
}
struct Preferences {
    CFDictionaryRef values = nullptr;
    timespec modified{};
    ~Preferences() { if (values) CFRelease(values); }
};
bool readPreferences(int directory, uint uid, Preferences& result, QString& error)
{
    if (directory < 0) return true; // Legacy root preferences are optional.
    Fd fd{::openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)};
    if (fd.value < 0 && errno == ENOENT) return true;
    struct stat info{};
    if (fd.value < 0 || ::fstat(fd.value, &info) || !S_ISREG(info.st_mode)
        || info.st_uid != uid || info.st_size < 0 || info.st_size > 8 * 1024 * 1024) {
        error = "Unsafe or oversized legacy preferences file"; return false;
    }
    QByteArray bytes(info.st_size, '\0');
    qint64 offset = 0;
    while (offset < bytes.size()) {
        const auto count = ::read(fd.value, bytes.data() + offset, bytes.size() - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { error = "Cannot read legacy preferences"; return false; }
        offset += count;
    }
    CFDataRef data = CFDataCreate(kCFAllocatorDefault,
        reinterpret_cast<const UInt8*>(bytes.constData()), bytes.size());
    CFPropertyListRef plist = CFPropertyListCreateWithData(kCFAllocatorDefault, data,
        kCFPropertyListImmutable, nullptr, nullptr);
    CFRelease(data);
    if (!plist || CFGetTypeID(plist) != CFDictionaryGetTypeID()) {
        if (plist) CFRelease(plist);
        error = "Invalid legacy preferences plist"; return false;
    }
    result.values = static_cast<CFDictionaryRef>(plist);
    result.modified = info.st_mtimespec;
    return true;
}
}
#endif

bool migrateLegacyPreferences(uint uid, QString& error)
{
#ifdef Q_OS_MACOS
    if (::geteuid() != 0 || uid < 500) { error = "Preferences migration requires root and a desktop UID"; return false; }
    const auto account = ::getpwuid(uid);
    if (!account) { error = "Unknown desktop UID"; return false; }
    Fd home{::open(account->pw_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)};
    Fd library{home.value < 0 ? -1 : ::openat(home.value, "Library", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)};
    if (!safeDirectory(home.value, uid) || !safeDirectory(library.value, uid)) {
        error = "Unsafe desktop preferences parent"; return false;
    }
    if (::mkdirat(library.value, "Preferences", 0755) == 0)
        ::fchownat(library.value, "Preferences", uid, -1, AT_SYMLINK_NOFOLLOW);
    Fd directory{::openat(library.value, "Preferences", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)};
    if (!safeDirectory(directory.value, uid)) { error = "Unsafe desktop preferences directory"; return false; }
    Fd legacy{::open("/var/root/Library/Preferences", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)};
    if (legacy.value >= 0 && !safeDirectory(legacy.value, 0)) { error = "Unsafe root preferences directory"; return false; }
    Preferences user, root;
    if (!readPreferences(directory.value, uid, user, error) || !readPreferences(legacy.value, 0, root, error)) return false;
    if (!root.values) return true; // No root GUI existed; leave the user's plist untouched.
    CFMutableDictionaryRef merged = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    std::array<Preferences*, 2> sources{&user, &root};
    std::sort(sources.begin(), sources.end(), [](const auto a, const auto b) {
        return a->modified.tv_sec < b->modified.tv_sec
            || (a->modified.tv_sec == b->modified.tv_sec && a->modified.tv_nsec < b->modified.tv_nsec);
    });
    for (const auto source : sources) if (source->values)
        CFDictionaryApplyFunction(source->values, [](const void* key, const void* value, void* context) {
            CFDictionarySetValue(static_cast<CFMutableDictionaryRef>(context), key, value);
        }, merged);
    CFDataRef data = CFPropertyListCreateData(kCFAllocatorDefault, merged, kCFPropertyListBinaryFormat_v1_0, 0, nullptr);
    CFRelease(merged);
    if (!data) { error = "Cannot encode migrated preferences"; return false; }
    const QByteArray temporary = ".openconnect-migrate-" + QByteArray::number(QRandomGenerator::system()->generate64(), 16);
    Fd output{::openat(directory.value, temporary.constData(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600)};
    bool ok = output.value >= 0 && ::fchown(output.value, uid, -1) == 0;
    const auto length = CFDataGetLength(data);
    CFIndex offset = 0;
    while (ok && offset < length) {
        const auto count = ::write(output.value, CFDataGetBytePtr(data) + offset, length - offset);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) ok = false; else offset += count;
    }
    CFRelease(data);
    ok = ok && ::fsync(output.value) == 0
        && ::renameat(directory.value, temporary.constData(), directory.value, name) == 0;
    if (!ok) { ::unlinkat(directory.value, temporary.constData(), 0); error = "Cannot save migrated preferences"; }
    return ok;
#else
    Q_UNUSED(uid); error = "Preferences migration requires macOS"; return false;
#endif
}
