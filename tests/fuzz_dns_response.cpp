// SPDX-License-Identifier: GPL-2.0-or-later
// libFuzzer target: parser only, no DNS queries or firewall changes.
#include "WindowsDnsBootstrap.h"
#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size > 8192) return 0; // Same bound as the bootstrap UDP receiver.
    const QByteArray wire(reinterpret_cast<const char*>(data), qsizetype(size));
    for (const quint16 type : {quint16(1), quint16(28)}) {
        bool truncated = false;
        WindowsDnsBootstrap::response(wire, 0x1234, "vpn.example.net", type, truncated);
    }
    return 0;
}

// Bounded deterministic fallback for toolchains without the libFuzzer runtime.
// Still compile with ASan/UBSan; this is mutation testing, not coverage fuzzing.
#ifdef OCGUI_FUZZ_STANDALONE
#include <cstdio>
#include <random>
int main()
{
    const auto seed = QByteArray::fromHex(
        "1234818000010001000000000376706e076578616d706c65036e65740000010001"
        "c00c000100010000001e0004c0000208");
    std::mt19937 random(0x4f434755);
    for (unsigned test = 0; test < 150000; ++test) {
        auto packet = seed;
        if (test % 4 == 0) {
            packet.resize(random() % 1024);
            for (qsizetype i = 0; i < packet.size(); ++i) packet[i] = char(random());
        } else {
            for (unsigned edit = 0, edits = random() % 10; edit < edits; ++edit)
                packet[qsizetype(random() % unsigned(packet.size()))] = char(random());
            if (test % 4 == 1) packet.truncate(random() % unsigned(packet.size() + 1));
            if (test % 4 == 2) packet.append(QByteArray(random() % 200, char(random())));
        }
        LLVMFuzzerTestOneInput(reinterpret_cast<const uint8_t*>(packet.constData()), size_t(packet.size()));
    }
    std::puts("PASS: 150000 deterministic DNS mutations; no network or firewall operations");
    return 0;
}
#endif
