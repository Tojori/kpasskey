// SPDX-License-Identifier: LGPL-2.1-or-later
// libFuzzer target: arbitrary sequences of 64 byte HID reports into CTAPHID,
// backed by the real authenticator.
#include "common/fakes.h"
#include "hid/ctaphid.h"

#include <QCoreApplication>

using namespace kpasskey;

namespace {
struct Env {
    MemoryStore store;
    test::FakePrompter prompter;
    test::FakeVerifier verifier;
    Authenticator auth{&store, &prompter, &verifier, {}};
    CtapHid hid{&auth};
    QByteArray lastReport;
    Env()
    {
        QObject::connect(&hid, &CtapHid::reportReady, [this](const QByteArray &r) {
            if (r.size() != CtapHid::ReportSize) {
                __builtin_trap();
            }
            lastReport = r;
        });
    }
    // Opens a channel via broadcast INIT and returns its CID bytes.
    QByteArray openChannel()
    {
        QByteArray init(4, '\xff');
        init += char(0x86);
        init += QByteArray("\x00\x08", 2);
        init += QByteArray("nonce123");
        init.resize(CtapHid::ReportSize, '\0');
        hid.handleReport(init);
        return lastReport.mid(15, 4); // payload offset 7 + nonce 8
    }
};
Env *env = nullptr;
} // namespace

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    static QCoreApplication app(*argc, *argv);
    env = new Env;
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // CIDs are random, so the fuzzer could never guess one. Every run opens a
    // channel first; reports whose CID field starts with 0x00 are rewritten to
    // that channel, all others are delivered verbatim (unknown/broadcast CIDs).
    const QByteArray cid = env->openChannel();
    for (size_t off = 0; off < size; off += CtapHid::ReportSize) {
        const size_t n = std::min<size_t>(CtapHid::ReportSize, size - off);
        QByteArray report(reinterpret_cast<const char *>(data + off), qsizetype(n));
        report.resize(CtapHid::ReportSize, '\0');
        if (report.at(0) == 0) {
            report.replace(0, 4, cid);
        }
        env->hid.handleReport(report);
    }
    return 0;
}
