// SPDX-License-Identifier: LGPL-2.1-or-later
// libFuzzer target: arbitrary CTAP2 requests (command byte + CBOR) against the
// authenticator with one stored credential and an auto-approving user.
#include "common/fakes.h"

#include <QCoreApplication>

using namespace kpasskey;

namespace {
struct Env {
    MemoryStore store;
    test::FakePrompter prompter;
    test::FakeVerifier verifier;
    Authenticator auth{&store, &prompter, &verifier, {}};
    Env()
    {
        const QByteArray cdh(32, 'c');
        test::run(auth, ctap::MakeCredential, test::makeCredentialParams(QStringLiteral("example.com"), "user", cdh));
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
    if (size == 0) {
        return 0;
    }
    // first byte steers the fake user, the rest is the CTAP request
    env->prompter.approve = data[0] & 1;
    env->prompter.select = (data[0] >> 1) & 3;
    env->verifier.result = data[0] & 8;
    const QByteArray request(reinterpret_cast<const char *>(data + 1), qsizetype(size - 1));
    bool done = false;
    env->auth.process(request, [&](const QByteArray &r) {
        done = true;
        if (r.isEmpty()) {
            __builtin_trap(); // every answer carries at least a status byte
        }
    });
    if (!done) {
        __builtin_trap(); // synchronous fakes: every request must complete
    }
    return 0;
}
