// SPDX-License-Identifier: LGPL-2.1-or-later
// libFuzzer target: wallet entries are attacker-controllable (any same-user
// process can write KWallet), so record decoding must be robust.
#include "core/credential.h"

#include <QCoreApplication>

using namespace kpasskey;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    static QCoreApplication app(*argc, *argv);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const QByteArray in(reinterpret_cast<const char *>(data), qsizetype(size));
    const qsizetype sep = in.indexOf('\n');
    const QString key = QString::fromUtf8(sep < 0 ? QByteArray() : in.left(sep));
    const QString json = QString::fromUtf8(sep < 0 ? in : in.mid(sep + 1));
    record::DecodeError err;
    if (auto r = record::decode(key, json, &err)) {
        // a successfully decoded record must round-trip
        if (!record::decode(key, record::encode(*r))) {
            __builtin_trap();
        }
    }
    return 0;
}
