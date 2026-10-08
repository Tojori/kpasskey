// SPDX-License-Identifier: LGPL-2.1-or-later
// Test-only harness: exposes the real CTAPHID + CTAP2 stack over stdin/stdout
// (raw 64 byte reports) with an in-memory store and auto-approving user
// interaction, so that independent FIDO client implementations (python-fido2,
// libfido2) can be run against it without /dev/uhid or root.
// NEVER install this binary.
#include "common/fakes.h"
#include "hid/ctaphid.h"

#include <QCoreApplication>
#include <QSocketNotifier>

#include <unistd.h>

using namespace kpasskey;

int main(int argc, char **argv)
{
    QCoreApplication app(argc, argv);
    const bool deny = app.arguments().contains(QStringLiteral("--deny-uv"));

    MemoryStore store;
    test::FakePrompter prompter;
    test::FakeVerifier verifier;
    verifier.result = !deny;
    Authenticator auth(&store, &prompter, &verifier, {});
    CtapHid hid(&auth);

    QObject::connect(&hid, &CtapHid::reportReady, [](const QByteArray &report) {
        const char *p = report.constData();
        qsizetype left = report.size();
        while (left > 0) {
            const ssize_t n = ::write(STDOUT_FILENO, p, size_t(left));
            if (n <= 0) {
                QCoreApplication::exit(1);
                return;
            }
            p += n;
            left -= n;
        }
    });

    QByteArray buffer;
    QSocketNotifier notifier(STDIN_FILENO, QSocketNotifier::Read);
    QObject::connect(&notifier, &QSocketNotifier::activated, [&] {
        char chunk[256];
        const ssize_t n = ::read(STDIN_FILENO, chunk, sizeof(chunk));
        if (n <= 0) {
            QCoreApplication::quit();
            return;
        }
        buffer.append(chunk, n);
        while (buffer.size() >= CtapHid::ReportSize) {
            hid.handleReport(buffer.left(CtapHid::ReportSize));
            buffer.remove(0, CtapHid::ReportSize);
        }
    });
    return app.exec();
}
