// SPDX-License-Identifier: LGPL-2.1-or-later
#include "polkit_verifier.h"

#include "core/logging.h"

#include <PolkitQt1/Authority>
#include <PolkitQt1/Subject>
#include <QCoreApplication>
#include <QDBusConnection>
#include <QDBusConnectionInterface>

namespace kpasskey {

using PolkitQt1::Authority;

PolkitVerifier::PolkitVerifier(QObject *parent)
    : QObject(parent)
{
    connect(Authority::instance(), &Authority::checkAuthorizationFinished, this, [this](Authority::Result result) {
        auto done = std::move(m_done);
        m_done = nullptr;
        qCInfo(KPASSKEY_LOG) << "polkit result" << int(result) << Authority::instance()->errorDetails();
        // A failed/cancelled check must not disable UV for the rest of the run.
        Authority::instance()->clearError();
        if (done) {
            // Only an explicit "Yes" counts. Errors, "No" and "Challenge" fail closed.
            done(result == Authority::Yes);
        }
    });
}

bool PolkitVerifier::isAvailable() const
{
    // polkitd must be reachable on the system bus; otherwise we must not
    // advertise "uv" in getInfo. (Transient errors of single checks do not
    // count; those fail the individual verification instead.)
    auto bus = QDBusConnection::systemBus();
    return bus.isConnected() && bus.interface()->isServiceRegistered(QStringLiteral("org.freedesktop.PolicyKit1"));
}

void PolkitVerifier::verify(const QString &rpId, std::function<void(bool)> done)
{
    if (m_done) {
        done(false);
        return;
    }
    m_done = std::move(done);
    Authority::instance()->clearError();
    // Subject: this process (unix-process, same as `pkcheck --process`). We only
    // ever ask about ourselves, so PID reuse is not a concern.
    // Not used, because they did not work on polkit 127 (2026-10-08):
    //  - unix-session subject: polkitd aborts on a failed assertion
    //  - system-bus-name subject (+ details): the request never got an answer
    PolkitQt1::UnixProcessSubject subject(QCoreApplication::applicationPid());
    qCInfo(KPASSKEY_LOG) << "polkit CheckAuthorization for pid" << QCoreApplication::applicationPid() << "rp" << rpId;
    Authority::instance()->checkAuthorization(QLatin1String(ActionId), subject, Authority::AllowUserInteraction);
}

void PolkitVerifier::cancel()
{
    if (m_done) {
        m_done = nullptr;
        Authority::instance()->checkAuthorizationCancel();
    }
}

} // namespace kpasskey
