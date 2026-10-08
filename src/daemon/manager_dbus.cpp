// SPDX-License-Identifier: LGPL-2.1-or-later
#include "manager_dbus.h"

#include "core/authenticator.h"
#include "core/logging.h"

#include <QDBusArgument>
#include <QDBusConnection>
#include <QDBusMetaType>

namespace kpasskey {

namespace {
const QString ErrNotFound = QStringLiteral("org.kde.kpasskey.Error.NotFound");
const QString ErrNotAuthorized = QStringLiteral("org.kde.kpasskey.Error.NotAuthorized");
const QString ErrWalletUnavailable = QStringLiteral("org.kde.kpasskey.Error.WalletUnavailable");
const QString ErrBusy = QStringLiteral("org.kde.kpasskey.Error.Busy");
} // namespace

QDBusArgument &operator<<(QDBusArgument &arg, const CredentialInfo &c)
{
    arg.beginStructure();
    arg << c.credentialId << c.rpId << c.userName << c.created << c.lastUsed;
    arg.endStructure();
    return arg;
}

const QDBusArgument &operator>>(const QDBusArgument &arg, CredentialInfo &c)
{
    arg.beginStructure();
    arg >> c.credentialId >> c.rpId >> c.userName >> c.created >> c.lastUsed;
    arg.endStructure();
    return arg;
}

ManagerDBus::ManagerDBus(CredentialStore *store, UserVerifier *verifier, Authenticator *authenticator, QObject *parent)
    : QObject(parent)
    , m_store(store)
    , m_verifier(verifier)
    , m_authenticator(authenticator)
{
    qDBusRegisterMetaType<CredentialInfo>();
    qDBusRegisterMetaType<QList<CredentialInfo>>();
}

QList<CredentialInfo> ManagerDBus::ListCredentials(const QString &rpId)
{
    const QDBusMessage msg = message();
    setDelayedReply(true);
    m_store->ensureReady([this, msg, rpId](bool ok) {
        if (!ok) {
            QDBusConnection::sessionBus().send(msg.createErrorReply(ErrWalletUnavailable, QStringLiteral("KWallet is not available")));
            return;
        }
        QList<CredentialInfo> list; // metadata only, never key material
        for (const CredentialMetadata &m : m_store->listAll()) {
            if (rpId.isEmpty() || m.rpId == rpId) {
                list.append({m.credentialIdB64, m.rpId, m.userName, m.created, m.lastUsed});
            }
        }
        QDBusMessage reply = msg.createReply();
        reply << QVariant::fromValue(list);
        QDBusConnection::sessionBus().send(reply);
    });
    return {};
}

void ManagerDBus::DeleteCredential(const QString &credentialId)
{
    const QDBusMessage msg = message();
    if (m_authenticator->isBusy()) {
        sendErrorReply(ErrBusy, QStringLiteral("A WebAuthn request is in progress"));
        return;
    }
    setDelayedReply(true);
    m_store->ensureReady([this, msg, credentialId](bool ok) {
        if (!ok) {
            QDBusConnection::sessionBus().send(msg.createErrorReply(ErrWalletUnavailable, QStringLiteral("KWallet is not available")));
            return;
        }
        // Deletion is destructive: require fresh user verification, like a
        // security key requires the PIN for credential management.
        m_verifier->verify(QStringLiteral("delete passkey"), [this, msg, credentialId](bool verified) {
            if (!verified) {
                QDBusConnection::sessionBus().send(msg.createErrorReply(ErrNotAuthorized, QStringLiteral("User verification failed")));
                return;
            }
            if (!m_store->remove(credentialId)) {
                QDBusConnection::sessionBus().send(msg.createErrorReply(ErrNotFound, QStringLiteral("No such credential")));
                return;
            }
            qCInfo(KPASSKEY_LOG) << "credential deleted via management API";
            Q_EMIT CredentialsChanged();
            QDBusConnection::sessionBus().send(msg.createReply());
        });
    });
}

QVariantMap ManagerDBus::GetStatus()
{
    return {
        {QStringLiteral("version"), QStringLiteral(KPASSKEY_VERSION)},
        {QStringLiteral("busy"), m_authenticator->isBusy()},
        {QStringLiteral("user_verification"), m_verifier->isAvailable()},
        {QStringLiteral("storage"), QStringLiteral("kwallet")},
    };
}

} // namespace kpasskey
