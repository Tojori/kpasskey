// SPDX-License-Identifier: LGPL-2.1-or-later
// Management interface on the session bus (for a future KCM / CLI). It is NOT a
// WebAuthn API for browsers: browsers talk CTAPHID to the virtual device.
// See docs/dbus-api.md.
#pragma once

#include "core/credential_store.h"
#include "core/user_interaction.h"

#include <QDBusArgument>
#include <QDBusContext>
#include <QDBusMessage>
#include <QObject>
#include <QVariantMap>

namespace kpasskey {

class Authenticator;

// D-Bus struct (sssxx)
struct CredentialInfo {
    QString credentialId;
    QString rpId;
    QString userName;
    qint64 created = 0;
    qint64 lastUsed = 0;
};
QDBusArgument &operator<<(QDBusArgument &arg, const CredentialInfo &c);
const QDBusArgument &operator>>(const QDBusArgument &arg, CredentialInfo &c);

class ManagerDBus : public QObject, protected QDBusContext
{
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "org.kde.kpasskey.Manager1")
public:
    static constexpr auto ServiceName = "org.kde.kpasskey";
    static constexpr auto ObjectPath = "/org/kde/kpasskey";

    ManagerDBus(CredentialStore *store, UserVerifier *verifier, Authenticator *authenticator, QObject *parent = nullptr);

public Q_SLOTS:
    // a(sssxx): credential_id (b64url), rp_id, user_name, created, last_used
    Q_SCRIPTABLE QList<CredentialInfo> ListCredentials(const QString &rpId);
    // Requires fresh user verification (polkit) before deleting.
    Q_SCRIPTABLE void DeleteCredential(const QString &credentialId);
    Q_SCRIPTABLE QVariantMap GetStatus();
    // Encrypted CXF backup. Only *triggers* the operation: user verification,
    // file choice and passphrase are handled by kpasskeyd's own dialogs, so no
    // key material or passphrase ever crosses D-Bus. Returns a summary.
    Q_SCRIPTABLE QVariantMap ExportCredentials();
    Q_SCRIPTABLE QVariantMap ImportCredentials();

Q_SIGNALS:
    Q_SCRIPTABLE void CredentialsChanged();

private:
    CredentialStore *m_store;
    UserVerifier *m_verifier;
    Authenticator *m_authenticator;
    bool m_backupRunning = false;
};

} // namespace kpasskey

Q_DECLARE_METATYPE(kpasskey::CredentialInfo)
