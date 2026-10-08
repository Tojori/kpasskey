// SPDX-License-Identifier: LGPL-2.1-or-later
#include "manager_dbus.h"

#include "core/authenticator.h"
#include "core/backup.h"
#include "core/cxf.h"
#include "ui/backup_dialogs.h"

#include <KLocalizedString>
#include <QFile>
#include <QSaveFile>
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
const QString ErrCancelled = QStringLiteral("org.kde.kpasskey.Error.Cancelled");
const QString ErrFailed = QStringLiteral("org.kde.kpasskey.Error.Failed");

void wipe(QString &s)
{
    s.fill(QLatin1Char('\0'));
    s.clear();
}
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

QVariantMap ManagerDBus::ExportCredentials()
{
    const QDBusMessage msg = message();
    if (m_authenticator->isBusy() || m_backupRunning) {
        sendErrorReply(ErrBusy, QStringLiteral("Another operation is in progress"));
        return {};
    }
    setDelayedReply(true);
    m_backupRunning = true;
    auto replyError = [this, msg](const QString &name, const QString &text) {
        m_backupRunning = false;
        QDBusConnection::sessionBus().send(msg.createErrorReply(name, text));
    };
    m_store->ensureReady([this, msg, replyError](bool ok) {
        if (!ok) {
            replyError(ErrWalletUnavailable, QStringLiteral("KWallet is not available"));
            return;
        }
        m_verifier->verify(QStringLiteral("export passkeys"), [this, msg, replyError](bool verified) {
            if (!verified) {
                replyError(ErrNotAuthorized, QStringLiteral("User verification failed"));
                return;
            }
            const auto path = ui::askExportPath();
            if (!path) {
                replyError(ErrCancelled, QStringLiteral("Cancelled"));
                return;
            }
            auto pass = ui::askPassphrase(true);
            if (!pass) {
                replyError(ErrCancelled, QStringLiteral("Cancelled"));
                return;
            }
            cxf::ExportReport rep;
            const SecretBytes json = cxf::exportJson(m_store->allRecords(), &rep);
            auto file = backup::encrypt(json, *pass);
            wipe(*pass);
            QSaveFile out(*path);
            if (!file || !out.open(QIODevice::WriteOnly)) {
                replyError(ErrFailed, QStringLiteral("Could not write the backup"));
                return;
            }
            out.setPermissions(QFileDevice::ReadOwner | QFileDevice::WriteOwner);
            out.write(*file);
            if (!out.commit()) {
                replyError(ErrFailed, QStringLiteral("Could not write the backup"));
                return;
            }
            qCInfo(KPASSKEY_LOG) << "exported" << rep.exported << "passkeys";
            QString text = i18np("1 passkey was exported.", "%1 passkeys were exported.", rep.exported);
            if (rep.skippedHardwareBound) {
                text += QLatin1Char('\n') + i18np("1 TPM-bound passkey cannot be exported.",
                                                  "%1 TPM-bound passkeys cannot be exported.", rep.skippedHardwareBound);
            }
            if (rep.skippedNonZeroCounter) {
                text += QLatin1Char('\n') + i18np("1 older passkey with a signature counter was left out (CXF does not allow exporting it).",
                                                  "%1 older passkeys with a signature counter were left out (CXF does not allow exporting them).",
                                                  rep.skippedNonZeroCounter);
            }
            ui::showInfo(i18n("Passkeys exported"), text);
            m_backupRunning = false;
            QDBusMessage reply = msg.createReply();
            reply << QVariant(QVariantMap{
                {QStringLiteral("exported"), rep.exported},
                {QStringLiteral("skipped_hardware_bound"), rep.skippedHardwareBound},
                {QStringLiteral("skipped_nonzero_counter"), rep.skippedNonZeroCounter},
                {QStringLiteral("path"), *path},
            });
            QDBusConnection::sessionBus().send(reply);
        });
    });
    return {};
}

QVariantMap ManagerDBus::ImportCredentials()
{
    const QDBusMessage msg = message();
    if (m_authenticator->isBusy() || m_backupRunning) {
        sendErrorReply(ErrBusy, QStringLiteral("Another operation is in progress"));
        return {};
    }
    setDelayedReply(true);
    m_backupRunning = true;
    auto replyError = [this, msg](const QString &name, const QString &text) {
        m_backupRunning = false;
        QDBusConnection::sessionBus().send(msg.createErrorReply(name, text));
    };
    m_store->ensureReady([this, msg, replyError](bool ok) {
        if (!ok) {
            replyError(ErrWalletUnavailable, QStringLiteral("KWallet is not available"));
            return;
        }
        m_verifier->verify(QStringLiteral("import passkeys"), [this, msg, replyError](bool verified) {
            if (!verified) {
                replyError(ErrNotAuthorized, QStringLiteral("User verification failed"));
                return;
            }
            const auto path = ui::askImportPath();
            if (!path) {
                replyError(ErrCancelled, QStringLiteral("Cancelled"));
                return;
            }
            QFile in(*path);
            if (!in.open(QIODevice::ReadOnly) || in.size() > 64 * 1024 * 1024) {
                replyError(ErrFailed, QStringLiteral("Could not read the backup"));
                return;
            }
            const QByteArray file = in.readAll();
            std::optional<SecretBytes> json;
            for (;;) {
                auto pass = ui::askPassphrase(false);
                if (!pass) {
                    replyError(ErrCancelled, QStringLiteral("Cancelled"));
                    return;
                }
                backup::DecryptError err;
                json = backup::decrypt(file, *pass, &err);
                wipe(*pass);
                if (json) {
                    break;
                }
                if (err != backup::DecryptError::WrongPassphraseOrCorrupt) {
                    ui::showError(i18n("Import failed"), i18n("This is not a supported passkey backup."));
                    replyError(ErrFailed, QStringLiteral("Not a supported backup"));
                    return;
                }
                ui::showError(i18n("Import failed"), i18n("Wrong passphrase, or the file is damaged."));
            }
            const cxf::ImportResult res = cxf::importJson(json->bytes());
            if (!res.error.isEmpty()) {
                replyError(ErrFailed, res.error);
                return;
            }
            int imported = 0;
            int existing = 0;
            int failed = 0;
            for (const CredentialRecord &r : res.records) {
                if (m_store->find(r.rpId, r.credentialId)) {
                    ++existing;
                } else if (m_store->put(r)) {
                    ++imported;
                } else {
                    ++failed;
                }
            }
            qCInfo(KPASSKEY_LOG) << "imported" << imported << "passkeys," << existing << "already present";
            Q_EMIT CredentialsChanged();
            QString text = i18np("1 passkey was imported.", "%1 passkeys were imported.", imported);
            if (existing) {
                text += QLatin1Char('\n') + i18np("1 was already present.", "%1 were already present.", existing);
            }
            if (res.skippedInvalid || failed) {
                text += QLatin1Char('\n') + i18n("%1 could not be imported (unsupported or damaged).", res.skippedInvalid + failed);
            }
            if (res.skippedOtherTypes) {
                text += QLatin1Char('\n') + i18n("%1 other entries (passwords, codes, notes) were ignored.", res.skippedOtherTypes);
            }
            ui::showInfo(i18n("Passkeys imported"), text);
            m_backupRunning = false;
            QDBusMessage reply = msg.createReply();
            reply << QVariant(QVariantMap{
                {QStringLiteral("imported"), imported},
                {QStringLiteral("skipped_existing"), existing},
                {QStringLiteral("skipped_invalid"), res.skippedInvalid + failed},
                {QStringLiteral("skipped_other_types"), res.skippedOtherTypes},
            });
            QDBusConnection::sessionBus().send(reply);
        });
    });
    return {};
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
