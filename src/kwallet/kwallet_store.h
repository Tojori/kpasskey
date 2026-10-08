// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include "core/credential_store.h"

#include <QObject>
#include <QPointer>

namespace KWallet {
class Wallet;
}

namespace kpasskey {

// Stores credentials in the user's local KWallet, folder "Passkeys", one
// password-type entry per credential:  key = "<rpId>/<b64url(credentialId)>",
// value = JSON record (docs/storage-format.md).
class KWalletStore : public QObject, public CredentialStore
{
    Q_OBJECT
public:
    static constexpr auto FolderName = "Passkeys";

    explicit KWalletStore(QObject *parent = nullptr);
    ~KWalletStore() override;

    void ensureReady(std::function<void(bool)> done) override;
    bool put(const CredentialRecord &record) override;
    std::optional<CredentialRecord> find(const QString &rpId, const QByteArray &credentialId) override;
    QList<CredentialRecord> findByRp(const QString &rpId) override;
    QList<CredentialMetadata> listAll() override;
    QList<CredentialRecord> allRecords() override;
    bool remove(const QString &credentialIdB64) override;

Q_SIGNALS:
    void changed();

private:
    bool isOpen() const;
    std::optional<CredentialRecord> readEntry(const QString &key);
    void onWalletOpened(bool success);

    QPointer<KWallet::Wallet> m_wallet;
    bool m_opening = false;
    QList<std::function<void(bool)>> m_waiting;
};

} // namespace kpasskey
