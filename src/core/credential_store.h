// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include "credential.h"

#include <QHash>
#include <QList>
#include <functional>

namespace kpasskey {

// Storage backend. All calls happen on the daemon's main thread; requests are
// processed strictly one at a time, so read-modify-write sequences (sign
// counter) are not interleaved.
class CredentialStore
{
public:
    virtual ~CredentialStore() = default;

    // Makes sure the backend is unlocked/usable. May prompt the user (e.g. the
    // KWallet unlock dialog). Unlocking the storage is NOT user verification.
    virtual void ensureReady(std::function<void(bool ok)> done) = 0;

    // Atomically creates or replaces the record. Returns false on failure; the
    // caller must then not release any signature.
    virtual bool put(const CredentialRecord &record) = 0;

    virtual std::optional<CredentialRecord> find(const QString &rpId, const QByteArray &credentialId) = 0;
    virtual QList<CredentialRecord> findByRp(const QString &rpId) = 0;
    virtual QList<CredentialMetadata> listAll() = 0;
    // Full records including key material (backup export only).
    virtual QList<CredentialRecord> allRecords() = 0;
    // Removes a credential by its base64url ID. Returns false if not found.
    virtual bool remove(const QString &credentialIdB64) = 0;
};

// Volatile store used by tests and by `kpasskeyd --ephemeral`.
class MemoryStore : public CredentialStore
{
public:
    void ensureReady(std::function<void(bool)> done) override { done(m_ready); }
    bool put(const CredentialRecord &record) override;
    std::optional<CredentialRecord> find(const QString &rpId, const QByteArray &credentialId) override;
    QList<CredentialRecord> findByRp(const QString &rpId) override;
    QList<CredentialMetadata> listAll() override;
    QList<CredentialRecord> allRecords() override;
    bool remove(const QString &credentialIdB64) override;

    // Test hooks
    void setReady(bool ready) { m_ready = ready; }
    void setFailWrites(bool fail) { m_failWrites = fail; }
    // Raw access to the serialised form, to simulate corruption.
    QHash<QString, QString> &rawEntries() { return m_entries; }

private:
    QHash<QString, QString> m_entries; // entry key -> JSON (same format as KWallet)
    bool m_ready = true;
    bool m_failWrites = false;
};

} // namespace kpasskey
