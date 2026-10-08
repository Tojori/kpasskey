// SPDX-License-Identifier: LGPL-2.1-or-later
#include "credential_store.h"

namespace kpasskey {

bool MemoryStore::put(const CredentialRecord &record)
{
    if (m_failWrites) {
        return false;
    }
    m_entries.insert(record::entryKey(record.rpId, record.credentialId), record::encode(record));
    return true;
}

std::optional<CredentialRecord> MemoryStore::find(const QString &rpId, const QByteArray &credentialId)
{
    const QString key = record::entryKey(rpId, credentialId);
    const auto it = m_entries.constFind(key);
    if (it == m_entries.constEnd()) {
        return std::nullopt;
    }
    return record::decode(key, it.value());
}

QList<CredentialRecord> MemoryStore::findByRp(const QString &rpId)
{
    QList<CredentialRecord> out;
    const QString prefix = rpId + QLatin1Char('/');
    for (auto it = m_entries.constBegin(); it != m_entries.constEnd(); ++it) {
        if (it.key().startsWith(prefix)) {
            if (auto r = record::decode(it.key(), it.value())) {
                out.append(std::move(*r));
            }
        }
    }
    return out;
}

QList<CredentialMetadata> MemoryStore::listAll()
{
    QList<CredentialMetadata> out;
    for (auto it = m_entries.constBegin(); it != m_entries.constEnd(); ++it) {
        if (auto r = record::decode(it.key(), it.value())) {
            out.append(metadataOf(*r));
        }
    }
    return out;
}

QList<CredentialRecord> MemoryStore::allRecords()
{
    QList<CredentialRecord> out;
    for (auto it = m_entries.constBegin(); it != m_entries.constEnd(); ++it) {
        if (auto r = record::decode(it.key(), it.value())) {
            out.append(std::move(*r));
        }
    }
    return out;
}

bool MemoryStore::remove(const QString &credentialIdB64)
{
    const QString suffix = QLatin1Char('/') + credentialIdB64;
    for (auto it = m_entries.begin(); it != m_entries.end(); ++it) {
        if (it.key().endsWith(suffix)) {
            m_entries.erase(it);
            return true;
        }
    }
    return false;
}

} // namespace kpasskey
