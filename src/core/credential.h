// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include "crypto.h"

#include <QByteArray>
#include <QDateTime>
#include <QString>
#include <optional>

namespace kpasskey {

// Newest on-disk schema version this build understands; see
// docs/storage-format.md. v1: key in KWallet (PKCS#8). v2: adds TPM-wrapped keys.
constexpr int CredentialSchemaVersion = 2;

namespace protection {
inline const QString Wallet = QStringLiteral("kwallet"); // PKCS#8, protected by KWallet only
inline const QString Tpm2 = QStringLiteral("tpm2");      // TPM key blob, unusable on other machines
}

struct CredentialRecord {
    QByteArray credentialId;      // 32 random bytes
    QString rpId;                 // effective RP ID as passed by the client (already origin-checked by it)
    QString rpName;               // informational only, site-controlled
    QByteArray userHandle;        // user.id, 1..64 bytes, opaque
    QString userName;             // user.name, site-controlled
    QString userDisplayName;      // user.displayName, site-controlled
    int coseAlg = 0;
    QByteArray publicKeyCose;
    SecretBytes privateKeyPkcs8;  // protection::Wallet: PKCS#8 DER; protection::Tpm2: TPM key blob
    QString keyProtection = protection::Wallet;
    quint32 signCount = 0;
    bool discoverable = true;     // resident key
    bool uvAtCreation = false;    // whether UV was performed when the credential was created
    QDateTime created;
    QDateTime lastUsed;

    // Non-secret view for UIs, D-Bus and logs.
    QString credentialIdB64() const;
};

// Metadata that may leave the daemon (never contains key material).
struct CredentialMetadata {
    QString credentialIdB64;
    QString rpId;
    QString userName;
    QString userDisplayName;
    qint64 created = 0;
    qint64 lastUsed = 0;
    QString keyProtection;
};
CredentialMetadata metadataOf(const CredentialRecord &r);

namespace record {

enum class DecodeError {
    None,
    Malformed,          // not JSON / wrong types / missing fields
    UnsupportedSchema,  // written by a newer version; must not be modified
    Inconsistent,       // key does not match fields, or public key does not match private key
};

// Serialises a record to the JSON string stored in the wallet entry.
QString encode(const CredentialRecord &r);

// Parses and validates a stored record. `entryKey` is the wallet entry key the
// value was read from; it must match the record content.
std::optional<CredentialRecord> decode(const QString &entryKey, const QString &json, DecodeError *error = nullptr);

// Wallet entry key: "<rpId>/<base64url(credentialId)>"
QString entryKey(const QString &rpId, const QByteArray &credentialId);

QString b64url(const QByteArray &data);
std::optional<QByteArray> fromB64url(const QString &s);

} // namespace record

// Returns true if `rpId` looks like a valid (ASCII / punycode) domain name.
// The authenticator cannot see the origin; this only rejects garbage early.
bool isPlausibleRpId(const QString &rpId);

} // namespace kpasskey
