// SPDX-License-Identifier: LGPL-2.1-or-later
// CTAP 2.1 PIN/UV auth protocol 2 (section 6.5.7). Only the parts needed for
// built-in user verification (getPinUvAuthTokenUsingUvWithPermissions); no PIN.
#pragma once

#include "crypto.h"

#include <QCborMap>
#include <optional>

namespace kpasskey {

class PinUvProtocol2
{
public:
    static constexpr int Version = 2;

    PinUvProtocol2();

    // Generates a fresh ephemeral key agreement key pair.
    bool regenerate();
    // COSE_Key {1:2, 3:-25, -1:1, -2:x, -3:y} for authenticatorClientPIN(getKeyAgreement).
    QCborMap keyAgreementCose() const;
    // ECDH + HKDF-SHA-256: returns HMAC key (32) || AES key (32).
    std::optional<SecretBytes> sharedSecret(const QCborMap &platformKey) const;
    // AES-256-CBC with random IV; returns IV || ciphertext.
    static std::optional<QByteArray> encrypt(const SecretBytes &shared, const QByteArray &plaintext);
    static std::optional<QByteArray> decrypt(const SecretBytes &shared, const QByteArray &ivAndCiphertext);
    // HMAC-SHA-256 (full 32 bytes for protocol 2).
    static QByteArray authenticate(const QByteArray &key, const QByteArray &message);
    static bool verify(const QByteArray &key, const QByteArray &message, const QByteArray &signature);

private:
    std::optional<crypto::EcdhKey> m_key;
};

} // namespace kpasskey
