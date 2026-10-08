// SPDX-License-Identifier: LGPL-2.1-or-later
#include "pin_uv.h"

#include <openssl/crypto.h>

namespace kpasskey {

namespace {
constexpr int CoseKty = 1;
constexpr int CoseAlg = 3;
constexpr int CoseCrv = -1;
constexpr int CoseX = -2;
constexpr int CoseY = -3;
constexpr int EcdhEsHkdf256 = -25;
} // namespace

PinUvProtocol2::PinUvProtocol2()
{
    regenerate();
}

bool PinUvProtocol2::regenerate()
{
    m_key = crypto::ecdhGenerate();
    return m_key.has_value();
}

QCborMap PinUvProtocol2::keyAgreementCose() const
{
    QCborMap m; // canonical order 1, 3, -1, -2, -3
    if (!m_key) {
        return m;
    }
    m.insert(CoseKty, 2);
    m.insert(CoseAlg, EcdhEsHkdf256);
    m.insert(CoseCrv, 1);
    m.insert(CoseX, m_key->x);
    m.insert(CoseY, m_key->y);
    return m;
}

std::optional<SecretBytes> PinUvProtocol2::sharedSecret(const QCborMap &platformKey) const
{
    if (!m_key || platformKey.value(CoseKty).toInteger() != 2 || platformKey.value(CoseCrv).toInteger() != 1) {
        return std::nullopt;
    }
    const auto z = crypto::ecdhSharedX(*m_key, platformKey.value(CoseX).toByteArray(), platformKey.value(CoseY).toByteArray());
    if (!z) {
        return std::nullopt;
    }
    const QByteArray salt(32, '\0');
    auto hmacKey = crypto::hkdfSha256(z->bytes(), salt, QByteArrayLiteral("CTAP2 HMAC key"), 32);
    auto aesKey = crypto::hkdfSha256(z->bytes(), salt, QByteArrayLiteral("CTAP2 AES key"), 32);
    if (!hmacKey || !aesKey) {
        return std::nullopt;
    }
    SecretBytes out(*hmacKey + *aesKey);
    OPENSSL_cleanse(hmacKey->data(), size_t(hmacKey->size()));
    OPENSSL_cleanse(aesKey->data(), size_t(aesKey->size()));
    return out;
}

std::optional<QByteArray> PinUvProtocol2::encrypt(const SecretBytes &shared, const QByteArray &plaintext)
{
    if (shared.bytes().size() != 64) {
        return std::nullopt;
    }
    const QByteArray iv = crypto::randomBytes(16);
    auto ct = crypto::aes256CbcEncrypt(shared.bytes().mid(32), iv, plaintext);
    if (!ct) {
        return std::nullopt;
    }
    return iv + *ct;
}

std::optional<QByteArray> PinUvProtocol2::decrypt(const SecretBytes &shared, const QByteArray &ivAndCiphertext)
{
    if (shared.bytes().size() != 64 || ivAndCiphertext.size() < 16) {
        return std::nullopt;
    }
    return crypto::aes256CbcDecrypt(shared.bytes().mid(32), ivAndCiphertext.left(16), ivAndCiphertext.mid(16));
}

QByteArray PinUvProtocol2::authenticate(const QByteArray &key, const QByteArray &message)
{
    return crypto::hmacSha256(key, message);
}

bool PinUvProtocol2::verify(const QByteArray &key, const QByteArray &message, const QByteArray &signature)
{
    return signature.size() == 32 && crypto::constantTimeEquals(authenticate(key, message), signature);
}

} // namespace kpasskey
