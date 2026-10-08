// SPDX-License-Identifier: LGPL-2.1-or-later
// Thin RAII wrapper around OpenSSL 3 (EVP API). No cryptographic primitives are
// implemented here; everything is delegated to libcrypto.
#pragma once

#include <QByteArray>
#include <optional>

namespace kpasskey {

// Holds secret material (PKCS#8 private keys). Wipes its buffer on destruction
// when it is the last owner. Deliberately has no QDebug streaming operator.
class SecretBytes
{
public:
    SecretBytes() = default;
    explicit SecretBytes(QByteArray data);
    SecretBytes(const SecretBytes &) = default;
    SecretBytes &operator=(const SecretBytes &) = default;
    SecretBytes(SecretBytes &&) noexcept = default;
    SecretBytes &operator=(SecretBytes &&) noexcept = default;
    ~SecretBytes();

    const QByteArray &bytes() const { return m_data; }
    bool isEmpty() const { return m_data.isEmpty(); }

private:
    QByteArray m_data;
};

namespace crypto {

struct KeyPair {
    int coseAlg = 0;
    SecretBytes privateKeyPkcs8; // DER encoded PKCS#8 PrivateKeyInfo
    QByteArray publicKeyCose;    // canonical CBOR COSE_Key
};

bool isSupportedAlg(int coseAlg);

// Generates a fresh key pair for ES256 (P-256) or EdDSA (Ed25519).
std::optional<KeyPair> generateKeyPair(int coseAlg);

// Signs `data` with the PKCS#8 key. ES256 yields an ASN.1 DER ECDSA signature
// (as required by WebAuthn), EdDSA a raw 64 byte signature.
std::optional<QByteArray> sign(const SecretBytes &privateKeyPkcs8, int coseAlg, const QByteArray &data);

// Re-derives the COSE public key from the private key. Used to detect corrupted
// or tampered records before a key is used.
std::optional<QByteArray> publicKeyCoseFromPrivate(const SecretBytes &privateKeyPkcs8, int coseAlg);

// Verifies a signature with a COSE public key (used by tests and self-checks).
bool verify(const QByteArray &publicKeyCose, const QByteArray &data, const QByteArray &signature);

// --- primitives used by the CTAP 2.1 PIN/UV auth protocol 2 (all via OpenSSL) ---
struct EcdhKey {
    SecretBytes privateKeyPkcs8;
    QByteArray x; // 32 bytes
    QByteArray y; // 32 bytes
};
std::optional<EcdhKey> ecdhGenerate();
// Returns the x coordinate of the shared point (Z). Rejects points not on P-256.
std::optional<SecretBytes> ecdhSharedX(const EcdhKey &own, const QByteArray &peerX, const QByteArray &peerY);
std::optional<QByteArray> hkdfSha256(const QByteArray &ikm, const QByteArray &salt, const QByteArray &info, int length);
// AES-256-CBC without padding; plaintext length must be a multiple of 16.
std::optional<QByteArray> aes256CbcEncrypt(const QByteArray &key, const QByteArray &iv, const QByteArray &plaintext);
std::optional<QByteArray> aes256CbcDecrypt(const QByteArray &key, const QByteArray &iv, const QByteArray &ciphertext);
QByteArray hmacSha256(const QByteArray &key, const QByteArray &data);
bool constantTimeEquals(const QByteArray &a, const QByteArray &b);

QByteArray randomBytes(int count);
QByteArray sha256(const QByteArray &data);

} // namespace crypto
} // namespace kpasskey
