// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include <QByteArray>
#include <optional>

namespace kpasskey {

// Non-exportable keys held by hardware (TPM 2.0 via kpasskey-tpm-helper).
// Only ES256 (ECC P-256): EdDSA is not available on common TPMs.
class HardwareKeyStore
{
public:
    struct Key {
        QByteArray blob;          // opaque, TPM-wrapped; safe to store in KWallet
        QByteArray publicKeyCose; // ES256 COSE_Key
    };

    virtual ~HardwareKeyStore() = default;
    virtual std::optional<Key> createKey() = 0;
    // Signs a SHA-256 digest; returns the ASN.1 DER ECDSA signature.
    virtual std::optional<QByteArray> signDigest(const QByteArray &blob, const QByteArray &digest) = 0;
};

namespace tpmblob {
// Parses a key blob (TPM2B_PUBLIC || TPM2B_PRIVATE, TPM marshalling via
// tss2-mu), checks that it is an unrestricted ECC P-256 ECDSA signing key and
// returns its public key as ES256 COSE_Key.
std::optional<QByteArray> publicKeyCose(const QByteArray &blob);
// Builds a blob from public point and an opaque private part (tests, helper).
std::optional<QByteArray> make(const QByteArray &x, const QByteArray &y, const QByteArray &privatePart);
} // namespace tpmblob

} // namespace kpasskey
