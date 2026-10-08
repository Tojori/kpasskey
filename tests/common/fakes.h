// SPDX-License-Identifier: LGPL-2.1-or-later
// Test doubles and helpers shared by unit and security tests.
#pragma once

#include "core/authenticator.h"
#include "core/crypto.h"
#include "core/ctap_constants.h"
#include "core/hardware_keys.h"

#include <QCborArray>
#include <QCborMap>
#include <QCborValue>
#include <QHash>
#include <QtEndian>

#include <openssl/evp.h>
#include <openssl/x509.h>

namespace kpasskey::test {

class FakePrompter : public PresencePrompter
{
public:
    bool approve = true;
    int select = 0;
    bool deferred = false; // keep the callback pending (to test cancel/timeout)
    int calls = 0;
    PresenceRequest last;
    std::function<void(PresenceResult)> pending;

    void requestPresence(const PresenceRequest &request, std::function<void(PresenceResult)> done) override
    {
        ++calls;
        last = request;
        if (deferred) {
            pending = std::move(done);
            return;
        }
        done({approve, select});
    }
    void cancel() override { pending = nullptr; }
};

class FakeVerifier : public UserVerifier
{
public:
    bool available = true;
    bool result = true;
    int calls = 0;
    bool isAvailable() const override { return available; }
    void verify(const QString &, std::function<void(bool)> done) override
    {
        ++calls;
        done(result);
    }
    void cancel() override { }
};

// Stands in for the TPM: keys are software keys, but blobs have the real
// TPM2B_PUBLIC || TPM2B_PRIVATE layout so record validation is exercised.
class FakeHardwareKeyStore : public HardwareKeyStore
{
public:
    int creates = 0;
    int signs = 0;
    bool fail = false;

    std::optional<Key> createKey() override
    {
        ++creates;
        if (fail) {
            return std::nullopt;
        }
        auto kp = crypto::generateKeyPair(ctap::ES256);
        const QCborMap cose = QCborValue::fromCbor(kp->publicKeyCose).toMap();
        const QByteArray id = crypto::randomBytes(16);
        auto blob = tpmblob::make(cose.value(-2).toByteArray(), cose.value(-3).toByteArray(), id);
        m_keys.insert(*blob, kp->privateKeyPkcs8);
        return Key{*blob, kp->publicKeyCose};
    }

    std::optional<QByteArray> signDigest(const QByteArray &blob, const QByteArray &digest) override
    {
        ++signs;
        const auto it = m_keys.constFind(blob);
        if (fail || it == m_keys.constEnd() || digest.size() != 32) {
            return std::nullopt;
        }
        const auto *p = reinterpret_cast<const unsigned char *>(it->bytes().constData());
        PKCS8_PRIV_KEY_INFO *p8 = d2i_PKCS8_PRIV_KEY_INFO(nullptr, &p, it->bytes().size());
        EVP_PKEY *pkey = p8 ? EVP_PKCS82PKEY(p8) : nullptr;
        PKCS8_PRIV_KEY_INFO_free(p8);
        EVP_PKEY_CTX *ctx = pkey ? EVP_PKEY_CTX_new(pkey, nullptr) : nullptr;
        size_t len = 0;
        QByteArray sig;
        if (ctx && EVP_PKEY_sign_init(ctx) == 1 && EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) == 1
            && EVP_PKEY_sign(ctx, nullptr, &len, reinterpret_cast<const unsigned char *>(digest.constData()), 32) == 1) {
            sig.resize(qsizetype(len));
            if (EVP_PKEY_sign(ctx, reinterpret_cast<unsigned char *>(sig.data()), &len,
                              reinterpret_cast<const unsigned char *>(digest.constData()), 32) == 1) {
                sig.resize(qsizetype(len));
            } else {
                sig.clear();
            }
        }
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        if (sig.isEmpty()) {
            return std::nullopt;
        }
        return sig;
    }

private:
    QHash<QByteArray, SecretBytes> m_keys;
};

// Synchronously runs one request; returns status byte + CBOR.
inline QByteArray run(Authenticator &a, quint8 cmd, const QCborMap &params = {})
{
    QByteArray result;
    bool called = false;
    QByteArray req(1, char(cmd));
    if (!params.isEmpty()) {
        req += QCborValue(params).toCbor();
    }
    a.process(req, [&](const QByteArray &r) {
        result = r;
        called = true;
    });
    return called ? result : QByteArray();
}

inline quint8 status(const QByteArray &r)
{
    return r.isEmpty() ? 0xff : quint8(r.at(0));
}

inline QCborMap body(const QByteArray &r)
{
    return QCborValue::fromCbor(r.mid(1)).toMap();
}

inline QCborMap pkParam(int alg)
{
    QCborMap m;
    m.insert(QStringLiteral("alg"), alg);
    m.insert(QStringLiteral("type"), QStringLiteral("public-key"));
    return m;
}

inline QCborMap makeCredentialParams(const QString &rpId, const QByteArray &userId, const QByteArray &cdh,
                                     bool rk = true, bool uv = false, QCborArray algs = {pkParam(ctap::ES256)})
{
    QCborMap rp;
    rp.insert(QStringLiteral("id"), rpId);
    rp.insert(QStringLiteral("name"), QStringLiteral("Example <b>Corp</b>"));
    QCborMap user;
    user.insert(QStringLiteral("id"), userId);
    user.insert(QStringLiteral("name"), QStringLiteral("alice@example.com"));
    user.insert(QStringLiteral("displayName"), QStringLiteral("Alice"));
    QCborMap options;
    options.insert(QStringLiteral("rk"), rk);
    if (uv) {
        options.insert(QStringLiteral("uv"), true);
    }
    QCborMap p;
    p.insert(1, cdh);
    p.insert(2, rp);
    p.insert(3, user);
    p.insert(4, algs);
    p.insert(7, options);
    return p;
}

inline QCborMap descriptor(const QByteArray &id)
{
    QCborMap d;
    d.insert(QStringLiteral("id"), id);
    d.insert(QStringLiteral("type"), QStringLiteral("public-key"));
    return d;
}

inline QCborMap getAssertionParams(const QString &rpId, const QByteArray &cdh, const QList<QByteArray> &allow = {},
                                   std::optional<bool> up = {}, bool uv = false)
{
    QCborMap p;
    p.insert(1, rpId);
    p.insert(2, cdh);
    if (!allow.isEmpty()) {
        QCborArray a;
        for (const QByteArray &id : allow) {
            a.append(descriptor(id));
        }
        p.insert(3, a);
    }
    QCborMap options;
    if (up.has_value()) {
        options.insert(QStringLiteral("up"), *up);
    }
    if (uv) {
        options.insert(QStringLiteral("uv"), true);
    }
    if (!options.isEmpty()) {
        p.insert(5, options);
    }
    return p;
}

// Plays the platform side of PIN/UV auth protocol 2 and returns the decrypted
// pinUvAuthToken, or nullopt with *statusOut set.
inline std::optional<QByteArray> obtainToken(Authenticator &a, int permissions, const QString &rpId,
                                             quint8 *statusOut = nullptr)
{
    QCborMap ka;
    ka.insert(1, 2);
    ka.insert(2, ctap::GetKeyAgreement);
    const QByteArray kr = run(a, ctap::ClientPin, ka);
    if (status(kr) != ctap::Ok) {
        if (statusOut) {
            *statusOut = status(kr);
        }
        return std::nullopt;
    }
    PinUvProtocol2 platform;
    const auto shared = platform.sharedSecret(body(kr).value(1).toMap());
    if (!shared) {
        return std::nullopt;
    }
    QCborMap req;
    req.insert(1, 2);
    req.insert(2, ctap::GetPinUvAuthTokenUsingUvWithPermissions);
    req.insert(3, platform.keyAgreementCose());
    req.insert(9, permissions);
    if (!rpId.isEmpty()) {
        req.insert(10, rpId);
    }
    const QByteArray tr = run(a, ctap::ClientPin, req);
    if (statusOut) {
        *statusOut = status(tr);
    }
    if (status(tr) != ctap::Ok) {
        return std::nullopt;
    }
    return PinUvProtocol2::decrypt(*shared, body(tr).value(2).toByteArray());
}

struct ParsedAuthData {
    QByteArray rpIdHash;
    quint8 flags = 0;
    quint32 counter = 0;
    QByteArray aaguid;
    QByteArray credentialId;
    QByteArray publicKeyCose;
};

inline ParsedAuthData parseAuthData(const QByteArray &ad)
{
    ParsedAuthData p;
    p.rpIdHash = ad.left(32);
    p.flags = quint8(ad.at(32));
    p.counter = qFromBigEndian<quint32>(ad.constData() + 33);
    if (p.flags & ctap::FlagAT) {
        p.aaguid = ad.mid(37, 16);
        const int len = qFromBigEndian<quint16>(ad.constData() + 53);
        p.credentialId = ad.mid(55, len);
        p.publicKeyCose = ad.mid(55 + len);
    }
    return p;
}

} // namespace kpasskey::test
