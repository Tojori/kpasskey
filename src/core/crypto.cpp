// SPDX-License-Identifier: LGPL-2.1-or-later
#include "crypto.h"

#include "ctap_constants.h"

#include <QCborMap>
#include <QCborValue>
#include <QCryptographicHash>

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/param_build.h>
#include <openssl/rand.h>
#include <openssl/x509.h>

#include <memory>

namespace kpasskey {

SecretBytes::SecretBytes(QByteArray data)
    : m_data(std::move(data))
{
}

SecretBytes::~SecretBytes()
{
    // Only wipe when we are the sole owner; data() would otherwise detach and
    // wipe a private copy while the shared buffer survives.
    if (!m_data.isEmpty() && m_data.isDetached()) {
        OPENSSL_cleanse(m_data.data(), size_t(m_data.size()));
    }
}

namespace crypto {
namespace {

struct PkeyDeleter {
    void operator()(EVP_PKEY *p) const { EVP_PKEY_free(p); }
};
struct MdCtxDeleter {
    void operator()(EVP_MD_CTX *p) const { EVP_MD_CTX_free(p); }
};
struct BnDeleter {
    void operator()(BIGNUM *p) const { BN_free(p); }
};
struct P8Deleter {
    void operator()(PKCS8_PRIV_KEY_INFO *p) const { PKCS8_PRIV_KEY_INFO_free(p); }
};
struct ParamBldDeleter {
    void operator()(OSSL_PARAM_BLD *p) const { OSSL_PARAM_BLD_free(p); }
};
struct ParamDeleter {
    void operator()(OSSL_PARAM *p) const { OSSL_PARAM_free(p); }
};
struct PkeyCtxDeleter {
    void operator()(EVP_PKEY_CTX *p) const { EVP_PKEY_CTX_free(p); }
};

using PkeyPtr = std::unique_ptr<EVP_PKEY, PkeyDeleter>;

// COSE key parameters (RFC 9052/9053)
constexpr int CoseKty = 1;
constexpr int CoseAlgLabel = 3;
constexpr int CoseCrv = -1;
constexpr int CoseX = -2;
constexpr int CoseY = -3;
constexpr int KtyOkp = 1;
constexpr int KtyEc2 = 2;
constexpr int CrvP256 = 1;
constexpr int CrvEd25519 = 6;

std::optional<QByteArray> coseFromPkey(EVP_PKEY *pkey, int coseAlg)
{
    // Map entries are inserted in CTAP2 canonical order (1, 3, -1, -2, -3).
    QCborMap cose;
    if (coseAlg == ctap::ES256) {
        BIGNUM *xRaw = nullptr;
        BIGNUM *yRaw = nullptr;
        if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &xRaw) != 1
            || EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &yRaw) != 1) {
            BN_free(xRaw);
            return std::nullopt;
        }
        std::unique_ptr<BIGNUM, BnDeleter> x(xRaw), y(yRaw);
        QByteArray xb(32, '\0'), yb(32, '\0');
        if (BN_bn2binpad(x.get(), reinterpret_cast<unsigned char *>(xb.data()), 32) != 32
            || BN_bn2binpad(y.get(), reinterpret_cast<unsigned char *>(yb.data()), 32) != 32) {
            return std::nullopt;
        }
        cose.insert(CoseKty, KtyEc2);
        cose.insert(CoseAlgLabel, ctap::ES256);
        cose.insert(CoseCrv, CrvP256);
        cose.insert(CoseX, xb);
        cose.insert(CoseY, yb);
    } else if (coseAlg == ctap::EdDSA) {
        QByteArray raw(32, '\0');
        size_t len = 32;
        if (EVP_PKEY_get_raw_public_key(pkey, reinterpret_cast<unsigned char *>(raw.data()), &len) != 1 || len != 32) {
            return std::nullopt;
        }
        cose.insert(CoseKty, KtyOkp);
        cose.insert(CoseAlgLabel, ctap::EdDSA);
        cose.insert(CoseCrv, CrvEd25519);
        cose.insert(CoseX, raw);
    } else {
        return std::nullopt;
    }
    return QCborValue(cose).toCbor();
}

PkeyPtr pkeyFromPkcs8(const SecretBytes &der)
{
    const auto *p = reinterpret_cast<const unsigned char *>(der.bytes().constData());
    std::unique_ptr<PKCS8_PRIV_KEY_INFO, P8Deleter> p8(d2i_PKCS8_PRIV_KEY_INFO(nullptr, &p, der.bytes().size()));
    if (!p8) {
        return nullptr;
    }
    return PkeyPtr(EVP_PKCS82PKEY(p8.get()));
}

bool pkeyMatchesAlg(EVP_PKEY *pkey, int coseAlg)
{
    if (coseAlg == ctap::ES256) {
        char group[64] = {};
        size_t len = 0;
        return EVP_PKEY_is_a(pkey, "EC")
            && EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME, group, sizeof(group), &len) == 1
            && (qstrcmp(group, "prime256v1") == 0 || qstrcmp(group, "P-256") == 0);
    }
    if (coseAlg == ctap::EdDSA) {
        return EVP_PKEY_is_a(pkey, "ED25519");
    }
    return false;
}

PkeyPtr ecPublicKey(const QByteArray &x, const QByteArray &y)
{
    if (x.size() != 32 || y.size() != 32) {
        return nullptr;
    }
    const QByteArray point = QByteArray(1, '\x04') + x + y;
    std::unique_ptr<OSSL_PARAM_BLD, ParamBldDeleter> bld(OSSL_PARAM_BLD_new());
    if (!bld
        || OSSL_PARAM_BLD_push_utf8_string(bld.get(), OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0) != 1
        || OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_PUB_KEY, point.constData(), size_t(point.size())) != 1) {
        return nullptr;
    }
    std::unique_ptr<OSSL_PARAM, ParamDeleter> params(OSSL_PARAM_BLD_to_param(bld.get()));
    std::unique_ptr<EVP_PKEY_CTX, PkeyCtxDeleter> ctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    EVP_PKEY *out = nullptr;
    if (!params || !ctx || EVP_PKEY_fromdata_init(ctx.get()) != 1
        || EVP_PKEY_fromdata(ctx.get(), &out, EVP_PKEY_PUBLIC_KEY, params.get()) != 1) {
        return nullptr;
    }
    PkeyPtr pkey(out);
    // Reject points that are not on the curve (invalid-curve attacks on ECDH).
    std::unique_ptr<EVP_PKEY_CTX, PkeyCtxDeleter> check(EVP_PKEY_CTX_new_from_pkey(nullptr, pkey.get(), nullptr));
    if (!check || EVP_PKEY_public_check(check.get()) != 1) {
        return nullptr;
    }
    return pkey;
}

PkeyPtr pkeyFromCose(const QByteArray &coseBytes, int *algOut)
{
    QCborParserError err;
    const QCborValue v = QCborValue::fromCbor(coseBytes, &err);
    if (err.error != QCborError::NoError || !v.isMap()) {
        return nullptr;
    }
    const QCborMap m = v.toMap();
    const qint64 kty = m.value(CoseKty).toInteger(0);
    const qint64 alg = m.value(CoseAlgLabel).toInteger(0);
    const qint64 crv = m.value(CoseCrv).toInteger(0);
    const QByteArray x = m.value(CoseX).toByteArray();
    *algOut = int(alg);

    if (kty == KtyEc2 && alg == ctap::ES256 && crv == CrvP256) {
        const QByteArray y = m.value(CoseY).toByteArray();
        if (x.size() != 32 || y.size() != 32) {
            return nullptr;
        }
        return ecPublicKey(x, y);
    }
    if (kty == KtyOkp && alg == ctap::EdDSA && crv == CrvEd25519 && x.size() == 32) {
        return PkeyPtr(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
                                                   reinterpret_cast<const unsigned char *>(x.constData()), 32));
    }
    return nullptr;
}

const EVP_MD *digestFor(int coseAlg)
{
    // Ed25519 is used in one-shot mode without a separate digest.
    return coseAlg == ctap::ES256 ? EVP_sha256() : nullptr;
}

} // namespace

bool isSupportedAlg(int coseAlg)
{
    return coseAlg == ctap::ES256 || coseAlg == ctap::EdDSA;
}

std::optional<KeyPair> generateKeyPair(int coseAlg)
{
    PkeyPtr pkey;
    if (coseAlg == ctap::ES256) {
        pkey.reset(EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256"));
    } else if (coseAlg == ctap::EdDSA) {
        pkey.reset(EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519"));
    }
    if (!pkey) {
        return std::nullopt;
    }

    std::unique_ptr<PKCS8_PRIV_KEY_INFO, P8Deleter> p8(EVP_PKEY2PKCS8(pkey.get()));
    if (!p8) {
        return std::nullopt;
    }
    const int len = i2d_PKCS8_PRIV_KEY_INFO(p8.get(), nullptr);
    if (len <= 0) {
        return std::nullopt;
    }
    QByteArray der(len, '\0');
    auto *out = reinterpret_cast<unsigned char *>(der.data());
    if (i2d_PKCS8_PRIV_KEY_INFO(p8.get(), &out) != len) {
        OPENSSL_cleanse(der.data(), size_t(der.size()));
        return std::nullopt;
    }

    auto cose = coseFromPkey(pkey.get(), coseAlg);
    if (!cose) {
        OPENSSL_cleanse(der.data(), size_t(der.size()));
        return std::nullopt;
    }
    KeyPair kp;
    kp.coseAlg = coseAlg;
    kp.privateKeyPkcs8 = SecretBytes(std::move(der));
    kp.publicKeyCose = *cose;
    return kp;
}

std::optional<QByteArray> sign(const SecretBytes &privateKeyPkcs8, int coseAlg, const QByteArray &data)
{
    PkeyPtr pkey = pkeyFromPkcs8(privateKeyPkcs8);
    if (!pkey || !pkeyMatchesAlg(pkey.get(), coseAlg)) {
        return std::nullopt;
    }
    std::unique_ptr<EVP_MD_CTX, MdCtxDeleter> ctx(EVP_MD_CTX_new());
    if (!ctx || EVP_DigestSignInit(ctx.get(), nullptr, digestFor(coseAlg), nullptr, pkey.get()) != 1) {
        return std::nullopt;
    }
    size_t sigLen = 0;
    const auto *in = reinterpret_cast<const unsigned char *>(data.constData());
    if (EVP_DigestSign(ctx.get(), nullptr, &sigLen, in, size_t(data.size())) != 1) {
        return std::nullopt;
    }
    QByteArray sig(qsizetype(sigLen), '\0');
    if (EVP_DigestSign(ctx.get(), reinterpret_cast<unsigned char *>(sig.data()), &sigLen, in, size_t(data.size())) != 1) {
        return std::nullopt;
    }
    sig.resize(qsizetype(sigLen));
    return sig;
}

std::optional<QByteArray> publicKeyCoseFromPrivate(const SecretBytes &privateKeyPkcs8, int coseAlg)
{
    PkeyPtr pkey = pkeyFromPkcs8(privateKeyPkcs8);
    if (!pkey || !pkeyMatchesAlg(pkey.get(), coseAlg)) {
        return std::nullopt;
    }
    return coseFromPkey(pkey.get(), coseAlg);
}

bool verify(const QByteArray &publicKeyCose, const QByteArray &data, const QByteArray &signature)
{
    int alg = 0;
    PkeyPtr pkey = pkeyFromCose(publicKeyCose, &alg);
    if (!pkey) {
        return false;
    }
    std::unique_ptr<EVP_MD_CTX, MdCtxDeleter> ctx(EVP_MD_CTX_new());
    if (!ctx || EVP_DigestVerifyInit(ctx.get(), nullptr, digestFor(alg), nullptr, pkey.get()) != 1) {
        return false;
    }
    return EVP_DigestVerify(ctx.get(),
                            reinterpret_cast<const unsigned char *>(signature.constData()), size_t(signature.size()),
                            reinterpret_cast<const unsigned char *>(data.constData()), size_t(data.size()))
        == 1;
}

std::optional<EcdhKey> ecdhGenerate()
{
    auto kp = generateKeyPair(ctap::ES256);
    if (!kp) {
        return std::nullopt;
    }
    const QCborMap cose = QCborValue::fromCbor(kp->publicKeyCose).toMap();
    return EcdhKey{kp->privateKeyPkcs8, cose.value(CoseX).toByteArray(), cose.value(CoseY).toByteArray()};
}

std::optional<SecretBytes> ecdhSharedX(const EcdhKey &own, const QByteArray &peerX, const QByteArray &peerY)
{
    PkeyPtr mine = pkeyFromPkcs8(own.privateKeyPkcs8);
    PkeyPtr peer = ecPublicKey(peerX, peerY);
    if (!mine || !peer) {
        return std::nullopt;
    }
    std::unique_ptr<EVP_PKEY_CTX, PkeyCtxDeleter> ctx(EVP_PKEY_CTX_new_from_pkey(nullptr, mine.get(), nullptr));
    size_t len = 0;
    if (!ctx || EVP_PKEY_derive_init(ctx.get()) != 1 || EVP_PKEY_derive_set_peer_ex(ctx.get(), peer.get(), 1) != 1
        || EVP_PKEY_derive(ctx.get(), nullptr, &len) != 1 || len != 32) {
        return std::nullopt;
    }
    QByteArray z(32, '\0');
    if (EVP_PKEY_derive(ctx.get(), reinterpret_cast<unsigned char *>(z.data()), &len) != 1) {
        OPENSSL_cleanse(z.data(), size_t(z.size()));
        return std::nullopt;
    }
    return SecretBytes(std::move(z));
}

std::optional<QByteArray> hkdfSha256(const QByteArray &ikm, const QByteArray &salt, const QByteArray &info, int length)
{
    EVP_KDF *kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    if (!kdf) {
        return std::nullopt;
    }
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if (!kctx) {
        return std::nullopt;
    }
    char digest[] = "SHA256";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<char *>(ikm.constData()), size_t(ikm.size())),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, const_cast<char *>(salt.constData()), size_t(salt.size())),
        OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, const_cast<char *>(info.constData()), size_t(info.size())),
        OSSL_PARAM_construct_end(),
    };
    QByteArray out(length, '\0');
    const bool ok = EVP_KDF_derive(kctx, reinterpret_cast<unsigned char *>(out.data()), size_t(length), params) == 1;
    EVP_KDF_CTX_free(kctx);
    if (!ok) {
        return std::nullopt;
    }
    return out;
}

namespace {
std::optional<QByteArray> aesCbc(bool encrypt, const QByteArray &key, const QByteArray &iv, const QByteArray &in)
{
    if (key.size() != 32 || iv.size() != 16 || in.size() % 16 != 0) {
        return std::nullopt;
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return std::nullopt;
    }
    QByteArray out(in.size() + 16, '\0');
    int len1 = 0;
    int len2 = 0;
    const auto *k = reinterpret_cast<const unsigned char *>(key.constData());
    const auto *v = reinterpret_cast<const unsigned char *>(iv.constData());
    bool ok = EVP_CipherInit_ex(ctx, EVP_aes_256_cbc(), nullptr, k, v, encrypt ? 1 : 0) == 1
        && EVP_CIPHER_CTX_set_padding(ctx, 0) == 1
        && EVP_CipherUpdate(ctx, reinterpret_cast<unsigned char *>(out.data()), &len1,
                            reinterpret_cast<const unsigned char *>(in.constData()), int(in.size())) == 1
        && EVP_CipherFinal_ex(ctx, reinterpret_cast<unsigned char *>(out.data()) + len1, &len2) == 1;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        return std::nullopt;
    }
    out.resize(len1 + len2);
    return out;
}
} // namespace

std::optional<QByteArray> aes256CbcEncrypt(const QByteArray &key, const QByteArray &iv, const QByteArray &plaintext)
{
    return aesCbc(true, key, iv, plaintext);
}

std::optional<QByteArray> aes256CbcDecrypt(const QByteArray &key, const QByteArray &iv, const QByteArray &ciphertext)
{
    return aesCbc(false, key, iv, ciphertext);
}

QByteArray hmacSha256(const QByteArray &key, const QByteArray &data)
{
    QByteArray out(32, '\0');
    size_t len = 0;
    if (!EVP_Q_mac(nullptr, "HMAC", nullptr, "SHA256", nullptr, key.constData(), size_t(key.size()),
                   reinterpret_cast<const unsigned char *>(data.constData()), size_t(data.size()),
                   reinterpret_cast<unsigned char *>(out.data()), size_t(out.size()), &len)
        || len != 32) {
        qFatal("HMAC-SHA-256 failed");
    }
    return out;
}

bool constantTimeEquals(const QByteArray &a, const QByteArray &b)
{
    return a.size() == b.size() && CRYPTO_memcmp(a.constData(), b.constData(), size_t(a.size())) == 0;
}

QByteArray randomBytes(int count)
{
    QByteArray out(count, '\0');
    if (RAND_bytes(reinterpret_cast<unsigned char *>(out.data()), count) != 1) {
        qFatal("RAND_bytes failed; refusing to continue without a CSPRNG");
    }
    return out;
}

QByteArray sha256(const QByteArray &data)
{
    return QCryptographicHash::hash(data, QCryptographicHash::Sha256);
}

} // namespace crypto
} // namespace kpasskey
