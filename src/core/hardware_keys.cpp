// SPDX-License-Identifier: LGPL-2.1-or-later
#include "hardware_keys.h"

#include "ctap_constants.h"

#include <QCborMap>
#include <QCborValue>

#include <cstring>
#include <tss2/tss2_mu.h>

namespace kpasskey::tpmblob {

namespace {
// Attributes every kpasskey TPM key must have (and those it must not have).
constexpr TPMA_OBJECT Required = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN
    | TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_SIGN_ENCRYPT;
constexpr TPMA_OBJECT Forbidden = TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT;
} // namespace

std::optional<QByteArray> publicKeyCose(const QByteArray &blob)
{
    const auto *buf = reinterpret_cast<const uint8_t *>(blob.constData());
    const size_t size = size_t(blob.size());
    size_t offset = 0;
    TPM2B_PUBLIC pub;
    TPM2B_PRIVATE priv;
    std::memset(&pub, 0, sizeof(pub));
    std::memset(&priv, 0, sizeof(priv));
    if (Tss2_MU_TPM2B_PUBLIC_Unmarshal(buf, size, &offset, &pub) != TSS2_RC_SUCCESS
        || Tss2_MU_TPM2B_PRIVATE_Unmarshal(buf, size, &offset, &priv) != TSS2_RC_SUCCESS || offset != size
        || priv.size == 0) {
        return std::nullopt;
    }
    const TPMT_PUBLIC &p = pub.publicArea;
    if (p.type != TPM2_ALG_ECC || p.nameAlg != TPM2_ALG_SHA256 || (p.objectAttributes & Required) != Required
        || (p.objectAttributes & Forbidden) != 0 || p.parameters.eccDetail.curveID != TPM2_ECC_NIST_P256
        || p.parameters.eccDetail.scheme.scheme != TPM2_ALG_ECDSA
        || p.parameters.eccDetail.scheme.details.ecdsa.hashAlg != TPM2_ALG_SHA256) {
        return std::nullopt;
    }
    const auto &x = p.unique.ecc.x;
    const auto &y = p.unique.ecc.y;
    if (x.size == 0 || x.size > 32 || y.size == 0 || y.size > 32) {
        return std::nullopt;
    }
    QByteArray xb(32 - x.size, '\0'), yb(32 - y.size, '\0');
    xb += QByteArray(reinterpret_cast<const char *>(x.buffer), x.size);
    yb += QByteArray(reinterpret_cast<const char *>(y.buffer), y.size);

    QCborMap cose; // canonical order 1, 3, -1, -2, -3
    cose.insert(1, 2);
    cose.insert(3, ctap::ES256);
    cose.insert(-1, 1);
    cose.insert(-2, xb);
    cose.insert(-3, yb);
    return QCborValue(cose).toCbor();
}

std::optional<QByteArray> make(const QByteArray &x, const QByteArray &y, const QByteArray &privatePart)
{
    if (x.size() != 32 || y.size() != 32 || privatePart.isEmpty() || privatePart.size() > qsizetype(sizeof(TPM2B_PRIVATE::buffer))) {
        return std::nullopt;
    }
    TPM2B_PUBLIC pub;
    std::memset(&pub, 0, sizeof(pub));
    pub.publicArea.type = TPM2_ALG_ECC;
    pub.publicArea.nameAlg = TPM2_ALG_SHA256;
    pub.publicArea.objectAttributes = Required;
    pub.publicArea.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_NULL;
    pub.publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG_ECDSA;
    pub.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg = TPM2_ALG_SHA256;
    pub.publicArea.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
    pub.publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
    pub.publicArea.unique.ecc.x.size = 32;
    std::memcpy(pub.publicArea.unique.ecc.x.buffer, x.constData(), 32);
    pub.publicArea.unique.ecc.y.size = 32;
    std::memcpy(pub.publicArea.unique.ecc.y.buffer, y.constData(), 32);
    TPM2B_PRIVATE priv;
    std::memset(&priv, 0, sizeof(priv));
    priv.size = uint16_t(privatePart.size());
    std::memcpy(priv.buffer, privatePart.constData(), size_t(privatePart.size()));

    QByteArray out(int(sizeof(TPM2B_PUBLIC) + sizeof(TPM2B_PRIVATE)), '\0');
    size_t offset = 0;
    auto *buf = reinterpret_cast<uint8_t *>(out.data());
    if (Tss2_MU_TPM2B_PUBLIC_Marshal(&pub, buf, size_t(out.size()), &offset) != TSS2_RC_SUCCESS
        || Tss2_MU_TPM2B_PRIVATE_Marshal(&priv, buf, size_t(out.size()), &offset) != TSS2_RC_SUCCESS) {
        return std::nullopt;
    }
    out.resize(qsizetype(offset));
    return out;
}

} // namespace kpasskey::tpmblob
