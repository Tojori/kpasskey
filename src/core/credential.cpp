// SPDX-License-Identifier: LGPL-2.1-or-later
#include "credential.h"

#include "ctap_constants.h"
#include "hardware_keys.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>

namespace kpasskey {

QString CredentialRecord::credentialIdB64() const
{
    return record::b64url(credentialId);
}

CredentialMetadata metadataOf(const CredentialRecord &r)
{
    return {r.credentialIdB64(), r.rpId, r.userName, r.userDisplayName,
            r.created.toSecsSinceEpoch(), r.lastUsed.isValid() ? r.lastUsed.toSecsSinceEpoch() : 0, r.keyProtection};
}

bool isPlausibleRpId(const QString &rpId)
{
    if (rpId.isEmpty() || rpId.size() > ctap::MaxRpIdLength) {
        return false;
    }
    // Lower-case LDH labels separated by dots, e.g. "login.example.com" or "localhost".
    static const QRegularExpression re(QStringLiteral(
        R"(^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$)"));
    return re.match(rpId).hasMatch();
}

namespace record {
namespace {

constexpr auto kSchema = "schema";
constexpr auto kType = "type";
constexpr auto kCredId = "credential_id";
constexpr auto kRpId = "rp_id";
constexpr auto kRpName = "rp_name";
constexpr auto kUserHandle = "user_handle";
constexpr auto kUserName = "user_name";
constexpr auto kUserDisplayName = "user_display_name";
constexpr auto kAlg = "alg";
constexpr auto kPublicKey = "public_key_cose";
constexpr auto kPrivateKey = "private_key";
constexpr auto kPkFormat = "format";
constexpr auto kPkProtection = "protection";
constexpr auto kPkData = "data";
constexpr auto kSignCount = "sign_count";
constexpr auto kDiscoverable = "discoverable";
constexpr auto kUvAtCreation = "uv_at_creation";
constexpr auto kBackupEligible = "backup_eligible";
constexpr auto kCreated = "created";
constexpr auto kLastUsed = "last_used";

constexpr auto kTypeValue = "webauthn.public-key";
constexpr auto kFormatPkcs8 = "pkcs8-der";
constexpr auto kFormatTpmBlob = "tpm2b-public-private";

std::optional<QByteArray> requireB64(const QJsonObject &o, const char *key)
{
    const QJsonValue v = o.value(QLatin1String(key));
    return v.isString() ? fromB64url(v.toString()) : std::nullopt;
}

} // namespace

QString b64url(const QByteArray &data)
{
    return QString::fromLatin1(data.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals));
}

std::optional<QByteArray> fromB64url(const QString &s)
{
    auto r = QByteArray::fromBase64Encoding(s.toLatin1(),
                                            QByteArray::Base64UrlEncoding | QByteArray::AbortOnBase64DecodingErrors);
    if (!r) {
        return std::nullopt;
    }
    return *r;
}

QString entryKey(const QString &rpId, const QByteArray &credentialId)
{
    return rpId + QLatin1Char('/') + b64url(credentialId);
}

QString encode(const CredentialRecord &r)
{
    const bool tpm = r.keyProtection == protection::Tpm2;
    QJsonObject pk;
    pk.insert(QLatin1String(kPkFormat), QLatin1String(tpm ? kFormatTpmBlob : kFormatPkcs8));
    pk.insert(QLatin1String(kPkProtection), r.keyProtection);
    pk.insert(QLatin1String(kPkData), b64url(r.privateKeyPkcs8.bytes()));

    QJsonObject o;
    // Wallet-protected records stay at v1 so that older builds keep reading them;
    // TPM records need v2 (older builds skip them without touching them).
    o.insert(QLatin1String(kSchema), tpm ? 2 : 1);
    o.insert(QLatin1String(kType), QLatin1String(kTypeValue));
    o.insert(QLatin1String(kCredId), b64url(r.credentialId));
    o.insert(QLatin1String(kRpId), r.rpId);
    o.insert(QLatin1String(kRpName), r.rpName);
    o.insert(QLatin1String(kUserHandle), b64url(r.userHandle));
    o.insert(QLatin1String(kUserName), r.userName);
    o.insert(QLatin1String(kUserDisplayName), r.userDisplayName);
    o.insert(QLatin1String(kAlg), r.coseAlg);
    o.insert(QLatin1String(kPublicKey), b64url(r.publicKeyCose));
    o.insert(QLatin1String(kPrivateKey), pk);
    o.insert(QLatin1String(kSignCount), qint64(r.signCount));
    o.insert(QLatin1String(kDiscoverable), r.discoverable);
    o.insert(QLatin1String(kUvAtCreation), r.uvAtCreation);
    o.insert(QLatin1String(kBackupEligible), false);
    o.insert(QLatin1String(kCreated), r.created.toUTC().toString(Qt::ISODate));
    if (r.lastUsed.isValid()) {
        o.insert(QLatin1String(kLastUsed), r.lastUsed.toUTC().toString(Qt::ISODate));
    }
    return QString::fromUtf8(QJsonDocument(o).toJson(QJsonDocument::Compact));
}

std::optional<CredentialRecord> decode(const QString &key, const QString &json, DecodeError *error)
{
    auto fail = [error](DecodeError e) -> std::optional<CredentialRecord> {
        if (error) {
            *error = e;
        }
        return std::nullopt;
    };
    if (error) {
        *error = DecodeError::None;
    }

    QJsonParseError perr;
    const QJsonDocument doc = QJsonDocument::fromJson(json.toUtf8(), &perr);
    if (perr.error != QJsonParseError::NoError || !doc.isObject()) {
        return fail(DecodeError::Malformed);
    }
    const QJsonObject o = doc.object();

    const QJsonValue schema = o.value(QLatin1String(kSchema));
    if (!schema.isDouble()) {
        return fail(DecodeError::Malformed);
    }
    if (schema.toInt() > CredentialSchemaVersion) {
        return fail(DecodeError::UnsupportedSchema);
    }
    // Migration hook: older schemas would be upgraded here (v1 needs none).
    if (schema.toInt() < 1 || o.value(QLatin1String(kType)).toString() != QLatin1String(kTypeValue)) {
        return fail(DecodeError::Malformed);
    }

    CredentialRecord r;
    auto credId = requireB64(o, kCredId);
    auto userHandle = requireB64(o, kUserHandle);
    auto pub = requireB64(o, kPublicKey);
    const QJsonObject pk = o.value(QLatin1String(kPrivateKey)).toObject();
    auto priv = requireB64(pk, kPkData);
    const QJsonValue rpId = o.value(QLatin1String(kRpId));
    const QJsonValue alg = o.value(QLatin1String(kAlg));
    const QJsonValue count = o.value(QLatin1String(kSignCount));
    const QString prot = pk.value(QLatin1String(kPkProtection)).toString();
    const QString format = pk.value(QLatin1String(kPkFormat)).toString();
    const bool walletKey = prot == protection::Wallet && format == QLatin1String(kFormatPkcs8);
    const bool tpmKey = prot == protection::Tpm2 && format == QLatin1String(kFormatTpmBlob) && schema.toInt() >= 2;
    if (!credId || !userHandle || !pub || !priv || !rpId.isString() || !alg.isDouble() || !count.isDouble()
        || !(walletKey || tpmKey)) {
        return fail(DecodeError::Malformed);
    }
    const double c = count.toDouble();
    if (c < 0 || c > 4294967295.0 || credId->size() != ctap::CredentialIdSize || userHandle->isEmpty()
        || userHandle->size() > ctap::MaxUserIdSize || !crypto::isSupportedAlg(alg.toInt())) {
        return fail(DecodeError::Malformed);
    }

    r.credentialId = *credId;
    r.rpId = rpId.toString();
    r.rpName = o.value(QLatin1String(kRpName)).toString();
    r.userHandle = *userHandle;
    r.userName = o.value(QLatin1String(kUserName)).toString();
    r.userDisplayName = o.value(QLatin1String(kUserDisplayName)).toString();
    r.coseAlg = alg.toInt();
    r.publicKeyCose = *pub;
    r.privateKeyPkcs8 = SecretBytes(std::move(*priv));
    r.keyProtection = prot;
    r.signCount = quint32(c);
    r.discoverable = o.value(QLatin1String(kDiscoverable)).toBool(true);
    r.uvAtCreation = o.value(QLatin1String(kUvAtCreation)).toBool(false);
    r.created = QDateTime::fromString(o.value(QLatin1String(kCreated)).toString(), Qt::ISODate);
    r.lastUsed = QDateTime::fromString(o.value(QLatin1String(kLastUsed)).toString(), Qt::ISODate);

    // The record must belong to the entry it was read from (prevents moving a
    // record to another RP by renaming entries) ...
    if (!isPlausibleRpId(r.rpId) || key != entryKey(r.rpId, r.credentialId)) {
        return fail(DecodeError::Inconsistent);
    }
    // ... and the stored public key must match the private key (for TPM keys:
    // the public area of the key blob).
    const auto derived = tpmKey ? (r.coseAlg == ctap::ES256 ? tpmblob::publicKeyCose(r.privateKeyPkcs8.bytes()) : std::nullopt)
                                : crypto::publicKeyCoseFromPrivate(r.privateKeyPkcs8, r.coseAlg);
    if (!derived || *derived != r.publicKeyCose) {
        return fail(DecodeError::Inconsistent);
    }
    return r;
}

} // namespace record
} // namespace kpasskey
