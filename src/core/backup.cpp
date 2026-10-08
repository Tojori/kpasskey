// SPDX-License-Identifier: LGPL-2.1-or-later
#include "backup.h"

#include "credential.h"

#include <QJsonDocument>
#include <QJsonObject>

namespace kpasskey::backup {

namespace {

// Limits accepted on import, so that a crafted file cannot make us allocate
// gigabytes or spin for minutes; and lower bounds per OWASP Argon2id guidance.
constexpr quint32 MaxIterations = 10;
constexpr quint32 MaxMemoryKiB = 1024 * 1024; // 1 GiB
constexpr quint32 MinMemoryKiB = 19 * 1024;
constexpr quint32 MaxLanes = 8;

// Everything except the ciphertext is authenticated as AAD. QJsonObject keeps
// keys sorted, so this serialisation is canonical.
QByteArray aadOf(QJsonObject header)
{
    header.remove(QStringLiteral("ciphertext"));
    return QJsonDocument(header).toJson(QJsonDocument::Compact);
}

std::optional<SecretBytes> deriveKey(const QString &passphrase, const QByteArray &salt, const KdfParams &p)
{
    QByteArray pw = passphrase.normalized(QString::NormalizationForm_C).toUtf8();
    auto key = crypto::argon2id(pw, salt, p.iterations, p.memoryKiB, p.lanes, 32);
    SecretBytes wipe(std::move(pw)); // wiped on scope exit
    return key;
}

} // namespace

std::optional<QByteArray> encrypt(const SecretBytes &cxfJson, const QString &passphrase, KdfParams params)
{
    if (passphrase.size() < MinPassphraseLength) {
        return std::nullopt;
    }
    const QByteArray salt = crypto::randomBytes(16);
    const QByteArray nonce = crypto::randomBytes(12);
    auto key = deriveKey(passphrase, salt, params);
    if (!key) {
        return std::nullopt;
    }
    QJsonObject header;
    header.insert(QStringLiteral("format"), QLatin1String(FormatId));
    header.insert(QStringLiteral("version"), FormatVersion);
    header.insert(QStringLiteral("payload"), QStringLiteral("application/fido.cxf+json; version=1.0"));
    header.insert(QStringLiteral("kdf"), QJsonObject{
                                             {QStringLiteral("alg"), QStringLiteral("argon2id")},
                                             {QStringLiteral("salt"), record::b64url(salt)},
                                             {QStringLiteral("iterations"), qint64(params.iterations)},
                                             {QStringLiteral("memoryKiB"), qint64(params.memoryKiB)},
                                             {QStringLiteral("lanes"), qint64(params.lanes)},
                                         });
    header.insert(QStringLiteral("cipher"), QJsonObject{
                                                {QStringLiteral("alg"), QStringLiteral("A256GCM")},
                                                {QStringLiteral("nonce"), record::b64url(nonce)},
                                            });
    auto ct = crypto::aes256GcmEncrypt(key->bytes(), nonce, cxfJson.bytes(), aadOf(header));
    if (!ct) {
        return std::nullopt;
    }
    header.insert(QStringLiteral("ciphertext"), record::b64url(*ct));
    return QJsonDocument(header).toJson(QJsonDocument::Indented);
}

std::optional<SecretBytes> decrypt(const QByteArray &file, const QString &passphrase, DecryptError *error)
{
    auto fail = [error](DecryptError e) -> std::optional<SecretBytes> {
        if (error) {
            *error = e;
        }
        return std::nullopt;
    };
    if (error) {
        *error = DecryptError::None;
    }
    QJsonParseError perr;
    const QJsonDocument doc = QJsonDocument::fromJson(file, &perr);
    if (perr.error != QJsonParseError::NoError || !doc.isObject()
        || doc.object().value(QLatin1String("format")).toString() != QLatin1String(FormatId)) {
        return fail(DecryptError::NotABackup);
    }
    const QJsonObject header = doc.object();
    if (header.value(QLatin1String("version")).toInt() != FormatVersion) {
        return fail(DecryptError::UnsupportedVersion);
    }
    const QJsonObject kdf = header.value(QLatin1String("kdf")).toObject();
    const QJsonObject cipher = header.value(QLatin1String("cipher")).toObject();
    const auto salt = record::fromB64url(kdf.value(QLatin1String("salt")).toString());
    const auto nonce = record::fromB64url(cipher.value(QLatin1String("nonce")).toString());
    const auto ct = record::fromB64url(header.value(QLatin1String("ciphertext")).toString());
    KdfParams p;
    p.iterations = quint32(kdf.value(QLatin1String("iterations")).toInteger());
    p.memoryKiB = quint32(kdf.value(QLatin1String("memoryKiB")).toInteger());
    p.lanes = quint32(kdf.value(QLatin1String("lanes")).toInteger());
    if (kdf.value(QLatin1String("alg")).toString() != QLatin1String("argon2id")
        || cipher.value(QLatin1String("alg")).toString() != QLatin1String("A256GCM") || !salt || salt->size() < 16
        || !nonce || nonce->size() != 12 || !ct || p.iterations < 1 || p.iterations > MaxIterations
        || p.memoryKiB < MinMemoryKiB || p.memoryKiB > MaxMemoryKiB || p.lanes < 1 || p.lanes > MaxLanes) {
        return fail(DecryptError::BadParameters);
    }
    auto key = deriveKey(passphrase, *salt, p);
    if (!key) {
        return fail(DecryptError::BadParameters);
    }
    auto plain = crypto::aes256GcmDecrypt(key->bytes(), *nonce, *ct, aadOf(header));
    if (!plain) {
        return fail(DecryptError::WrongPassphraseOrCorrupt);
    }
    return plain;
}

} // namespace kpasskey::backup
