// SPDX-License-Identifier: LGPL-2.1-or-later
#include "cxf.h"

#include "ctap_constants.h"

#include <QDateTime>
#include <QTimeZone>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>

namespace kpasskey::cxf {

namespace {

QString b64(const QByteArray &d)
{
    return record::b64url(d);
}

// Detects the COSE algorithm of a PKCS#8 key we can use.
int algOf(const SecretBytes &pkcs8, QByteArray *cose)
{
    for (int alg : {int(ctap::ES256), int(ctap::EdDSA)}) {
        if (auto c = crypto::publicKeyCoseFromPrivate(pkcs8, alg)) {
            *cose = *c;
            return alg;
        }
    }
    return 0;
}

std::optional<QByteArray> requiredB64(const QJsonObject &o, const char *key)
{
    const QJsonValue v = o.value(QLatin1String(key));
    return v.isString() ? record::fromB64url(v.toString()) : std::nullopt;
}

} // namespace

SecretBytes exportJson(const QList<CredentialRecord> &records, ExportReport *report)
{
    ExportReport rep;
    QJsonArray items;
    for (const CredentialRecord &r : records) {
        if (r.keyProtection != protection::Wallet) {
            ++rep.skippedHardwareBound;
            continue;
        }
        if (r.signCount != 0) {
            ++rep.skippedNonZeroCounter;
            continue;
        }
        QJsonObject passkey; // §3.3.12
        passkey.insert(QStringLiteral("type"), QStringLiteral("passkey"));
        passkey.insert(QStringLiteral("credentialId"), b64(r.credentialId));
        passkey.insert(QStringLiteral("rpId"), r.rpId);
        passkey.insert(QStringLiteral("username"), r.userName);
        passkey.insert(QStringLiteral("userDisplayName"), r.userDisplayName);
        passkey.insert(QStringLiteral("userHandle"), b64(r.userHandle));
        passkey.insert(QStringLiteral("key"), b64(r.privateKeyPkcs8.bytes())); // PKCS#8 DER

        QJsonObject item; // §3.2.3; optional empty arrays are omitted (§2.1.2)
        item.insert(QStringLiteral("id"), b64(crypto::randomBytes(16)));
        if (r.created.isValid()) {
            item.insert(QStringLiteral("creationAt"), r.created.toSecsSinceEpoch());
        }
        const QDateTime modified = r.lastUsed.isValid() ? r.lastUsed : r.created;
        if (modified.isValid()) {
            item.insert(QStringLiteral("modifiedAt"), modified.toSecsSinceEpoch());
        }
        item.insert(QStringLiteral("title"), r.rpName.isEmpty() ? r.rpId : r.rpName);
        if (!r.userName.isEmpty()) {
            item.insert(QStringLiteral("subtitle"), r.userName);
        }
        item.insert(QStringLiteral("credentials"), QJsonArray{passkey});
        items.append(item);
        ++rep.exported;
    }

    QJsonObject account; // §3.2.1
    account.insert(QStringLiteral("id"), b64(crypto::randomBytes(16)));
    account.insert(QStringLiteral("username"), QString());
    account.insert(QStringLiteral("email"), QString());
    account.insert(QStringLiteral("collections"), QJsonArray());
    account.insert(QStringLiteral("items"), items);

    QJsonObject header; // §3.1
    header.insert(QStringLiteral("version"), QJsonObject{{QStringLiteral("major"), VersionMajor}, {QStringLiteral("minor"), VersionMinor}});
    header.insert(QStringLiteral("exporterRpId"), QLatin1String(ExporterRpId));
    header.insert(QStringLiteral("exporterDisplayName"), QLatin1String(ExporterDisplayName));
    header.insert(QStringLiteral("timestamp"), QDateTime::currentSecsSinceEpoch());
    header.insert(QStringLiteral("accounts"), QJsonArray{account});

    if (report) {
        *report = rep;
    }
    return SecretBytes(QJsonDocument(header).toJson(QJsonDocument::Compact));
}

ImportResult importJson(const QByteArray &json)
{
    ImportResult result;
    QJsonParseError perr;
    const QJsonDocument doc = QJsonDocument::fromJson(json, &perr);
    if (perr.error != QJsonParseError::NoError || !doc.isObject()) {
        result.error = QStringLiteral("not a JSON document");
        return result;
    }
    const QJsonObject header = doc.object();
    const QJsonObject version = header.value(QLatin1String("version")).toObject();
    if (!version.value(QLatin1String("major")).isDouble() || version.value(QLatin1String("major")).toInt() != VersionMajor) {
        result.error = QStringLiteral("unsupported CXF version");
        return result;
    }
    const QJsonValue accounts = header.value(QLatin1String("accounts"));
    if (!accounts.isArray()) {
        result.error = QStringLiteral("missing accounts");
        return result;
    }

    const QDateTime now = QDateTime::currentDateTimeUtc();
    for (const QJsonValue &acc : accounts.toArray()) {
        for (const QJsonValue &itemValue : acc.toObject().value(QLatin1String("items")).toArray()) {
            const QJsonObject item = itemValue.toObject();
            const QJsonValue created = item.value(QLatin1String("creationAt"));
            for (const QJsonValue &credValue : item.value(QLatin1String("credentials")).toArray()) {
                const QJsonObject c = credValue.toObject();
                if (c.value(QLatin1String("type")).toString() != QLatin1String("passkey")) {
                    ++result.skippedOtherTypes; // unknown/unsupported types are ignored (§2.1.1)
                    continue;
                }
                const auto credId = requiredB64(c, "credentialId");
                const auto userHandle = requiredB64(c, "userHandle");
                const auto key = requiredB64(c, "key");
                const QJsonValue rpId = c.value(QLatin1String("rpId"));
                if (!credId || !userHandle || !key || !rpId.isString() || !isPlausibleRpId(rpId.toString())
                    || credId->size() < ctap::MinCredentialIdSize || credId->size() > ctap::MaxCredentialIdSize
                    || userHandle->isEmpty() || userHandle->size() > ctap::MaxUserIdSize) {
                    ++result.skippedInvalid;
                    continue;
                }
                CredentialRecord r;
                r.privateKeyPkcs8 = SecretBytes(*key);
                r.coseAlg = algOf(r.privateKeyPkcs8, &r.publicKeyCose);
                if (r.coseAlg == 0) {
                    ++result.skippedInvalid; // e.g. RS256 or a corrupt key
                    continue;
                }
                r.credentialId = *credId;
                r.rpId = rpId.toString();
                r.rpName = item.value(QLatin1String("title")).toString().left(64);
                r.userHandle = *userHandle;
                r.userName = c.value(QLatin1String("username")).toString().left(64);
                r.userDisplayName = c.value(QLatin1String("userDisplayName")).toString().left(64);
                r.keyProtection = protection::Wallet;
                r.signCount = 0;          // CXF: importers MUST set 0 ...
                r.backupEligible = true;  // ... and MUST NOT increment it afterwards
                r.discoverable = true;
                r.uvAtCreation = false;
                r.created = created.isDouble() ? QDateTime::fromSecsSinceEpoch(qint64(created.toDouble()), QTimeZone::UTC) : now;
                result.records.append(std::move(r));
            }
        }
    }
    return result;
}

} // namespace kpasskey::cxf
