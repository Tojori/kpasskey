// SPDX-License-Identifier: LGPL-2.1-or-later
// CXF 1.0 export/import and the encrypted backup container.
#include "common/fakes.h"
#include "core/backup.h"
#include "core/cxf.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTest>

#include <openssl/evp.h>
#include <openssl/x509.h>

using namespace kpasskey;
using namespace kpasskey::test;

namespace {

QByteArray pkcs8Of(EVP_PKEY *pkey)
{
    PKCS8_PRIV_KEY_INFO *p8 = EVP_PKEY2PKCS8(pkey);
    const int len = i2d_PKCS8_PRIV_KEY_INFO(p8, nullptr);
    QByteArray out(len, '\0');
    auto *p = reinterpret_cast<unsigned char *>(out.data());
    i2d_PKCS8_PRIV_KEY_INFO(p8, &p);
    PKCS8_PRIV_KEY_INFO_free(p8);
    return out;
}

QJsonObject passkeyJson(const QByteArray &credId, const QString &rpId, const QByteArray &key)
{
    return QJsonObject{
        {QStringLiteral("type"), QStringLiteral("passkey")},
        {QStringLiteral("credentialId"), record::b64url(credId)},
        {QStringLiteral("rpId"), rpId},
        {QStringLiteral("username"), QStringLiteral("bob")},
        {QStringLiteral("userDisplayName"), QStringLiteral("Bob")},
        {QStringLiteral("userHandle"), record::b64url("bob-handle")},
        {QStringLiteral("key"), record::b64url(key)},
    };
}

QByteArray cxfDoc(const QJsonArray &credentials, int major = 1)
{
    QJsonObject item{{QStringLiteral("id"), record::b64url("item")},
                     {QStringLiteral("title"), QStringLiteral("Other provider item")},
                     {QStringLiteral("credentials"), credentials}};
    QJsonObject account{{QStringLiteral("id"), record::b64url("acc")},       {QStringLiteral("username"), QString()},
                        {QStringLiteral("email"), QString()},                {QStringLiteral("collections"), QJsonArray()},
                        {QStringLiteral("items"), QJsonArray{item}}};
    QJsonObject header{{QStringLiteral("version"), QJsonObject{{QStringLiteral("major"), major}, {QStringLiteral("minor"), 0}}},
                       {QStringLiteral("exporterRpId"), QStringLiteral("other.example")},
                       {QStringLiteral("exporterDisplayName"), QStringLiteral("Other")},
                       {QStringLiteral("timestamp"), 1791480000},
                       {QStringLiteral("accounts"), QJsonArray{account}}};
    return QJsonDocument(header).toJson();
}

// Fast but still within the accepted bounds.
const backup::KdfParams TestKdf{1, 19 * 1024, 1};

} // namespace

class TestBackup : public QObject
{
    Q_OBJECT

    MemoryStore store;
    FakePrompter prompter;
    FakeVerifier verifier;
    const QByteArray cdh = crypto::sha256("clientDataJSON");

    QByteArray create(Authenticator &a, const QString &rpId, const QByteArray &user)
    {
        const QByteArray r = run(a, ctap::MakeCredential, makeCredentialParams(rpId, user, cdh));
        return parseAuthData(body(r).value(2).toByteArray()).credentialId;
    }

private Q_SLOTS:
    void init()
    {
        store = MemoryStore();
    }

    void exportStructureFollowsCxf()
    {
        Authenticator a(&store, &prompter, &verifier, {});
        create(a, QStringLiteral("example.com"), "user-1");
        create(a, QStringLiteral("other.org"), "user-2");
        // a TPM credential and a legacy credential with a non-zero counter
        FakeHardwareKeyStore hw;
        Authenticator::Options o;
        o.hardwareKeys = &hw;
        o.createInHardware = true;
        Authenticator tpm(&store, &prompter, &verifier, o);
        create(tpm, QStringLiteral("bank.example"), "user-3");
        QList<CredentialRecord> all = store.findByRp(QStringLiteral("example.com")) + store.findByRp(QStringLiteral("other.org"))
            + store.findByRp(QStringLiteral("bank.example"));
        CredentialRecord legacy = all.first();
        legacy.credentialId = crypto::randomBytes(32);
        legacy.signCount = 7;
        all.append(legacy);

        cxf::ExportReport rep;
        const SecretBytes json = cxf::exportJson(all, &rep);
        QCOMPARE(rep.exported, 2);
        QCOMPARE(rep.skippedHardwareBound, 1);
        QCOMPARE(rep.skippedNonZeroCounter, 1);

        const QJsonObject h = QJsonDocument::fromJson(json.bytes()).object();
        QCOMPARE(h.value(QStringLiteral("version")).toObject().value(QStringLiteral("major")).toInt(), 1);
        QCOMPARE(h.value(QStringLiteral("version")).toObject().value(QStringLiteral("minor")).toInt(), 0);
        QVERIFY(h.value(QStringLiteral("exporterRpId")).isString());
        QVERIFY(h.value(QStringLiteral("exporterDisplayName")).isString());
        QVERIFY(h.value(QStringLiteral("timestamp")).isDouble());
        const QJsonObject acc = h.value(QStringLiteral("accounts")).toArray().first().toObject();
        for (const char *k : {"id", "username", "email"}) {
            QVERIFY2(acc.value(QLatin1String(k)).isString(), k);
        }
        QVERIFY(acc.value(QStringLiteral("collections")).isArray()); // required array, present even if empty
        QVERIFY(!acc.contains(QStringLiteral("extensions")));          // optional empty array must be absent
        const QJsonArray items = acc.value(QStringLiteral("items")).toArray();
        QCOMPARE(items.size(), 2);
        for (const QJsonValue &iv : items) {
            const QJsonObject item = iv.toObject();
            QVERIFY(item.value(QStringLiteral("id")).isString());
            QVERIFY(item.value(QStringLiteral("title")).isString());
            QVERIFY(!item.contains(QStringLiteral("tags")));
            const QJsonObject pk = item.value(QStringLiteral("credentials")).toArray().first().toObject();
            QCOMPARE(pk.value(QStringLiteral("type")).toString(), QStringLiteral("passkey"));
            for (const char *k : {"credentialId", "rpId", "username", "userDisplayName", "userHandle", "key"}) {
                QVERIFY2(pk.value(QLatin1String(k)).isString(), k);
            }
        }
    }

    void roundTripKeepsPasskeysUsable()
    {
        Authenticator a(&store, &prompter, &verifier, {});
        const QByteArray id = create(a, QStringLiteral("example.com"), "user-1");
        const auto original = store.find(QStringLiteral("example.com"), id);

        const SecretBytes json = cxf::exportJson(store.findByRp(QStringLiteral("example.com")), nullptr);
        const auto file = backup::encrypt(json, QStringLiteral("correct horse battery"), TestKdf);
        QVERIFY(file);
        const auto plain = backup::decrypt(*file, QStringLiteral("correct horse battery"));
        QVERIFY(plain);
        const cxf::ImportResult imported = cxf::importJson(plain->bytes());
        QVERIFY(imported.error.isEmpty());
        QCOMPARE(imported.records.size(), 1);

        // restore into an empty store (new machine) and sign in
        MemoryStore restored;
        QVERIFY(restored.put(imported.records.first()));
        Authenticator b(&restored, &prompter, &verifier, {});
        const QByteArray r = run(b, ctap::GetAssertion, getAssertionParams(QStringLiteral("example.com"), cdh, {id}));
        QCOMPARE(status(r), ctap::Ok);
        const QByteArray authData = body(r).value(2).toByteArray();
        QVERIFY(crypto::verify(original->publicKeyCose, authData + cdh, body(r).value(3).toByteArray()));
        QCOMPARE(parseAuthData(authData).counter, 0u);
        QVERIFY(parseAuthData(authData).flags & ctap::FlagBE);
        const auto rec = restored.find(QStringLiteral("example.com"), id);
        QCOMPARE(rec->userHandle, original->userHandle);
        QVERIFY(rec->backupEligible);
    }

    void importsForeignPasskeys()
    {
        // Ed25519 key with a 20 byte credential ID, as another provider might export
        EVP_PKEY *ed = EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519");
        const QByteArray edKey = pkcs8Of(ed);
        EVP_PKEY_free(ed);
        EVP_PKEY *rsa = EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", size_t(2048));
        const QByteArray rsaKey = pkcs8Of(rsa);
        EVP_PKEY_free(rsa);
        const QByteArray foreignId = crypto::randomBytes(20);

        QJsonArray creds{
            passkeyJson(foreignId, QStringLiteral("foreign.example"), edKey),
            passkeyJson(crypto::randomBytes(20), QStringLiteral("rsa.example"), rsaKey),       // RS256: unsupported
            passkeyJson(crypto::randomBytes(8), QStringLiteral("short.example"), edKey),       // ID too short
            passkeyJson(crypto::randomBytes(20), QStringLiteral("https://bad.example"), edKey), // invalid RP ID
            QJsonObject{{QStringLiteral("type"), QStringLiteral("basic-auth")}},               // other type
        };
        const cxf::ImportResult res = cxf::importJson(cxfDoc(creds));
        QVERIFY(res.error.isEmpty());
        QCOMPARE(res.records.size(), 1);
        QCOMPARE(res.skippedInvalid, 3);
        QCOMPARE(res.skippedOtherTypes, 1);
        QCOMPARE(res.records.first().coseAlg, int(ctap::EdDSA));

        QVERIFY(store.put(res.records.first()));
        Authenticator a(&store, &prompter, &verifier, {});
        const QByteArray r = run(a, ctap::GetAssertion, getAssertionParams(QStringLiteral("foreign.example"), cdh, {foreignId}));
        QCOMPARE(status(r), ctap::Ok);
        QVERIFY(crypto::verify(res.records.first().publicKeyCose, body(r).value(2).toByteArray() + cdh, body(r).value(3).toByteArray()));
    }

    void rejectsUnknownMajorVersion()
    {
        QVERIFY(!cxf::importJson(cxfDoc({}, 2)).error.isEmpty());
        QVERIFY(!cxf::importJson("not json").error.isEmpty());
    }

    void backupRejectsWrongPassphraseAndTampering()
    {
        const SecretBytes payload(QByteArray("{\"secret\":1}"));
        QVERIFY(!backup::encrypt(payload, QStringLiteral("short"), TestKdf)); // < 12 characters
        const auto file = backup::encrypt(payload, QStringLiteral("a long passphrase"), TestKdf);
        QVERIFY(file);
        QVERIFY(!file->contains("secret")); // nothing in clear

        backup::DecryptError err;
        QVERIFY(!backup::decrypt(*file, QStringLiteral("a long passphrasE"), &err));
        QCOMPARE(err, backup::DecryptError::WrongPassphraseOrCorrupt);

        // header fields are authenticated (AAD)
        QJsonObject h = QJsonDocument::fromJson(*file).object();
        h.insert(QStringLiteral("payload"), QStringLiteral("something else"));
        QVERIFY(!backup::decrypt(QJsonDocument(h).toJson(), QStringLiteral("a long passphrase"), &err));
        QCOMPARE(err, backup::DecryptError::WrongPassphraseOrCorrupt);

        // absurd KDF parameters are refused before any work is done
        h = QJsonDocument::fromJson(*file).object();
        QJsonObject kdf = h.value(QStringLiteral("kdf")).toObject();
        kdf.insert(QStringLiteral("memoryKiB"), qint64(64) * 1024 * 1024);
        h.insert(QStringLiteral("kdf"), kdf);
        QVERIFY(!backup::decrypt(QJsonDocument(h).toJson(), QStringLiteral("a long passphrase"), &err));
        QCOMPARE(err, backup::DecryptError::BadParameters);

        QVERIFY(!backup::decrypt("{\"format\":\"zip\"}", QStringLiteral("a long passphrase"), &err));
        QCOMPARE(err, backup::DecryptError::NotABackup);

        const auto ok = backup::decrypt(*file, QStringLiteral("a long passphrase"), &err);
        QVERIFY(ok);
        QCOMPARE(ok->bytes(), payload.bytes());
    }
};

QTEST_GUILESS_MAIN(TestBackup)
#include "test_backup.moc"
