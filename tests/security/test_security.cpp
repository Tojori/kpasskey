// SPDX-License-Identifier: LGPL-2.1-or-later
// Negative / adversarial tests. Origin and challenge checks are performed by
// the browser and the relying party (the authenticator never sees them); the
// tests here verify the properties the authenticator is responsible for:
// RP scoping, binding of signatures to clientDataHash and rpIdHash, integrity
// of stored records, fail-closed user verification and request isolation.
#include "common/fakes.h"

#include <QSignalSpy>
#include <QTest>

using namespace kpasskey;
using namespace kpasskey::test;

class TestSecurity : public QObject
{
    Q_OBJECT

    MemoryStore store;
    FakePrompter prompter;
    FakeVerifier verifier;
    std::unique_ptr<Authenticator> auth;
    const QByteArray cdh = crypto::sha256("clientDataJSON");

    QByteArray create(const QString &rpId, const QByteArray &user = "user-1")
    {
        const QByteArray r = run(*auth, ctap::MakeCredential, makeCredentialParams(rpId, user, cdh));
        return parseAuthData(body(r).value(2).toByteArray()).credentialId;
    }

private Q_SLOTS:
    void init()
    {
        store = MemoryStore();
        prompter = FakePrompter();
        verifier = FakeVerifier();
        auth = std::make_unique<Authenticator>(&store, &prompter, &verifier, Authenticator::Options{});
    }

    // --- wrong RP ID / RP ID manipulation ---------------------------------
    void credentialIsScopedToItsRpId()
    {
        const QByteArray id = create(QStringLiteral("bank.example"));
        // A phishing origin can only ever ask for its own rpId (browser rule);
        // even when it knows the credential ID, the lookup is rpId-scoped.
        QCOMPARE(status(run(*auth, ctap::GetAssertion, getAssertionParams(QStringLiteral("bank-example.evil"), cdh, {id}))),
                 ctap::ErrNoCredentials);
        QCOMPARE(status(run(*auth, ctap::GetAssertion, getAssertionParams(QStringLiteral("evil"), cdh))),
                 ctap::ErrNoCredentials);
    }

    void signatureBindsRpIdHash()
    {
        const QByteArray id = create(QStringLiteral("bank.example"));
        const auto rec = store.find(QStringLiteral("bank.example"), id);
        const QByteArray r = run(*auth, ctap::GetAssertion, getAssertionParams(QStringLiteral("bank.example"), cdh));
        QByteArray authData = body(r).value(2).toByteArray();
        const QByteArray sig = body(r).value(3).toByteArray();
        QVERIFY(crypto::verify(rec->publicKeyCose, authData + cdh, sig));
        authData.replace(0, 32, crypto::sha256("evil.example"));
        QVERIFY(!crypto::verify(rec->publicKeyCose, authData + cdh, sig));
    }

    void implausibleRpIdsRejected_data()
    {
        QTest::addColumn<QString>("rpId");
        QTest::newRow("empty") << QString();
        QTest::newRow("scheme") << QStringLiteral("https://example.com");
        QTest::newRow("port") << QStringLiteral("example.com:443");
        QTest::newRow("upper") << QStringLiteral("Example.com");
        QTest::newRow("space") << QStringLiteral("exa mple.com");
        QTest::newRow("unicode") << QStringLiteral("bänk.example");
        QTest::newRow("slash") << QStringLiteral("example.com/x");
        QTest::newRow("too-long") << QString(300, QLatin1Char('a'));
    }
    void implausibleRpIdsRejected()
    {
        QFETCH(QString, rpId);
        QCOMPARE(status(run(*auth, ctap::MakeCredential, makeCredentialParams(rpId, "u", cdh))), ctap::ErrInvalidParameter);
    }

    // --- wrong challenge / replay ------------------------------------------
    void signatureBindsClientDataHash()
    {
        const QByteArray id = create(QStringLiteral("example.com"));
        const auto rec = store.find(QStringLiteral("example.com"), id);
        const QByteArray r = run(*auth, ctap::GetAssertion, getAssertionParams(QStringLiteral("example.com"), cdh));
        const QByteArray authData = body(r).value(2).toByteArray();
        const QByteArray sig = body(r).value(3).toByteArray();
        // An RP checking a different challenge (different clientDataHash) rejects it.
        QVERIFY(!crypto::verify(rec->publicKeyCose, authData + crypto::sha256("other challenge"), sig));
    }

    void replayIsDetectableViaCounter()
    {
        create(QStringLiteral("example.com"));
        const QByteArray r1 = run(*auth, ctap::GetAssertion, getAssertionParams(QStringLiteral("example.com"), cdh));
        const QByteArray r2 = run(*auth, ctap::GetAssertion, getAssertionParams(QStringLiteral("example.com"), cdh));
        const quint32 c1 = parseAuthData(body(r1).value(2).toByteArray()).counter;
        const quint32 c2 = parseAuthData(body(r2).value(2).toByteArray()).counter;
        QVERIFY(c2 > c1); // a replayed r1 carries a stale counter
        QVERIFY(body(r1).value(3).toByteArray() != body(r2).value(3).toByteArray());
    }

    void noSignatureWhenCounterCannotBePersisted()
    {
        const QByteArray id = create(QStringLiteral("example.com"));
        store.setFailWrites(true);
        const QByteArray r = run(*auth, ctap::GetAssertion, getAssertionParams(QStringLiteral("example.com"), cdh));
        QCOMPARE(status(r), ctap::ErrOther);
        QCOMPARE(r.size(), 1); // no signature leaves the authenticator
        store.setFailWrites(false);
        QCOMPARE(store.find(QStringLiteral("example.com"), id)->signCount, 0u);
    }

    // --- manipulated credential IDs / corrupted wallet data ------------------
    void manipulatedCredentialIds()
    {
        const QByteArray id = create(QStringLiteral("example.com"));
        QByteArray flipped = id;
        flipped[0] = char(flipped.at(0) ^ 0x01);
        QCOMPARE(status(run(*auth, ctap::GetAssertion, getAssertionParams(QStringLiteral("example.com"), cdh, {flipped}))),
                 ctap::ErrNoCredentials);
        QCOMPARE(status(run(*auth, ctap::GetAssertion, getAssertionParams(QStringLiteral("example.com"), cdh, {id.left(16)}))),
                 ctap::ErrNoCredentials);
        QCOMPARE(status(run(*auth, ctap::GetAssertion, getAssertionParams(QStringLiteral("example.com"), cdh, {QByteArray(2000, 'A')}))),
                 ctap::ErrNoCredentials);
    }

    void corruptedRecordIsIgnored()
    {
        const QByteArray id = create(QStringLiteral("example.com"));
        const QString key = record::entryKey(QStringLiteral("example.com"), id);
        store.rawEntries()[key] = QStringLiteral("{not json");
        QCOMPARE(status(run(*auth, ctap::GetAssertion, getAssertionParams(QStringLiteral("example.com"), cdh))),
                 ctap::ErrNoCredentials);
    }

    void recordMovedToOtherRpIsRejected()
    {
        const QByteArray id = create(QStringLiteral("bank.example"));
        // Attacker with wallet write access renames the entry to evil.example
        const QString json = store.rawEntries().take(record::entryKey(QStringLiteral("bank.example"), id));
        store.rawEntries().insert(record::entryKey(QStringLiteral("evil.example"), id), json);
        QCOMPARE(status(run(*auth, ctap::GetAssertion, getAssertionParams(QStringLiteral("evil.example"), cdh))),
                 ctap::ErrNoCredentials);
    }

    void swappedPublicKeyIsRejected()
    {
        const QByteArray a = create(QStringLiteral("example.com"), "user-a");
        const QByteArray b = create(QStringLiteral("example.com"), "user-b");
        const QString keyA = record::entryKey(QStringLiteral("example.com"), a);
        const QString keyB = record::entryKey(QStringLiteral("example.com"), b);
        auto recA = record::decode(keyA, store.rawEntries().value(keyA));
        auto recB = record::decode(keyB, store.rawEntries().value(keyB));
        QVERIFY(recA && recB);
        recA->publicKeyCose = recB->publicKeyCose;
        store.rawEntries()[keyA] = record::encode(*recA);
        record::DecodeError err;
        QVERIFY(!record::decode(keyA, store.rawEntries().value(keyA), &err));
        QCOMPARE(err, record::DecodeError::Inconsistent);
    }

    void tamperedTpmBlobIsRejected()
    {
        FakeHardwareKeyStore hw;
        Authenticator::Options o;
        o.hardwareKeys = &hw;
        o.createInHardware = true;
        Authenticator a(&store, &prompter, &verifier, o);
        const QByteArray r1 = run(a, ctap::MakeCredential, makeCredentialParams(QStringLiteral("example.com"), "user-a", cdh));
        const QByteArray r2 = run(a, ctap::MakeCredential, makeCredentialParams(QStringLiteral("example.com"), "user-b", cdh));
        const QByteArray id1 = parseAuthData(body(r1).value(2).toByteArray()).credentialId;
        const QByteArray id2 = parseAuthData(body(r2).value(2).toByteArray()).credentialId;
        const QString k1 = record::entryKey(QStringLiteral("example.com"), id1);
        const QString k2 = record::entryKey(QStringLiteral("example.com"), id2);
        auto rec1 = record::decode(k1, store.rawEntries().value(k1));
        auto rec2 = record::decode(k2, store.rawEntries().value(k2));
        QVERIFY(rec1 && rec2);
        // swap the key blob of credential 2 into credential 1
        rec1->privateKeyPkcs8 = rec2->privateKeyPkcs8;
        record::DecodeError err;
        QVERIFY(!record::decode(k1, record::encode(*rec1), &err));
        QCOMPARE(err, record::DecodeError::Inconsistent);
        // garbage blob
        rec1->privateKeyPkcs8 = SecretBytes(QByteArray(100, 'x'));
        QVERIFY(!record::decode(k1, record::encode(*rec1), &err));
    }

    void tpmFailureYieldsNoCredential()
    {
        FakeHardwareKeyStore hw;
        hw.fail = true;
        Authenticator::Options o;
        o.hardwareKeys = &hw;
        o.createInHardware = true;
        Authenticator a(&store, &prompter, &verifier, o);
        QCOMPARE(status(run(a, ctap::MakeCredential, makeCredentialParams(QStringLiteral("example.com"), "u", cdh))), ctap::ErrOther);
        QVERIFY(store.listAll().isEmpty());
    }

    void futureSchemaIsNotTouched()
    {
        const QByteArray id = create(QStringLiteral("example.com"));
        const QString key = record::entryKey(QStringLiteral("example.com"), id);
        QString json = store.rawEntries().value(key);
        json.replace(QStringLiteral("\"schema\":1"), QStringLiteral("\"schema\":99"));
        record::DecodeError err;
        QVERIFY(!record::decode(key, json, &err));
        QCOMPARE(err, record::DecodeError::UnsupportedSchema);
    }

    void encodedRecordDoesNotContainRawSecretsInMetadata()
    {
        const QByteArray id = create(QStringLiteral("example.com"));
        const auto meta = store.listAll();
        QCOMPARE(meta.size(), 1);
        QCOMPARE(meta.first().credentialIdB64, record::b64url(id));
        // CredentialMetadata has no field for key material by construction.
    }

    // --- user verification ----------------------------------------------------
    void failedUvYieldsNoCredential()
    {
        verifier.result = false;
        QCOMPARE(status(run(*auth, ctap::MakeCredential, makeCredentialParams(QStringLiteral("example.com"), "u", cdh, true, true))),
                 ctap::ErrOperationDenied);
        QVERIFY(store.listAll().isEmpty());
    }

    void failedUvYieldsNoAssertion()
    {
        const QByteArray id = create(QStringLiteral("example.com"));
        verifier.result = false;
        QCOMPARE(status(run(*auth, ctap::GetAssertion, getAssertionParams(QStringLiteral("example.com"), cdh, {}, {}, true))),
                 ctap::ErrOperationDenied);
        QCOMPARE(store.find(QStringLiteral("example.com"), id)->signCount, 0u);
    }

    void uvNotOfferedWhenUnavailable()
    {
        verifier.available = false;
        QCOMPARE(status(run(*auth, ctap::MakeCredential, makeCredentialParams(QStringLiteral("example.com"), "u", cdh, true, true))),
                 ctap::ErrUnsupportedOption);
    }

    void uvFlagNeverSetWithoutVerification()
    {
        create(QStringLiteral("example.com"));
        const QByteArray r = run(*auth, ctap::GetAssertion, getAssertionParams(QStringLiteral("example.com"), cdh));
        QCOMPARE(parseAuthData(body(r).value(2).toByteArray()).flags & ctap::FlagUV, 0);
        QCOMPARE(verifier.calls, 0);
    }

    void makeCredentialUpFalseRejected()
    {
        QCborMap p = makeCredentialParams(QStringLiteral("example.com"), "u", cdh);
        QCborMap opts;
        opts.insert(QStringLiteral("up"), false);
        p.insert(7, opts);
        QCOMPARE(status(run(*auth, ctap::MakeCredential, p)), ctap::ErrInvalidOption);
    }

    // --- pinUvAuthToken (CTAP 2.1) ------------------------------------------------
    void tokenRequiresSuccessfulUv()
    {
        verifier.result = false;
        quint8 st = 0;
        QVERIFY(!obtainToken(*auth, ctap::PermMakeCredential, QStringLiteral("example.com"), &st));
        QCOMPARE(st, ctap::ErrOperationDenied);
    }

    void tokenIsBoundToRpId()
    {
        const auto token = obtainToken(*auth, ctap::PermMakeCredential | ctap::PermGetAssertion, QStringLiteral("example.com"));
        QVERIFY(token);
        QCborMap mc = makeCredentialParams(QStringLiteral("evil.example"), "u", cdh);
        mc.insert(8, PinUvProtocol2::authenticate(*token, cdh));
        mc.insert(9, 2);
        QCOMPARE(status(run(*auth, ctap::MakeCredential, mc)), ctap::ErrUnauthorizedPermission);
        QVERIFY(store.listAll().isEmpty());
    }

    void tokenPermissionsAreEnforced()
    {
        create(QStringLiteral("example.com"));
        const auto token = obtainToken(*auth, ctap::PermMakeCredential, QStringLiteral("example.com"));
        QVERIFY(token);
        QCborMap ga = getAssertionParams(QStringLiteral("example.com"), cdh);
        ga.insert(6, PinUvProtocol2::authenticate(*token, cdh));
        ga.insert(7, 2);
        QCOMPARE(status(run(*auth, ctap::GetAssertion, ga)), ctap::ErrUnauthorizedPermission);
    }

    void wrongTokenMacRejected()
    {
        QVERIFY(obtainToken(*auth, ctap::PermMakeCredential, QStringLiteral("example.com")));
        QCborMap mc = makeCredentialParams(QStringLiteral("example.com"), "u", cdh);
        mc.insert(8, PinUvProtocol2::authenticate(QByteArray(32, 'k'), cdh));
        mc.insert(9, 2);
        QCOMPARE(status(run(*auth, ctap::MakeCredential, mc)), ctap::ErrPinAuthInvalid);
        mc.insert(8, QByteArray(16, 'x')); // protocol 1 sized MAC
        QCOMPARE(status(run(*auth, ctap::MakeCredential, mc)), ctap::ErrPinAuthInvalid);
        QVERIFY(store.listAll().isEmpty());
    }

    void tokenMacBindsClientDataHash()
    {
        const auto token = obtainToken(*auth, ctap::PermMakeCredential, QStringLiteral("example.com"));
        QCborMap mc = makeCredentialParams(QStringLiteral("example.com"), "u", cdh);
        mc.insert(8, PinUvProtocol2::authenticate(*token, crypto::sha256("another request")));
        mc.insert(9, 2);
        QCOMPARE(status(run(*auth, ctap::MakeCredential, mc)), ctap::ErrPinAuthInvalid);
    }

    void tokenExpires()
    {
        Authenticator::Options o;
        o.pinUvAuthTokenLifetimeMs = 20;
        Authenticator a(&store, &prompter, &verifier, o);
        const auto token = obtainToken(a, ctap::PermMakeCredential, QStringLiteral("example.com"));
        QVERIFY(token);
        QTest::qWait(60);
        QCborMap mc = makeCredentialParams(QStringLiteral("example.com"), "u", cdh);
        mc.insert(8, PinUvProtocol2::authenticate(*token, cdh));
        mc.insert(9, 2);
        QCOMPARE(status(run(a, ctap::MakeCredential, mc)), ctap::ErrPinAuthInvalid);
    }

    void newTokenRequestInvalidatesOldToken()
    {
        const auto first = obtainToken(*auth, ctap::PermMakeCredential, QStringLiteral("example.com"));
        verifier.result = false;
        QVERIFY(!obtainToken(*auth, ctap::PermMakeCredential, QStringLiteral("example.com")));
        QCborMap mc = makeCredentialParams(QStringLiteral("example.com"), "u", cdh);
        mc.insert(8, PinUvProtocol2::authenticate(*first, cdh));
        mc.insert(9, 2);
        QCOMPARE(status(run(*auth, ctap::MakeCredential, mc)), ctap::ErrPinAuthInvalid);
    }

    void unsupportedTokenPermissionsAndSubcommands()
    {
        quint8 st = 0;
        QVERIFY(!obtainToken(*auth, 0x04 /* credential management */, QStringLiteral("example.com"), &st));
        QCOMPARE(st, ctap::ErrUnauthorizedPermission);
        QVERIFY(!obtainToken(*auth, ctap::PermGetAssertion, QString(), &st));
        QCOMPARE(st, ctap::ErrMissingParameter);
        QCborMap retries;
        retries.insert(1, 2);
        retries.insert(2, ctap::GetPinRetries);
        QCOMPARE(status(run(*auth, ctap::ClientPin, retries)), ctap::ErrInvalidSubcommand);
        QCOMPARE(verifier.calls, 0); // nothing above may trigger a UV prompt
    }

    void invalidPlatformKeyRejected()
    {
        QCborMap bogus;
        bogus.insert(1, 2);
        bogus.insert(3, -25);
        bogus.insert(-1, 1);
        bogus.insert(-2, QByteArray(32, '\x01'));
        bogus.insert(-3, QByteArray(32, '\x02')); // not on the curve
        QCborMap req;
        req.insert(1, 2);
        req.insert(2, ctap::GetPinUvAuthTokenUsingUvWithPermissions);
        req.insert(3, bogus);
        req.insert(9, int(ctap::PermGetAssertion));
        req.insert(10, QStringLiteral("example.com"));
        QCOMPARE(status(run(*auth, ctap::ClientPin, req)), ctap::ErrInvalidParameter);
        QCOMPARE(verifier.calls, 0);
    }

    void silentProbesCanBeDisabled()
    {
        Authenticator::Options o;
        o.allowSilentAssertions = false;
        Authenticator a(&store, &prompter, &verifier, o);
        const QByteArray id = create(QStringLiteral("example.com"));
        QCOMPARE(status(run(a, ctap::GetAssertion, getAssertionParams(QStringLiteral("example.com"), cdh, {id}, false))),
                 ctap::ErrNoCredentials);
        QCOMPARE(store.find(QStringLiteral("example.com"), id)->signCount, 0u);
        // a normal login is unaffected
        QCOMPARE(status(run(a, ctap::GetAssertion, getAssertionParams(QStringLiteral("example.com"), cdh, {id}))), ctap::Ok);
    }

    // --- malformed input ------------------------------------------------------
    void malformedRequests()
    {
        QCOMPARE(status(run(*auth, ctap::MakeCredential, makeCredentialParams(QStringLiteral("example.com"), "u", QByteArray(31, 'x')))),
                 ctap::ErrInvalidParameter);
        QCOMPARE(status(run(*auth, ctap::MakeCredential, makeCredentialParams(QStringLiteral("example.com"), QByteArray(65, 'u'), cdh))),
                 ctap::ErrInvalidParameter);
        QByteArray garbage(1, char(ctap::GetAssertion));
        garbage += QByteArray::fromHex("bf01"); // truncated indefinite map
        QByteArray out;
        auth->process(garbage, [&](const QByteArray &r) { out = r; });
        QCOMPARE(status(out), ctap::ErrInvalidCbor);
        QCborMap noHash;
        noHash.insert(1, QStringLiteral("example.com"));
        QCOMPARE(status(run(*auth, ctap::GetAssertion, noHash)), ctap::ErrMissingParameter);
        QCborMap wrongType;
        wrongType.insert(1, 42);
        wrongType.insert(2, cdh);
        QCOMPARE(status(run(*auth, ctap::GetAssertion, wrongType)), ctap::ErrCborUnexpectedType);
    }

    // --- concurrency / cancellation ---------------------------------------------
    void concurrentRequestIsRejected()
    {
        prompter.deferred = true;
        QByteArray first;
        auth->process(QByteArray(1, char(ctap::MakeCredential))
                          + QCborValue(makeCredentialParams(QStringLiteral("example.com"), "u", cdh)).toCbor(),
                      [&](const QByteArray &r) { first = r; });
        QVERIFY(first.isEmpty());
        QVERIFY(auth->isBusy());
        QCOMPARE(status(run(*auth, ctap::GetInfo)), ctap::ErrChannelBusy);

        auth->cancel();
        QCOMPARE(status(first), ctap::ErrKeepaliveCancel);
        QVERIFY(!auth->isBusy());
        QVERIFY(!prompter.pending); // prompt was withdrawn
        QVERIFY(store.listAll().isEmpty());
    }

    void lateUserApprovalAfterCancelIsIgnored()
    {
        prompter.deferred = true;
        QByteArray first;
        int calls = 0;
        auth->process(QByteArray(1, char(ctap::MakeCredential))
                          + QCborValue(makeCredentialParams(QStringLiteral("example.com"), "u", cdh)).toCbor(),
                      [&](const QByteArray &r) {
                          first = r;
                          ++calls;
                      });
        auto staleCallback = prompter.pending;
        auth->cancel();
        staleCallback({true, 0}); // user clicks "Create" after the browser cancelled
        QCOMPARE(calls, 1);
        QVERIFY(store.listAll().isEmpty());
    }

    void userActionTimeout()
    {
        Authenticator::Options o;
        o.userActionTimeoutMs = 50;
        Authenticator a(&store, &prompter, &verifier, o);
        prompter.deferred = true;
        QByteArray out;
        a.process(QByteArray(1, char(ctap::MakeCredential))
                      + QCborValue(makeCredentialParams(QStringLiteral("example.com"), "u", cdh)).toCbor(),
                  [&](const QByteArray &r) { out = r; });
        QTRY_COMPARE_WITH_TIMEOUT(status(out), ctap::ErrUserActionTimeout, 2000);
    }
};

QTEST_GUILESS_MAIN(TestSecurity)
#include "test_security.moc"
