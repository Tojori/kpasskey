// SPDX-License-Identifier: LGPL-2.1-or-later
// Functional tests of the CTAP2 engine against the in-memory store.
#include "common/fakes.h"

#include <QTest>

using namespace kpasskey;
using namespace kpasskey::test;

class TestAuthenticator : public QObject
{
    Q_OBJECT

    MemoryStore store;
    FakePrompter prompter;
    FakeVerifier verifier;
    std::unique_ptr<Authenticator> auth;
    const QByteArray cdh = crypto::sha256("clientDataJSON");

    QByteArray createCredential(const QString &rpId, const QByteArray &userId, bool rk = true, bool uv = false)
    {
        const QByteArray r = run(*auth, ctap::MakeCredential, makeCredentialParams(rpId, userId, cdh, rk, uv));
        if (status(r) != ctap::Ok) {
            return {};
        }
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

    void getInfo()
    {
        const QByteArray r = run(*auth, ctap::GetInfo);
        QCOMPARE(status(r), ctap::Ok);
        const QCborMap info = body(r);
        QCOMPARE(info.value(1).toArray().at(0).toString(), QStringLiteral("FIDO_2_0"));
        QCOMPARE(info.value(1).toArray().at(1).toString(), QStringLiteral("FIDO_2_1"));
        QCOMPARE(info.value(6).toArray().at(0).toInteger(), qint64(2)); // PIN/UV auth protocol 2
        const QCborMap opts = info.value(4).toMap();
        QVERIFY(opts.value(QStringLiteral("rk")).toBool());
        QVERIFY(opts.value(QStringLiteral("uv")).toBool());
        QCOMPARE(opts.value(QStringLiteral("plat")).toBool(), false);
        QVERIFY(opts.value(QStringLiteral("pinUvAuthToken")).toBool());
        QVERIFY(!opts.contains(QStringLiteral("clientPin")));
    }

    void tokenBasedRegistrationAndLogin()
    {
        const auto token = obtainToken(*auth, ctap::PermMakeCredential | ctap::PermGetAssertion, QStringLiteral("example.com"));
        QVERIFY(token);
        QCOMPARE(verifier.calls, 1);
        QCborMap mc = makeCredentialParams(QStringLiteral("example.com"), "user-1", cdh);
        mc.insert(8, PinUvProtocol2::authenticate(*token, cdh));
        mc.insert(9, 2);
        const QByteArray r = run(*auth, ctap::MakeCredential, mc);
        QCOMPARE(status(r), ctap::Ok);
        QVERIFY(parseAuthData(body(r).value(2).toByteArray()).flags & ctap::FlagUV);
        QCOMPARE(verifier.calls, 1); // UV was not repeated
        QCOMPARE(prompter.calls, 1); // but user presence was collected

        QCborMap ga = getAssertionParams(QStringLiteral("example.com"), cdh);
        ga.insert(6, PinUvProtocol2::authenticate(*token, cdh));
        ga.insert(7, 2);
        const QByteArray a = run(*auth, ctap::GetAssertion, ga);
        QCOMPARE(status(a), ctap::Ok);
        QCOMPARE(parseAuthData(body(a).value(2).toByteArray()).flags, quint8(ctap::FlagUP | ctap::FlagUV));
    }

    void authenticatorSelection()
    {
        QCOMPARE(status(run(*auth, ctap::Selection)), ctap::Ok);
        QCOMPARE(prompter.last.kind, PresenceRequest::Kind::Selection);
        prompter.approve = false;
        QCOMPARE(status(run(*auth, ctap::Selection)), ctap::ErrOperationDenied);
    }

    void getInfoWithoutVerifierDoesNotClaimUv()
    {
        Authenticator noUv(&store, &prompter, nullptr, {});
        const QCborMap opts = body(run(noUv, ctap::GetInfo)).value(4).toMap();
        QVERIFY(!opts.contains(QStringLiteral("uv")));
    }

    void makeCredentialEs256()
    {
        const QByteArray r = run(*auth, ctap::MakeCredential, makeCredentialParams(QStringLiteral("example.com"), "user-1", cdh, true, true));
        QCOMPARE(status(r), ctap::Ok);
        const QCborMap resp = body(r);
        QCOMPARE(resp.value(1).toString(), QStringLiteral("packed"));
        const QByteArray authData = resp.value(2).toByteArray();
        const auto ad = parseAuthData(authData);
        QCOMPARE(ad.rpIdHash, crypto::sha256("example.com"));
        QCOMPARE(ad.flags, quint8(ctap::FlagUP | ctap::FlagUV | ctap::FlagAT));
        QCOMPARE(ad.counter, 0u);
        QCOMPARE(ad.credentialId.size(), ctap::CredentialIdSize);
        const QByteArray aaguid = QByteArray::fromHex("a449940063e64329b1e1883b52c928b2");
        QCOMPARE(ad.aaguid, aaguid);
        QCOMPARE(body(run(*auth, ctap::GetInfo)).value(3).toByteArray(), aaguid);

        // packed self attestation verifies with the credential public key
        const QCborMap attStmt = resp.value(3).toMap();
        QCOMPARE(attStmt.value(QStringLiteral("alg")).toInteger(), qint64(ctap::ES256));
        QVERIFY(crypto::verify(ad.publicKeyCose, authData + cdh, attStmt.value(QStringLiteral("sig")).toByteArray()));

        QCOMPARE(verifier.calls, 1);
        QCOMPARE(prompter.last.kind, PresenceRequest::Kind::Register);
        QCOMPARE(store.listAll().size(), 1);
    }

    void makeCredentialEdDsaPreferred()
    {
        const QByteArray r = run(*auth, ctap::MakeCredential,
                                 makeCredentialParams(QStringLiteral("example.com"), "u", cdh, true, false,
                                                      {pkParam(-999), pkParam(ctap::EdDSA), pkParam(ctap::ES256)}));
        QCOMPARE(status(r), ctap::Ok);
        QCOMPARE(body(r).value(3).toMap().value(QStringLiteral("alg")).toInteger(), qint64(ctap::EdDSA));
    }

    void unsupportedAlgorithm()
    {
        const QByteArray r = run(*auth, ctap::MakeCredential,
                                 makeCredentialParams(QStringLiteral("example.com"), "u", cdh, true, false, {pkParam(-257)}));
        QCOMPARE(status(r), ctap::ErrUnsupportedAlgorithm);
    }

    void discoverableAssertionAndCounter()
    {
        const QByteArray credId = createCredential(QStringLiteral("example.com"), "user-1");
        QVERIFY(!credId.isEmpty());
        const auto rec = store.find(QStringLiteral("example.com"), credId);
        QVERIFY(rec);

        for (quint32 expected = 1; expected <= 3; ++expected) {
            const QByteArray r = run(*auth, ctap::GetAssertion, getAssertionParams(QStringLiteral("example.com"), cdh));
            QCOMPARE(status(r), ctap::Ok);
            const QCborMap resp = body(r);
            QCOMPARE(resp.value(1).toMap().value(QStringLiteral("id")).toByteArray(), credId);
            const QByteArray authData = resp.value(2).toByteArray();
            const auto ad = parseAuthData(authData);
            QCOMPARE(ad.counter, expected);
            QCOMPARE(ad.flags, quint8(ctap::FlagUP));
            QVERIFY(crypto::verify(rec->publicKeyCose, authData + cdh, resp.value(3).toByteArray()));
            QCOMPARE(resp.value(4).toMap().value(QStringLiteral("id")).toByteArray(), QByteArray("user-1"));
            // no identifying info without UV
            QVERIFY(!resp.value(4).toMap().contains(QStringLiteral("name")));
        }
        QCOMPARE(store.find(QStringLiteral("example.com"), credId)->signCount, 3u);
    }

    void assertionWithUvReturnsUserInfo()
    {
        createCredential(QStringLiteral("example.com"), "user-1");
        const QByteArray r = run(*auth, ctap::GetAssertion, getAssertionParams(QStringLiteral("example.com"), cdh, {}, {}, true));
        QCOMPARE(status(r), ctap::Ok);
        QCOMPARE(parseAuthData(body(r).value(2).toByteArray()).flags, quint8(ctap::FlagUP | ctap::FlagUV));
        QCOMPARE(body(r).value(4).toMap().value(QStringLiteral("name")).toString(), QStringLiteral("alice@example.com"));
    }

    void allowListAssertion()
    {
        const QByteArray nonResident = createCredential(QStringLiteral("example.com"), "user-1", false);
        // not discoverable: invisible without allowList
        QCOMPARE(status(run(*auth, ctap::GetAssertion, getAssertionParams(QStringLiteral("example.com"), cdh))),
                 ctap::ErrNoCredentials);
        const QByteArray r = run(*auth, ctap::GetAssertion,
                                 getAssertionParams(QStringLiteral("example.com"), cdh, {QByteArray(32, 'x'), nonResident}));
        QCOMPARE(status(r), ctap::Ok);
        QCOMPARE(body(r).value(1).toMap().value(QStringLiteral("id")).toByteArray(), nonResident);
        QVERIFY(!body(r).contains(4)); // user is omitted when allowList was given
    }

    void multipleCredentialsSelection()
    {
        const QByteArray a = createCredential(QStringLiteral("example.com"), "user-a");
        const QByteArray b = createCredential(QStringLiteral("example.com"), "user-b");
        createCredential(QStringLiteral("other.org"), "user-c");
        QVERIFY(a != b);

        prompter.select = 1;
        const QByteArray r = run(*auth, ctap::GetAssertion, getAssertionParams(QStringLiteral("example.com"), cdh));
        QCOMPARE(status(r), ctap::Ok);
        QCOMPARE(prompter.last.accounts.size(), 2); // other.org is not offered
        const QByteArray chosen = body(r).value(1).toMap().value(QStringLiteral("id")).toByteArray();
        QVERIFY(chosen == a || chosen == b);
    }

    void newestCredentialIsPreselected()
    {
        const QByteArray older = createCredential(QStringLiteral("example.com"), "user-a");
        QVERIFY(status(run(*auth, ctap::GetAssertion, getAssertionParams(QStringLiteral("example.com"), cdh))) == ctap::Ok);
        QTest::qWait(1100); // timestamps have second resolution in storage
        const QByteArray newer = createCredential(QStringLiteral("example.com"), "user-b");
        prompter.select = 0;
        const QByteArray r = run(*auth, ctap::GetAssertion, getAssertionParams(QStringLiteral("example.com"), cdh));
        QCOMPARE(body(r).value(1).toMap().value(QStringLiteral("id")).toByteArray(), newer);
        QVERIFY(older != newer);
    }

    void residentKeyReplacedForSameUser()
    {
        const QByteArray first = createCredential(QStringLiteral("example.com"), "user-1");
        const QByteArray second = createCredential(QStringLiteral("example.com"), "user-1");
        QVERIFY(first != second);
        QCOMPARE(store.findByRp(QStringLiteral("example.com")).size(), 1);
        QVERIFY(!store.find(QStringLiteral("example.com"), first));
    }

    void excludeList()
    {
        const QByteArray id = createCredential(QStringLiteral("example.com"), "user-1");
        QCborMap p = makeCredentialParams(QStringLiteral("example.com"), "user-2", cdh);
        p.insert(5, QCborArray{descriptor(id)});
        const int before = prompter.calls;
        QCOMPARE(status(run(*auth, ctap::MakeCredential, p)), ctap::ErrCredentialExcluded);
        QCOMPARE(prompter.calls, before + 1); // user presence before revealing the result
        QCOMPARE(prompter.last.kind, PresenceRequest::Kind::Excluded);
    }

    void userDenies()
    {
        prompter.approve = false;
        QCOMPARE(status(run(*auth, ctap::MakeCredential, makeCredentialParams(QStringLiteral("example.com"), "u", cdh))),
                 ctap::ErrOperationDenied);
        QVERIFY(store.listAll().isEmpty());
    }

    void deletion()
    {
        const QByteArray id = createCredential(QStringLiteral("example.com"), "user-1");
        QVERIFY(store.remove(record::b64url(id)));
        QCOMPARE(status(run(*auth, ctap::GetAssertion, getAssertionParams(QStringLiteral("example.com"), cdh))),
                 ctap::ErrNoCredentials);
    }

    void walletLocked()
    {
        store.setReady(false);
        QCOMPARE(status(run(*auth, ctap::MakeCredential, makeCredentialParams(QStringLiteral("example.com"), "u", cdh))),
                 ctap::ErrOperationDenied);
        store.setReady(true);
        QCOMPARE(status(run(*auth, ctap::MakeCredential, makeCredentialParams(QStringLiteral("example.com"), "u", cdh))),
                 ctap::Ok);
    }

    void silentAssertionHasNoUpFlag()
    {
        createCredential(QStringLiteral("example.com"), "user-1");
        const int before = prompter.calls;
        const QByteArray r = run(*auth, ctap::GetAssertion, getAssertionParams(QStringLiteral("example.com"), cdh, {}, false));
        QCOMPARE(status(r), ctap::Ok);
        QCOMPARE(prompter.calls, before);
        QCOMPARE(parseAuthData(body(r).value(2).toByteArray()).flags, quint8(0));
    }

    void unsupportedCommands()
    {
        QCOMPARE(status(run(*auth, ctap::Reset)), ctap::ErrNotAllowed);
        QCOMPARE(status(run(*auth, ctap::GetNextAssertion)), ctap::ErrNotAllowed);
        QCOMPARE(status(run(*auth, ctap::ClientPin)), ctap::ErrInvalidCbor); // parameters are mandatory
        QCOMPARE(status(run(*auth, 0x42)), ctap::ErrInvalidCommand);
    }

    void selectionProbe()
    {
        QCborMap p = makeCredentialParams(QStringLiteral("example.com"), "u", cdh);
        p.insert(8, QByteArray());
        QCOMPARE(status(run(*auth, ctap::MakeCredential, p)), ctap::ErrPinNotSet);
        QCOMPARE(prompter.last.kind, PresenceRequest::Kind::Selection);
        QVERIFY(store.listAll().isEmpty());
    }
};

QTEST_GUILESS_MAIN(TestAuthenticator)
#include "test_authenticator.moc"
