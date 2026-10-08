// SPDX-License-Identifier: LGPL-2.1-or-later
// Test doubles and helpers shared by unit and security tests.
#pragma once

#include "core/authenticator.h"
#include "core/crypto.h"
#include "core/ctap_constants.h"

#include <QCborArray>
#include <QCborMap>
#include <QCborValue>
#include <QtEndian>

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
