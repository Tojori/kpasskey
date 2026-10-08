// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include "credential_store.h"
#include "pin_uv.h"
#include "user_interaction.h"

#include <QByteArray>
#include <QCborMap>
#include <QElapsedTimer>
#include <QObject>
#include <QTimer>
#include <functional>

namespace kpasskey {

// Something that answers CTAP2 CBOR requests (transport independent).
class CborProcessor
{
public:
    enum class Activity { Processing, WaitingForUser };

    virtual ~CborProcessor() = default;
    // `request` = command byte + CBOR parameters. `done` receives status byte +
    // optional CBOR response and is invoked exactly once, unless cancel() was
    // called first (then it is invoked once with ErrKeepaliveCancel).
    virtual void process(const QByteArray &request, std::function<void(QByteArray)> done) = 0;
    virtual void cancel() = 0;
    virtual Activity activity() const = 0;
};

// CTAP 2.1 authenticator with built-in user verification (no PIN) and its own
// display (the KDE dialog), so it selects among multiple accounts itself and
// does not need authenticatorGetNextAssertion.
//
// User verification is offered both CTAP 2.0 style ("uv" option) and CTAP 2.1
// style (pinUvAuthToken obtained via getPinUvAuthTokenUsingUvWithPermissions,
// PIN/UV auth protocol 2), which is what current clients use.
class Authenticator : public QObject, public CborProcessor
{
    Q_OBJECT
public:
    struct Options {
        // Identifies the authenticator *model* "KDE Passkey (KWallet)" (same for
        // every installation, so it reveals nothing about the user). Randomly
        // generated v4 UUID a4499400-63e6-4329-b1e1-883b52c928b2; see
        // docs/storage-format.md#aaguid.
        QByteArray aaguid = QByteArray::fromHex("a449940063e64329b1e1883b52c928b2");
        int userActionTimeoutMs = 120000;
        int pinUvAuthTokenLifetimeMs = 30000; // CTAP 2.1 initial usage time limit
        // Silent probes (up=false, no UV) let any local process holding the
        // hidraw node test whether a credential exists. Browsers use them for
        // excludeList pre-flight; disabling only answers NO_CREDENTIALS.
        bool allowSilentAssertions = true;
    };

    Authenticator(CredentialStore *store, PresencePrompter *prompter, UserVerifier *verifier, Options options,
                  QObject *parent = nullptr);
    ~Authenticator() override;

    void process(const QByteArray &request, std::function<void(QByteArray)> done) override;
    void cancel() override;
    Activity activity() const override { return m_activity; }

    bool isBusy() const { return bool(m_done); }

private:
    struct Pending;

    void finish(quint8 status, const QCborMap &response = {});
    QByteArray getInfo() const;
    void clientPin(const QCborMap &params);
    // Validates pinUvAuthParam/protocol. Returns Ok and sets *uvDone, or an error.
    quint8 checkPinUvAuth(const QCborValue &param, const QCborValue &protocol, const QByteArray &clientDataHash,
                          quint8 permission, const QString &rpId, bool *uvDone);
    bool uvSupported() const;
    void makeCredential(const QCborMap &params);
    void getAssertion(const QCborMap &params);
    void makeCredentialConfirmed(const std::shared_ptr<Pending> &p);
    void getAssertionConfirmed(const std::shared_ptr<Pending> &p, int index);

    // Runs `presence` (UP) and, if requested, `uv`; calls `next` on success.
    void collectUser(const PresenceRequest &req, bool uv, std::function<void(int selected)> next);

    CredentialStore *m_store;
    PresencePrompter *m_prompter;
    UserVerifier *m_verifier;
    Options m_options;
    std::function<void(QByteArray)> m_done;
    Activity m_activity = Activity::Processing;
    quint64 m_generation = 0; // invalidates callbacks of cancelled requests
    QTimer m_timeout;

    PinUvProtocol2 m_pinUv;
    struct Token {
        QByteArray value; // 32 random bytes, never leaves the daemon unencrypted
        quint8 permissions = 0;
        QString rpId;
        QElapsedTimer issued;
        bool valid = false;
    } m_token;
};

} // namespace kpasskey
