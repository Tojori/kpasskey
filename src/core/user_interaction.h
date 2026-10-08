// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include <QList>
#include <QString>
#include <functional>

namespace kpasskey {

struct AccountChoice {
    QString userName;
    QString userDisplayName;
};

struct PresenceRequest {
    enum class Kind {
        Register,     // makeCredential
        Authenticate, // getAssertion (choose one of `accounts`)
        Excluded,     // makeCredential hit the excludeList: confirm, then report "already registered"
        Selection,    // zero-length pinUvAuthParam probe (browser asks which key to use)
    };
    Kind kind = Kind::Register;
    QString rpId;     // authoritative, hashed into authenticatorData
    QString rpName;   // site-controlled, must be shown as unverified
    QString userName; // Register only, site-controlled
    QString userDisplayName;
    QList<AccountChoice> accounts; // Authenticate only
    bool userVerificationFollows = false;
};

struct PresenceResult {
    bool approved = false;
    int selectedIndex = 0; // index into PresenceRequest::accounts
};

// User presence (UP): an explicit confirmation by the user for this ceremony.
class PresencePrompter
{
public:
    virtual ~PresencePrompter() = default;
    virtual void requestPresence(const PresenceRequest &request, std::function<void(PresenceResult)> done) = 0;
    // Aborts an outstanding prompt. `done` must not be invoked afterwards.
    virtual void cancel() = 0;
};

// User verification (UV): proves that the *owner* of the account is present
// (password via PAM, fingerprint, ...), freshly for this ceremony.
class UserVerifier
{
public:
    virtual ~UserVerifier() = default;
    virtual bool isAvailable() const = 0;
    virtual void verify(const QString &rpId, std::function<void(bool verified)> done) = 0;
    virtual void cancel() = 0;
};

} // namespace kpasskey
