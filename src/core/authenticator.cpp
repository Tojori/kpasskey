// SPDX-License-Identifier: LGPL-2.1-or-later
#include "authenticator.h"

#include "ctap_constants.h"
#include "logging.h"

#include <QCborArray>
#include <QCborValue>
#include <QtEndian>

namespace kpasskey {

using namespace ctap;

namespace {

constexpr int MaxStringLength = 64; // CTAP allows truncating user/rp strings to 64 bytes

QString truncated(const QString &s)
{
    return s.left(MaxStringLength);
}

QByteArray bigEndian32(quint32 v)
{
    QByteArray out(4, '\0');
    qToBigEndian(v, out.data());
    return out;
}

QByteArray bigEndian16(quint16 v)
{
    QByteArray out(2, '\0');
    qToBigEndian(v, out.data());
    return out;
}

// Reads a CTAP "options" map; returns false on type errors.
bool readOption(const QCborMap &options, const char *name, std::optional<bool> *out)
{
    const QCborValue v = options.value(QLatin1String(name));
    if (v.isUndefined()) {
        return true;
    }
    if (!v.isBool()) {
        return false;
    }
    *out = v.toBool();
    return true;
}

} // namespace

struct Authenticator::Pending {
    QByteArray clientDataHash;
    QString rpId;
    QString rpName;
    QByteArray userHandle;
    QString userName;
    QString userDisplayName;
    int alg = 0;
    bool rk = false;
    bool uv = false;
    bool uvDone = false; // UV already performed (pinUvAuthToken)
    bool up = true;
    bool allowListGiven = false;
    QList<CredentialRecord> candidates;
};

Authenticator::Authenticator(CredentialStore *store, PresencePrompter *prompter, UserVerifier *verifier,
                             Options options, QObject *parent)
    : QObject(parent)
    , m_store(store)
    , m_prompter(prompter)
    , m_verifier(verifier)
    , m_options(std::move(options))
{
    Q_ASSERT(m_options.aaguid.size() == 16);
    m_timeout.setSingleShot(true);
    connect(&m_timeout, &QTimer::timeout, this, [this] {
        qCInfo(KPASSKEY_LOG) << "user action timed out";
        m_prompter->cancel();
        if (m_verifier) {
            m_verifier->cancel();
        }
        finish(ErrUserActionTimeout);
    });
}

Authenticator::~Authenticator() = default;

void Authenticator::finish(quint8 status, const QCborMap &response)
{
    m_timeout.stop();
    m_activity = Activity::Processing;
    ++m_generation;
    auto done = std::move(m_done);
    m_done = nullptr;
    if (!done) {
        return;
    }
    qCInfo(KPASSKEY_LOG).nospace() << "<- status 0x" << qPrintable(QString::number(status, 16));
    QByteArray out(1, char(status));
    if (status == Ok && !response.isEmpty()) {
        out += QCborValue(response).toCbor();
    }
    done(out);
}

void Authenticator::cancel()
{
    if (!m_done) {
        return;
    }
    qCInfo(KPASSKEY_LOG) << "request cancelled by client";
    m_prompter->cancel();
    if (m_verifier) {
        m_verifier->cancel();
    }
    finish(ErrKeepaliveCancel);
}

void Authenticator::process(const QByteArray &request, std::function<void(QByteArray)> done)
{
    if (m_done) {
        done(QByteArray(1, char(ErrChannelBusy)));
        return;
    }
    m_done = std::move(done);
    ++m_generation;
    m_activity = Activity::Processing;

    if (request.isEmpty()) {
        finish(ErrInvalidLength);
        return;
    }
    const quint8 cmd = quint8(request.at(0));
    const QByteArray payload = request.mid(1);
    qCInfo(KPASSKEY_LOG).nospace() << "-> command 0x" << qPrintable(QString::number(cmd, 16)) << " (" << payload.size() << " bytes)";

    if (cmd == GetInfo) {
        auto done2 = std::move(m_done);
        m_done = nullptr;
        done2(payload.isEmpty() ? getInfo() : QByteArray(1, char(ErrInvalidLength)));
        return;
    }
    if (cmd == Selection) {
        PresenceRequest req;
        req.kind = PresenceRequest::Kind::Selection;
        collectUser(req, false, [this](int) { finish(Ok); });
        return;
    }
    if (cmd != MakeCredential && cmd != GetAssertion && cmd != ClientPin) {
        // authenticatorReset is only available through the KDE management UI,
        // and GetNextAssertion is never needed because we select the account on
        // our own display.
        finish(cmd == Reset || cmd == GetNextAssertion ? ErrNotAllowed : ErrInvalidCommand);
        return;
    }

    QCborParserError err;
    const QCborValue v = QCborValue::fromCbor(payload, &err);
    if (err.error != QCborError::NoError) {
        finish(ErrInvalidCbor);
        return;
    }
    if (!v.isMap()) {
        finish(ErrCborUnexpectedType);
        return;
    }
    const QCborMap params = v.toMap();
    if (cmd == ClientPin) {
        clientPin(params);
        return;
    }
    const quint64 gen = m_generation;
    m_store->ensureReady([this, gen, cmd, params](bool ok) {
        if (gen != m_generation) {
            return;
        }
        if (!ok) {
            qCWarning(KPASSKEY_LOG) << "credential storage is not available";
            finish(ErrOperationDenied);
            return;
        }
        if (cmd == MakeCredential) {
            makeCredential(params);
        } else {
            getAssertion(params);
        }
    });
}

bool Authenticator::uvSupported() const
{
    return m_verifier && m_verifier->isAvailable();
}

QByteArray Authenticator::getInfo() const
{
    const bool uv = uvSupported();
    QCborMap options; // canonical order: rk, up, uv, plat, pinUvAuthToken
    options.insert(QStringLiteral("rk"), true);
    options.insert(QStringLiteral("up"), true);
    if (uv) {
        options.insert(QStringLiteral("uv"), true);
    }
    options.insert(QStringLiteral("plat"), false); // reached via USB HID: a roaming authenticator from the browser's view
    if (uv) {
        options.insert(QStringLiteral("pinUvAuthToken"), true);
    }
    // "clientPin" is absent: no PIN exists, user verification is built in.

    QCborMap info;
    info.insert(1, QCborArray{QStringLiteral("FIDO_2_0"), QStringLiteral("FIDO_2_1")});
    info.insert(3, m_options.aaguid);
    info.insert(4, options);
    info.insert(5, 4096); // maxMsgSize
    if (uv) {
        info.insert(6, QCborArray{PinUvProtocol2::Version});
    }
    info.insert(9, QCborArray{QStringLiteral("usb")});
    QCborArray algs;
    for (int alg : {int(ES256), int(EdDSA)}) {
        QCborMap m; // canonical order: "alg", "type"
        m.insert(QStringLiteral("alg"), alg);
        m.insert(QStringLiteral("type"), QStringLiteral("public-key"));
        algs.append(m);
    }
    info.insert(10, algs);
    return QByteArray(1, char(Ok)) + QCborValue(info).toCbor();
}

void Authenticator::clientPin(const QCborMap &params)
{
    const QCborValue protocol = params.value(1);
    const QCborValue sub = params.value(2);
    if (sub.isUndefined()) {
        finish(ErrMissingParameter);
        return;
    }
    if (!sub.isInteger()) {
        finish(ErrCborUnexpectedType);
        return;
    }
    if (!uvSupported()) {
        finish(ErrInvalidCommand);
        return;
    }
    switch (sub.toInteger()) {
    case GetKeyAgreement: {
        if (protocol.toInteger(-1) != PinUvProtocol2::Version) {
            finish(protocol.isUndefined() ? ErrMissingParameter : ErrInvalidParameter);
            return;
        }
        QCborMap resp;
        resp.insert(1, m_pinUv.keyAgreementCose());
        finish(Ok, resp);
        return;
    }
    case GetUvRetries: {
        // polkit/PAM keep their own lockout policy (e.g. pam_faillock); we do
        // not maintain a separate counter and report a constant.
        QCborMap resp;
        resp.insert(5, 3);
        finish(Ok, resp);
        return;
    }
    case GetPinUvAuthTokenUsingUvWithPermissions:
        break;
    default:
        finish(ErrInvalidSubcommand); // no PIN: getPinRetries, setPIN, changePIN, getPinToken
        return;
    }

    const QCborValue keyAgreement = params.value(3);
    const QCborValue permissions = params.value(9);
    const QCborValue rpId = params.value(10);
    if (protocol.isUndefined() || keyAgreement.isUndefined() || permissions.isUndefined()) {
        finish(ErrMissingParameter);
        return;
    }
    if (!protocol.isInteger() || !keyAgreement.isMap() || !permissions.isInteger() || (!rpId.isUndefined() && !rpId.isString())) {
        finish(ErrCborUnexpectedType);
        return;
    }
    if (protocol.toInteger() != PinUvProtocol2::Version || permissions.toInteger() <= 0 || permissions.toInteger() > 0xff) {
        finish(ErrInvalidParameter);
        return;
    }
    const quint8 perms = quint8(permissions.toInteger());
    if (perms & ~(PermMakeCredential | PermGetAssertion)) {
        finish(ErrUnauthorizedPermission); // credential management, bio enrollment, ... are not offered
        return;
    }
    if (rpId.isUndefined() || !isPlausibleRpId(rpId.toString())) {
        // mc/ga permissions require an RP ID; we always bind tokens to one.
        finish(rpId.isUndefined() ? ErrMissingParameter : ErrInvalidParameter);
        return;
    }
    auto shared = std::make_shared<SecretBytes>();
    if (auto s = m_pinUv.sharedSecret(keyAgreement.toMap())) {
        *shared = std::move(*s);
    } else {
        finish(ErrInvalidParameter);
        return;
    }

    m_token = Token{}; // any previous token is invalidated by a new request
    m_activity = Activity::WaitingForUser;
    m_timeout.start(m_options.userActionTimeoutMs);
    const quint64 gen = m_generation;
    const QString rp = rpId.toString();
    qCInfo(KPASSKEY_LOG) << "requesting user verification for pinUvAuthToken, rp" << rp;
    m_verifier->verify(rp, [this, gen, shared, perms, rp](bool verified) {
        if (gen != m_generation) {
            return;
        }
        if (!verified) {
            qCInfo(KPASSKEY_LOG) << "user verification for token failed";
            finish(ErrOperationDenied);
            return;
        }
        m_token.value = crypto::randomBytes(32);
        m_token.permissions = perms;
        m_token.rpId = rp;
        m_token.issued.start();
        m_token.valid = true;
        auto encrypted = PinUvProtocol2::encrypt(*shared, m_token.value);
        m_pinUv.regenerate(); // fresh key agreement key for the next exchange
        if (!encrypted) {
            m_token = Token{};
            finish(ErrOther);
            return;
        }
        QCborMap resp;
        resp.insert(2, *encrypted);
        finish(Ok, resp);
    });
}

quint8 Authenticator::checkPinUvAuth(const QCborValue &param, const QCborValue &protocol, const QByteArray &clientDataHash,
                                     quint8 permission, const QString &rpId, bool *uvDone)
{
    *uvDone = false;
    if (!param.isByteArray()) {
        return ErrCborUnexpectedType;
    }
    if (protocol.isUndefined()) {
        return ErrMissingParameter;
    }
    if (protocol.toInteger(-1) != PinUvProtocol2::Version) {
        return ErrInvalidParameter;
    }
    if (!m_token.valid || m_token.issued.hasExpired(m_options.pinUvAuthTokenLifetimeMs)) {
        m_token = Token{};
        return ErrPinAuthInvalid;
    }
    if (!PinUvProtocol2::verify(m_token.value, clientDataHash, param.toByteArray())) {
        return ErrPinAuthInvalid;
    }
    if (!(m_token.permissions & permission)) {
        return ErrUnauthorizedPermission;
    }
    if (m_token.rpId != rpId) {
        return ErrUnauthorizedPermission;
    }
    *uvDone = true;
    return Ok;
}

void Authenticator::collectUser(const PresenceRequest &req, bool uv, std::function<void(int)> next)
{
    m_activity = Activity::WaitingForUser;
    m_timeout.start(m_options.userActionTimeoutMs);
    const quint64 gen = m_generation;
    const QString rpId = req.rpId;
    qCInfo(KPASSKEY_LOG) << "requesting user presence for" << rpId << "kind" << int(req.kind) << "uv follows" << uv;
    m_prompter->requestPresence(req, [this, gen, uv, rpId, next](PresenceResult r) {
        if (gen != m_generation) {
            return;
        }
        qCInfo(KPASSKEY_LOG) << "user presence result:" << r.approved;
        if (!r.approved) {
            finish(ErrOperationDenied);
            return;
        }
        if (!uv) {
            m_timeout.stop();
            m_activity = Activity::Processing;
            next(r.selectedIndex);
            return;
        }
        m_verifier->verify(rpId, [this, gen, next, idx = r.selectedIndex](bool verified) {
            if (gen != m_generation) {
                return;
            }
            if (!verified) {
                qCInfo(KPASSKEY_LOG) << "user verification failed";
                finish(ErrOperationDenied);
                return;
            }
            m_timeout.stop();
            m_activity = Activity::Processing;
            next(idx);
        });
    });
}

void Authenticator::makeCredential(const QCborMap &params)
{
    auto p = std::make_shared<Pending>();

    const QCborValue cdh = params.value(1);
    const QCborValue rp = params.value(2);
    const QCborValue user = params.value(3);
    const QCborValue algs = params.value(4);
    if (cdh.isUndefined() || rp.isUndefined() || user.isUndefined() || algs.isUndefined()) {
        finish(ErrMissingParameter);
        return;
    }
    if (!cdh.isByteArray() || !rp.isMap() || !user.isMap() || !algs.isArray()) {
        finish(ErrCborUnexpectedType);
        return;
    }
    p->clientDataHash = cdh.toByteArray();
    if (p->clientDataHash.size() != ClientDataHashSize) {
        finish(ErrInvalidParameter);
        return;
    }

    const QCborMap rpMap = rp.toMap();
    const QCborValue rpId = rpMap.value(QLatin1String("id"));
    if (!rpId.isString()) {
        finish(rpId.isUndefined() ? ErrMissingParameter : ErrCborUnexpectedType);
        return;
    }
    p->rpId = rpId.toString();
    if (!isPlausibleRpId(p->rpId)) {
        qCInfo(KPASSKEY_LOG) << "rejecting implausible RP ID";
        finish(ErrInvalidParameter);
        return;
    }
    p->rpName = truncated(rpMap.value(QLatin1String("name")).toString());

    const QCborMap userMap = user.toMap();
    const QCborValue userId = userMap.value(QLatin1String("id"));
    if (!userId.isByteArray()) {
        finish(userId.isUndefined() ? ErrMissingParameter : ErrCborUnexpectedType);
        return;
    }
    p->userHandle = userId.toByteArray();
    if (p->userHandle.isEmpty() || p->userHandle.size() > MaxUserIdSize) {
        finish(ErrInvalidParameter);
        return;
    }
    p->userName = truncated(userMap.value(QLatin1String("name")).toString());
    p->userDisplayName = truncated(userMap.value(QLatin1String("displayName")).toString());

    // Pick the first algorithm we support, in the RP's order of preference.
    for (const QCborValue &entry : algs.toArray()) {
        const QCborMap m = entry.toMap();
        if (m.value(QLatin1String("type")).toString() != QLatin1String("public-key")) {
            continue;
        }
        const int alg = int(m.value(QLatin1String("alg")).toInteger(0));
        if (crypto::isSupportedAlg(alg)) {
            p->alg = alg;
            break;
        }
    }
    if (p->alg == 0) {
        finish(ErrUnsupportedAlgorithm);
        return;
    }

    std::optional<bool> rk, uv, up;
    const QCborValue options = params.value(7);
    if (!options.isUndefined()) {
        if (!options.isMap() || !readOption(options.toMap(), "rk", &rk) || !readOption(options.toMap(), "uv", &uv)
            || !readOption(options.toMap(), "up", &up)) {
            finish(ErrCborUnexpectedType);
            return;
        }
    }
    if (up.has_value() && !*up) {
        finish(ErrInvalidOption); // makeCredential always requires user presence
        return;
    }
    p->rk = rk.value_or(false);
    p->uv = uv.value_or(false);
    if (p->uv && !uvSupported()) {
        finish(ErrUnsupportedOption);
        return;
    }

    // A zero-length pinUvAuthParam is the "touch to select this authenticator"
    // probe; otherwise it must be a valid pinUvAuthToken MAC (CTAP 2.1).
    const QCborValue pinAuth = params.value(8);
    if (!pinAuth.isUndefined()) {
        if (pinAuth.isByteArray() && pinAuth.toByteArray().isEmpty()) {
            PresenceRequest req;
            req.kind = PresenceRequest::Kind::Selection;
            req.rpId = p->rpId;
            req.rpName = p->rpName;
            collectUser(req, false, [this](int) { finish(ErrPinNotSet); });
            return;
        }
        const quint8 st = checkPinUvAuth(pinAuth, params.value(9), p->clientDataHash, PermMakeCredential, p->rpId, &p->uvDone);
        if (st != Ok) {
            finish(st);
            return;
        }
        p->uv = true;
    }

    // excludeList: if a listed credential exists here, wait for UP, then report it.
    const QCborValue exclude = params.value(5);
    if (!exclude.isUndefined()) {
        if (!exclude.isArray()) {
            finish(ErrCborUnexpectedType);
            return;
        }
        for (const QCborValue &entry : exclude.toArray()) {
            const QByteArray id = entry.toMap().value(QLatin1String("id")).toByteArray();
            if (id.size() == CredentialIdSize && m_store->find(p->rpId, id)) {
                PresenceRequest req;
                req.kind = PresenceRequest::Kind::Excluded;
                req.rpId = p->rpId;
                req.rpName = p->rpName;
                collectUser(req, false, [this](int) { finish(ErrCredentialExcluded); });
                return;
            }
        }
    }

    PresenceRequest req;
    req.kind = PresenceRequest::Kind::Register;
    req.rpId = p->rpId;
    req.rpName = p->rpName;
    req.userName = p->userName;
    req.userDisplayName = p->userDisplayName;
    req.userVerificationFollows = p->uv && !p->uvDone;
    collectUser(req, p->uv && !p->uvDone, [this, p](int) { makeCredentialConfirmed(p); });
}

void Authenticator::makeCredentialConfirmed(const std::shared_ptr<Pending> &p)
{
    auto keyPair = crypto::generateKeyPair(p->alg);
    if (!keyPair) {
        qCWarning(KPASSKEY_LOG) << "key generation failed";
        finish(ErrOther);
        return;
    }

    CredentialRecord r;
    r.credentialId = crypto::randomBytes(CredentialIdSize);
    r.rpId = p->rpId;
    r.rpName = p->rpName;
    r.userHandle = p->userHandle;
    r.userName = p->userName;
    r.userDisplayName = p->userDisplayName;
    r.coseAlg = p->alg;
    r.publicKeyCose = keyPair->publicKeyCose;
    r.privateKeyPkcs8 = keyPair->privateKeyPkcs8;
    r.signCount = 0;
    r.discoverable = p->rk;
    r.uvAtCreation = p->uv;
    r.created = QDateTime::currentDateTimeUtc();

    // A new discoverable credential replaces an existing one for the same account.
    QList<QString> replaced;
    if (r.discoverable) {
        for (const CredentialRecord &old : m_store->findByRp(r.rpId)) {
            if (old.discoverable && old.userHandle == r.userHandle) {
                replaced.append(old.credentialIdB64());
            }
        }
    }

    // Persist BEFORE releasing anything to the client.
    if (!m_store->put(r)) {
        qCWarning(KPASSKEY_LOG) << "failed to persist new credential";
        finish(ErrKeyStoreFull);
        return;
    }
    for (const QString &id : std::as_const(replaced)) {
        m_store->remove(id);
    }

    quint8 flags = FlagUP | FlagAT; // BE/BS stay 0: KWallet credentials are device-bound
    if (p->uv) {
        flags |= FlagUV;
    }
    const QByteArray authData = crypto::sha256(p->rpId.toUtf8()) + QByteArray(1, char(flags))
        + bigEndian32(r.signCount) + m_options.aaguid + bigEndian16(quint16(r.credentialId.size())) + r.credentialId
        + r.publicKeyCose;

    // "packed" self attestation: signed with the credential key itself, which
    // reveals nothing beyond the new public key.
    const auto sig = crypto::sign(r.privateKeyPkcs8, r.coseAlg, authData + p->clientDataHash);
    if (!sig) {
        m_store->remove(r.credentialIdB64());
        finish(ErrOther);
        return;
    }
    QCborMap attStmt; // canonical order: "alg", "sig"
    attStmt.insert(QStringLiteral("alg"), r.coseAlg);
    attStmt.insert(QStringLiteral("sig"), *sig);

    QCborMap resp;
    resp.insert(1, QStringLiteral("packed"));
    resp.insert(2, authData);
    resp.insert(3, attStmt);
    qCInfo(KPASSKEY_LOG) << "created credential for" << r.rpId;
    finish(Ok, resp);
}

void Authenticator::getAssertion(const QCborMap &params)
{
    auto p = std::make_shared<Pending>();

    const QCborValue rpId = params.value(1);
    const QCborValue cdh = params.value(2);
    if (rpId.isUndefined() || cdh.isUndefined()) {
        finish(ErrMissingParameter);
        return;
    }
    if (!rpId.isString() || !cdh.isByteArray()) {
        finish(ErrCborUnexpectedType);
        return;
    }
    p->rpId = rpId.toString();
    p->clientDataHash = cdh.toByteArray();
    if (!isPlausibleRpId(p->rpId) || p->clientDataHash.size() != ClientDataHashSize) {
        finish(ErrInvalidParameter);
        return;
    }

    std::optional<bool> uv, up, rk;
    const QCborValue options = params.value(5);
    if (!options.isUndefined()) {
        if (!options.isMap() || !readOption(options.toMap(), "uv", &uv) || !readOption(options.toMap(), "up", &up)
            || !readOption(options.toMap(), "rk", &rk)) {
            finish(ErrCborUnexpectedType);
            return;
        }
    }
    if (rk.has_value()) {
        finish(ErrUnsupportedOption); // "rk" is not a valid getAssertion option
        return;
    }
    p->uv = uv.value_or(false);
    p->up = up.value_or(true);
    if (p->uv && !uvSupported()) {
        finish(ErrUnsupportedOption);
        return;
    }

    const QCborValue pinAuth = params.value(6);
    if (!pinAuth.isUndefined()) {
        if (pinAuth.isByteArray() && pinAuth.toByteArray().isEmpty()) {
            PresenceRequest req;
            req.kind = PresenceRequest::Kind::Selection;
            req.rpId = p->rpId;
            collectUser(req, false, [this](int) { finish(ErrPinNotSet); });
            return;
        }
        const quint8 st = checkPinUvAuth(pinAuth, params.value(7), p->clientDataHash, PermGetAssertion, p->rpId, &p->uvDone);
        if (st != Ok) {
            finish(st);
            return;
        }
        p->uv = true;
    }

    // Locate credentials. Lookups are always scoped to the requested RP ID, so
    // a credential ID of another RP can never be used here.
    const QCborValue allow = params.value(3);
    if (!allow.isUndefined()) {
        if (!allow.isArray()) {
            finish(ErrCborUnexpectedType);
            return;
        }
        const QCborArray list = allow.toArray();
        p->allowListGiven = !list.isEmpty();
        QSet<QByteArray> seen;
        for (const QCborValue &entry : list) {
            const QCborMap d = entry.toMap();
            if (d.value(QLatin1String("type")).toString() != QLatin1String("public-key")) {
                continue;
            }
            const QByteArray id = d.value(QLatin1String("id")).toByteArray();
            if (id.size() != CredentialIdSize || seen.contains(id)) {
                continue; // not one of ours (wrong size), or duplicate
            }
            seen.insert(id);
            if (auto r = m_store->find(p->rpId, id)) {
                p->candidates.append(std::move(*r));
            }
        }
    }
    if (!p->allowListGiven) {
        for (CredentialRecord &r : m_store->findByRp(p->rpId)) {
            if (r.discoverable) {
                p->candidates.append(std::move(r));
            }
        }
    }
    if (p->candidates.isEmpty()) {
        finish(ErrNoCredentials);
        return;
    }
    // Most recently used (or, if never used, most recently created) first; the
    // dialog preselects the first entry.
    const auto recency = [](const CredentialRecord &r) { return r.lastUsed.isValid() ? r.lastUsed : r.created; };
    std::sort(p->candidates.begin(), p->candidates.end(), [&](const CredentialRecord &a, const CredentialRecord &b) {
        return recency(a) > recency(b);
    });

    if (!p->up && (!p->uv || p->uvDone)) {
        // Silent assertion (UP=0). Relying parties must reject these for login;
        // browsers use them to probe whether a credential exists on this device.
        if (!m_options.allowSilentAssertions) {
            finish(ErrNoCredentials);
            return;
        }
        getAssertionConfirmed(p, 0);
        return;
    }

    PresenceRequest req;
    req.kind = PresenceRequest::Kind::Authenticate;
    req.rpId = p->rpId;
    req.userVerificationFollows = p->uv && !p->uvDone;
    for (const CredentialRecord &r : std::as_const(p->candidates)) {
        req.accounts.append({r.userName, r.userDisplayName});
    }
    p->up = true; // UP is collected by the prompt, even if only UV was requested
    collectUser(req, p->uv && !p->uvDone, [this, p](int index) { getAssertionConfirmed(p, index); });
}

void Authenticator::getAssertionConfirmed(const std::shared_ptr<Pending> &p, int index)
{
    if (index < 0 || index >= p->candidates.size()) {
        finish(ErrInvalidParameter);
        return;
    }
    // Re-read: the record may have changed or been deleted while the prompt was open.
    auto fresh = m_store->find(p->rpId, p->candidates.at(index).credentialId);
    if (!fresh) {
        finish(ErrNoCredentials);
        return;
    }
    CredentialRecord r = std::move(*fresh);
    if (r.signCount == std::numeric_limits<quint32>::max()) {
        finish(ErrOther); // never wrap the counter
        return;
    }
    r.signCount += 1;
    r.lastUsed = QDateTime::currentDateTimeUtc();
    // Persist the incremented counter BEFORE the signature leaves the daemon,
    // so a crash can never cause a counter value to be used twice.
    if (!m_store->put(r)) {
        qCWarning(KPASSKEY_LOG) << "failed to persist sign counter";
        finish(ErrOther);
        return;
    }

    quint8 flags = 0;
    if (p->up) {
        flags |= FlagUP;
    }
    if (p->uv) {
        flags |= FlagUV;
    }
    const QByteArray authData = crypto::sha256(r.rpId.toUtf8()) + QByteArray(1, char(flags)) + bigEndian32(r.signCount);
    const auto sig = crypto::sign(r.privateKeyPkcs8, r.coseAlg, authData + p->clientDataHash);
    if (!sig) {
        finish(ErrOther);
        return;
    }

    QCborMap cred; // canonical order: "id", "type"
    cred.insert(QStringLiteral("id"), r.credentialId);
    cred.insert(QStringLiteral("type"), QStringLiteral("public-key"));

    QCborMap resp;
    resp.insert(1, cred);
    resp.insert(2, authData);
    resp.insert(3, *sig);
    if (!p->allowListGiven) {
        QCborMap user; // canonical order: "id", "name", "displayName"
        user.insert(QStringLiteral("id"), r.userHandle);
        if (p->uv) { // identifying information only after user verification
            if (!r.userName.isEmpty()) {
                user.insert(QStringLiteral("name"), r.userName);
            }
            if (!r.userDisplayName.isEmpty()) {
                user.insert(QStringLiteral("displayName"), r.userDisplayName);
            }
        }
        resp.insert(4, user);
    }
    finish(Ok, resp);
}

} // namespace kpasskey
