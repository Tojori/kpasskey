// SPDX-License-Identifier: LGPL-2.1-or-later
//
// kpasskey-tpm-helper: creates non-exportable ECC P-256 keys in the TPM and
// signs digests with them. The only kpasskey component with TPM access.
//
// Started by systemd per connection (kpasskey-tpm.socket, Accept=yes, client
// socket on stdin) as the system user "kpasskey-tpm" (member of group tss).
//
// Key hierarchy (nothing is stored on disk by the helper):
//   owner hierarchy
//    ├─ storage primary  ECC P-256, restricted decrypt, unique "kpasskey-srk-v1"
//    │    └─ passkey keys ECC P-256 ECDSA/SHA-256 sign, fixedTPM, noDA
//    └─ HMAC primary     keyed hash, unique "kpasskey-auth-v1"
// Primaries are re-derived deterministically from the owner seed on every run.
//
// Each passkey key gets authValue = HMAC_TPM(hmacPrimary, "kpasskey-key-auth-v1" || uid)
// where uid comes from SO_PEERCRED. A blob can therefore only be used by the
// user who created it, and only on this TPM. Keys are noDA: a wrong authValue
// (another user's blob) must not count towards the TPM's dictionary-attack
// lockout, which would otherwise be a DoS against every DA-protected key.
// The authValue is 256 bit and derived inside the TPM, so guessing is infeasible.
//
// All commands use a salted HMAC session with parameter encryption, so
// authValues and digests are not sent in clear over the TPM bus.

#include "core/tpm_protocol.h"

#include <systemd/sd-login.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tctildr.h>

#include <cerrno>
#include <csignal>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

using namespace kpasskey;

namespace {

constexpr int SocketFd = STDIN_FILENO;

void logMsg(const char *prio, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void logMsg(const char *prio, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    std::fputs(prio, stderr);
    std::vfprintf(stderr, fmt, ap);
    std::fputc('\n', stderr);
    va_end(ap);
}

bool readAll(int fd, void *data, size_t size)
{
    char *p = static_cast<char *>(data);
    while (size > 0) {
        const ssize_t n = ::read(fd, p, size);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            return false;
        }
        p += n;
        size -= size_t(n);
    }
    return true;
}

bool writeAll(int fd, const void *data, size_t size)
{
    const char *p = static_cast<const char *>(data);
    while (size > 0) {
        const ssize_t n = ::write(fd, p, size);
        if (n < 0 && errno == EINTR) {
            continue;
        }
        if (n <= 0) {
            return false;
        }
        p += n;
        size -= size_t(n);
    }
    return true;
}

bool reply(uint8_t status, const std::vector<uint8_t> &payload = {})
{
    uint8_t header[5] = {status, uint8_t(payload.size() >> 24), uint8_t(payload.size() >> 16),
                         uint8_t(payload.size() >> 8), uint8_t(payload.size())};
    return writeAll(SocketFd, header, sizeof(header)) && (payload.empty() || writeAll(SocketFd, payload.data(), payload.size()));
}

bool uidIsActiveLocally(uid_t uid)
{
    char *session = nullptr;
    if (sd_uid_get_display(uid, &session) < 0 || !session) {
        return false;
    }
    const bool ok = sd_session_is_active(session) > 0 && sd_session_is_remote(session) == 0;
    std::free(session);
    return ok;
}

constexpr TPMA_OBJECT KeyAttributes = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN
    | TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_NODA;

class Tpm
{
public:
    ~Tpm()
    {
        if (m_ctx) {
            for (ESYS_TR h : {m_session, m_hmacPrimary, m_storagePrimary}) {
                if (h != ESYS_TR_NONE) {
                    Esys_FlushContext(m_ctx, h);
                }
            }
            Esys_Finalize(&m_ctx);
        }
        if (m_tcti) {
            Tss2_TctiLdr_Finalize(&m_tcti);
        }
    }

    bool init(uid_t uid)
    {
        TSS2_RC rc = Tss2_TctiLdr_Initialize("device:/dev/tpmrm0", &m_tcti);
        if (rc == TSS2_RC_SUCCESS) {
            rc = Esys_Initialize(&m_ctx, m_tcti, nullptr);
        }
        if (rc != TSS2_RC_SUCCESS) {
            return fail("initialize", rc);
        }
        if (!createStoragePrimary() || !startSession() || !createHmacPrimary()) {
            return false;
        }
        return deriveAuth(uid);
    }

    bool createKey(std::vector<uint8_t> *blob)
    {
        TPM2B_SENSITIVE_CREATE sensitive {};
        sensitive.sensitive.userAuth = m_auth;
        TPM2B_PUBLIC tmpl {};
        tmpl.publicArea.type = TPM2_ALG_ECC;
        tmpl.publicArea.nameAlg = TPM2_ALG_SHA256;
        tmpl.publicArea.objectAttributes = KeyAttributes;
        tmpl.publicArea.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_NULL;
        tmpl.publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG_ECDSA;
        tmpl.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg = TPM2_ALG_SHA256;
        tmpl.publicArea.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
        tmpl.publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
        TPM2B_DATA outside {};
        TPML_PCR_SELECTION pcrs {};
        TPM2B_PRIVATE *outPrivate = nullptr;
        TPM2B_PUBLIC *outPublic = nullptr;
        TSS2_RC rc = Esys_Create(m_ctx, m_storagePrimary, m_session, ESYS_TR_NONE, ESYS_TR_NONE, &sensitive, &tmpl,
                                 &outside, &pcrs, &outPrivate, &outPublic, nullptr, nullptr, nullptr);
        if (rc != TSS2_RC_SUCCESS) {
            return fail("Create", rc);
        }
        blob->assign(sizeof(TPM2B_PUBLIC) + sizeof(TPM2B_PRIVATE), 0);
        size_t offset = 0;
        rc = Tss2_MU_TPM2B_PUBLIC_Marshal(outPublic, blob->data(), blob->size(), &offset);
        if (rc == TSS2_RC_SUCCESS) {
            rc = Tss2_MU_TPM2B_PRIVATE_Marshal(outPrivate, blob->data(), blob->size(), &offset);
        }
        Esys_Free(outPrivate);
        Esys_Free(outPublic);
        if (rc != TSS2_RC_SUCCESS) {
            return fail("marshal", rc);
        }
        blob->resize(offset);
        return true;
    }

    bool sign(const uint8_t *digest, const uint8_t *blob, size_t blobSize, std::vector<uint8_t> *rs)
    {
        TPM2B_PUBLIC pub {};
        TPM2B_PRIVATE priv {};
        size_t offset = 0;
        if (Tss2_MU_TPM2B_PUBLIC_Unmarshal(blob, blobSize, &offset, &pub) != TSS2_RC_SUCCESS
            || Tss2_MU_TPM2B_PRIVATE_Unmarshal(blob, blobSize, &offset, &priv) != TSS2_RC_SUCCESS || offset != blobSize
            || pub.publicArea.type != TPM2_ALG_ECC || pub.publicArea.objectAttributes != KeyAttributes
            || pub.publicArea.parameters.eccDetail.curveID != TPM2_ECC_NIST_P256) {
            logMsg("<4>", "rejecting malformed or foreign key blob");
            return false;
        }
        ESYS_TR key = ESYS_TR_NONE;
        TSS2_RC rc = Esys_Load(m_ctx, m_storagePrimary, m_session, ESYS_TR_NONE, ESYS_TR_NONE, &priv, &pub, &key);
        if (rc != TSS2_RC_SUCCESS) {
            return fail("Load", rc);
        }
        Esys_TR_SetAuth(m_ctx, key, &m_auth);
        TPM2B_DIGEST d {};
        d.size = 32;
        std::memcpy(d.buffer, digest, 32);
        TPMT_SIG_SCHEME scheme {};
        scheme.scheme = TPM2_ALG_ECDSA;
        scheme.details.ecdsa.hashAlg = TPM2_ALG_SHA256;
        TPMT_TK_HASHCHECK validation {};
        validation.tag = TPM2_ST_HASHCHECK;
        validation.hierarchy = TPM2_RH_NULL;
        TPMT_SIGNATURE *signature = nullptr;
        rc = Esys_Sign(m_ctx, key, m_session, ESYS_TR_NONE, ESYS_TR_NONE, &d, &scheme, &validation, &signature);
        Esys_FlushContext(m_ctx, key);
        if (rc != TSS2_RC_SUCCESS) {
            // TPM_RC_AUTH_FAIL here means: blob belongs to another uid.
            return fail("Sign", rc);
        }
        const auto &r = signature->signature.ecdsa.signatureR;
        const auto &s = signature->signature.ecdsa.signatureS;
        bool ok = r.size <= 32 && s.size <= 32;
        if (ok) {
            rs->assign(64, 0);
            std::memcpy(rs->data() + (32 - r.size), r.buffer, r.size);
            std::memcpy(rs->data() + 32 + (32 - s.size), s.buffer, s.size);
        }
        Esys_Free(signature);
        return ok;
    }

private:
    bool fail(const char *what, TSS2_RC rc)
    {
        logMsg("<4>", "TPM %s failed: 0x%08x", what, unsigned(rc));
        return false;
    }

    bool createStoragePrimary()
    {
        TPM2B_SENSITIVE_CREATE sensitive {};
        TPM2B_PUBLIC tmpl {};
        tmpl.publicArea.type = TPM2_ALG_ECC;
        tmpl.publicArea.nameAlg = TPM2_ALG_SHA256;
        tmpl.publicArea.objectAttributes = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN
            | TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT | TPMA_OBJECT_NODA;
        tmpl.publicArea.parameters.eccDetail.symmetric.algorithm = TPM2_ALG_AES;
        tmpl.publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
        tmpl.publicArea.parameters.eccDetail.symmetric.mode.aes = TPM2_ALG_CFB;
        tmpl.publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG_NULL;
        tmpl.publicArea.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
        tmpl.publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
        static const char label[] = "kpasskey-srk-v1";
        tmpl.publicArea.unique.ecc.x.size = sizeof(label) - 1;
        std::memcpy(tmpl.publicArea.unique.ecc.x.buffer, label, sizeof(label) - 1);
        TPM2B_DATA outside {};
        TPML_PCR_SELECTION pcrs {};
        // Owner hierarchy auth is assumed empty (the common default). The
        // command parameters contain no secrets, so a password session is fine.
        const TSS2_RC rc = Esys_CreatePrimary(m_ctx, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                                              &sensitive, &tmpl, &outside, &pcrs, &m_storagePrimary, nullptr, nullptr,
                                              nullptr, nullptr);
        return rc == TSS2_RC_SUCCESS || fail("CreatePrimary(storage)", rc);
    }

    bool startSession()
    {
        TPMT_SYM_DEF sym {};
        sym.algorithm = TPM2_ALG_AES;
        sym.keyBits.aes = 128;
        sym.mode.aes = TPM2_ALG_CFB;
        // Salted with the storage primary: the session key is unknown to bus sniffers.
        TSS2_RC rc = Esys_StartAuthSession(m_ctx, m_storagePrimary, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                           ESYS_TR_NONE, nullptr, TPM2_SE_HMAC, &sym, TPM2_ALG_SHA256, &m_session);
        if (rc != TSS2_RC_SUCCESS) {
            return fail("StartAuthSession", rc);
        }
        const TPMA_SESSION attrs = TPMA_SESSION_DECRYPT | TPMA_SESSION_ENCRYPT | TPMA_SESSION_CONTINUESESSION;
        rc = Esys_TRSess_SetAttributes(m_ctx, m_session, attrs, 0xff);
        return rc == TSS2_RC_SUCCESS || fail("TRSess_SetAttributes", rc);
    }

    bool createHmacPrimary()
    {
        TPM2B_SENSITIVE_CREATE sensitive {};
        TPM2B_PUBLIC tmpl {};
        tmpl.publicArea.type = TPM2_ALG_KEYEDHASH;
        tmpl.publicArea.nameAlg = TPM2_ALG_SHA256;
        tmpl.publicArea.objectAttributes = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN
            | TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_SIGN_ENCRYPT | TPMA_OBJECT_NODA;
        tmpl.publicArea.parameters.keyedHashDetail.scheme.scheme = TPM2_ALG_HMAC;
        tmpl.publicArea.parameters.keyedHashDetail.scheme.details.hmac.hashAlg = TPM2_ALG_SHA256;
        static const char label[] = "kpasskey-auth-v1";
        tmpl.publicArea.unique.keyedHash.size = sizeof(label) - 1;
        std::memcpy(tmpl.publicArea.unique.keyedHash.buffer, label, sizeof(label) - 1);
        TPM2B_DATA outside {};
        TPML_PCR_SELECTION pcrs {};
        const TSS2_RC rc = Esys_CreatePrimary(m_ctx, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                                              &sensitive, &tmpl, &outside, &pcrs, &m_hmacPrimary, nullptr, nullptr,
                                              nullptr, nullptr);
        return rc == TSS2_RC_SUCCESS || fail("CreatePrimary(hmac)", rc);
    }

    bool deriveAuth(uid_t uid)
    {
        static const char label[] = "kpasskey-key-auth-v1";
        TPM2B_MAX_BUFFER msg {};
        msg.size = uint16_t(sizeof(label) - 1 + sizeof(uint32_t));
        std::memcpy(msg.buffer, label, sizeof(label) - 1);
        const uint32_t u = uint32_t(uid);
        std::memcpy(msg.buffer + sizeof(label) - 1, &u, sizeof(u));
        TPM2B_DIGEST *out = nullptr;
        // The response (the authValue) is encrypted by the session.
        const TSS2_RC rc = Esys_HMAC(m_ctx, m_hmacPrimary, m_session, ESYS_TR_NONE, ESYS_TR_NONE, &msg, TPM2_ALG_SHA256, &out);
        if (rc != TSS2_RC_SUCCESS) {
            return fail("HMAC", rc);
        }
        m_auth.size = out->size;
        std::memcpy(m_auth.buffer, out->buffer, out->size);
        Esys_Free(out);
        return true;
    }

    TSS2_TCTI_CONTEXT *m_tcti = nullptr;
    ESYS_CONTEXT *m_ctx = nullptr;
    ESYS_TR m_storagePrimary = ESYS_TR_NONE;
    ESYS_TR m_hmacPrimary = ESYS_TR_NONE;
    ESYS_TR m_session = ESYS_TR_NONE;
    TPM2B_AUTH m_auth {};
};

} // namespace

int main()
{
    std::signal(SIGPIPE, SIG_IGN);

    ucred cred {};
    socklen_t len = sizeof(cred);
    if (getsockopt(SocketFd, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) {
        logMsg("<3>", "stdin is not a Unix socket: %s", std::strerror(errno));
        return 2;
    }
    if (cred.uid == 0 || !uidIsActiveLocally(cred.uid)) {
        logMsg("<4>", "refusing uid %u (root or no active local session)", unsigned(cred.uid));
        return 3;
    }

    Tpm tpm;
    if (!tpm.init(cred.uid)) {
        reply(tpmproto::TpmError);
        return 4;
    }

    std::vector<uint8_t> payload;
    for (;;) {
        uint8_t header[5];
        if (!readAll(SocketFd, header, sizeof(header))) {
            break; // client closed
        }
        const uint32_t size = (uint32_t(header[1]) << 24) | (uint32_t(header[2]) << 16) | (uint32_t(header[3]) << 8) | header[4];
        if (size > tpmproto::MaxPayload) {
            reply(tpmproto::BadRequest);
            break;
        }
        payload.assign(size, 0);
        if (size && !readAll(SocketFd, payload.data(), size)) {
            break;
        }
        std::vector<uint8_t> out;
        switch (header[0]) {
        case tpmproto::CreateKey:
            if (size != 0) {
                reply(tpmproto::BadRequest);
            } else if (tpm.createKey(&out)) {
                logMsg("<6>", "created TPM key for uid %u", unsigned(cred.uid));
                reply(tpmproto::Ok, out);
            } else {
                reply(tpmproto::TpmError);
            }
            break;
        case tpmproto::SignDigest:
            if (size <= 32) {
                reply(tpmproto::BadRequest);
            } else if (tpm.sign(payload.data(), payload.data() + 32, size - 32, &out)) {
                reply(tpmproto::Ok, out);
            } else {
                reply(tpmproto::TpmError);
            }
            break;
        default:
            reply(tpmproto::BadRequest);
            break;
        }
    }
    return 0;
}
