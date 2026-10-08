// SPDX-License-Identifier: LGPL-2.1-or-later
#include "tpm_client.h"

#include "core/crypto.h"
#include "core/logging.h"
#include "core/tpm_protocol.h"

#include <QFileInfo>
#include <QLocalSocket>
#include <QtEndian>

namespace kpasskey {

namespace {
constexpr int TimeoutMs = 10000;

bool readExactly(QLocalSocket *s, char *out, qint64 size)
{
    qint64 got = 0;
    while (got < size) {
        if (s->bytesAvailable() == 0 && !s->waitForReadyRead(TimeoutMs)) {
            return false;
        }
        const qint64 n = s->read(out + got, size - got);
        if (n < 0) {
            return false;
        }
        got += n;
    }
    return true;
}
} // namespace

TpmClient::TpmClient(QObject *parent)
    : QObject(parent)
{
}

TpmClient::~TpmClient() = default;

bool TpmClient::isAvailable()
{
    return QFileInfo(QLatin1String(tpmproto::SocketPath)).exists();
}

bool TpmClient::ensureConnected()
{
    if (m_socket && m_socket->state() == QLocalSocket::ConnectedState) {
        return true;
    }
    delete m_socket;
    m_socket = new QLocalSocket(this);
    m_socket->connectToServer(QLatin1String(tpmproto::SocketPath));
    if (!m_socket->waitForConnected(TimeoutMs)) {
        qCWarning(KPASSKEY_LOG) << "cannot connect to kpasskey-tpm-helper:" << m_socket->errorString();
        return false;
    }
    return true;
}

std::optional<QByteArray> TpmClient::request(quint8 op, const QByteArray &payload)
{
    // One retry: the helper instance may have exited (e.g. after a session change).
    for (int attempt = 0; attempt < 2; ++attempt) {
        if (!ensureConnected()) {
            return std::nullopt;
        }
        QByteArray msg(1, char(op));
        QByteArray len(4, '\0');
        qToBigEndian(quint32(payload.size()), len.data());
        msg += len + payload;
        m_socket->write(msg);
        if (!m_socket->waitForBytesWritten(TimeoutMs)) {
            m_socket->abort();
            continue;
        }
        char header[5];
        if (!readExactly(m_socket, header, sizeof(header))) {
            m_socket->abort();
            continue;
        }
        const quint32 size = qFromBigEndian<quint32>(header + 1);
        if (size > tpmproto::MaxPayload) {
            m_socket->abort();
            return std::nullopt;
        }
        QByteArray body(qsizetype(size), '\0');
        if (size && !readExactly(m_socket, body.data(), size)) {
            m_socket->abort();
            return std::nullopt;
        }
        if (quint8(header[0]) != tpmproto::Ok) {
            qCWarning(KPASSKEY_LOG) << "kpasskey-tpm-helper returned status" << int(quint8(header[0]));
            return std::nullopt;
        }
        return body;
    }
    return std::nullopt;
}

std::optional<HardwareKeyStore::Key> TpmClient::createKey()
{
    auto blob = request(tpmproto::CreateKey, {});
    if (!blob) {
        return std::nullopt;
    }
    auto cose = tpmblob::publicKeyCose(*blob);
    if (!cose) {
        qCWarning(KPASSKEY_LOG) << "TPM helper returned an unexpected key blob";
        return std::nullopt;
    }
    return Key{*blob, *cose};
}

std::optional<QByteArray> TpmClient::signDigest(const QByteArray &blob, const QByteArray &digest)
{
    if (digest.size() != 32) {
        return std::nullopt;
    }
    auto rs = request(tpmproto::SignDigest, digest + blob);
    if (!rs) {
        return std::nullopt;
    }
    return crypto::ecdsaRawToDer(*rs);
}

} // namespace kpasskey
