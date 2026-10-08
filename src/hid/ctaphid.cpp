// SPDX-License-Identifier: LGPL-2.1-or-later
#include "ctaphid.h"

#include "core/crypto.h"
#include "core/logging.h"

#include <QtEndian>

namespace kpasskey {

namespace {
constexpr int MaxChannels = 32;
constexpr quint8 CapCbor = 0x04;
constexpr quint8 CapNoMsg = 0x08; // CTAP1/U2F (CTAPHID_MSG) is not implemented
constexpr quint8 KeepaliveProcessing = 1;
constexpr quint8 KeepaliveUpNeeded = 2;
} // namespace

CtapHid::CtapHid(CborProcessor *processor, QObject *parent)
    : QObject(parent)
    , m_processor(processor)
{
    m_assemblyTimer.setSingleShot(true);
    m_assemblyTimer.setInterval(500);
    connect(&m_assemblyTimer, &QTimer::timeout, this, [this] {
        if (m_assembling) {
            const quint32 cid = m_rxCid;
            abortAssembly();
            sendError(cid, ErrMsgTimeout);
        }
    });
    m_keepaliveTimer.setInterval(100);
    connect(&m_keepaliveTimer, &QTimer::timeout, this, [this] {
        if (m_processing) {
            const bool waiting = m_processor->activity() == CborProcessor::Activity::WaitingForUser;
            send(m_busyCid, Keepalive, QByteArray(1, char(waiting ? KeepaliveUpNeeded : KeepaliveProcessing)));
        }
    });
}

void CtapHid::handleReport(QByteArray report)
{
    if (report.size() == ReportSize + 1) {
        report.remove(0, 1); // leading report ID (always 0, the FIDO descriptor has none)
    }
    if (report.size() != ReportSize) {
        return;
    }
    const quint32 cid = qFromBigEndian<quint32>(report.constData());
    const quint8 b4 = quint8(report.at(4));

    if (b4 & 0x80) { // initialization packet
        const quint8 cmd = b4 & 0x7f;
        const int bcnt = qFromBigEndian<quint16>(report.constData() + 5);
        const QByteArray data = report.mid(7);

        if (cid == 0) {
            sendError(cid, ErrInvalidChannel);
            return;
        }
        if (cmd == Init) {
            handleInit(cid, data, bcnt);
            return;
        }
        if (cid == BroadcastCid || !m_channels.contains(cid)) {
            sendError(cid, ErrInvalidChannel);
            return;
        }
        if (cmd == Cancel) {
            if (m_processing && cid == m_busyCid) {
                m_processor->cancel(); // completes the pending request with KEEPALIVE_CANCEL
            }
            return; // CANCEL itself has no response
        }
        if (m_assembling && cid == m_rxCid) {
            abortAssembly();
            sendError(cid, ErrInvalidSeq);
            return;
        }
        if (m_processing || m_assembling) {
            sendError(cid, ErrChannelBusy);
            return;
        }
        if (bcnt > MaxMessageSize) {
            sendError(cid, ErrInvalidLen);
            return;
        }
        if (bcnt <= data.size()) {
            dispatch(cid, cmd, data.left(bcnt));
            return;
        }
        m_assembling = true;
        m_rxCid = cid;
        m_rxCmd = cmd;
        m_rxLen = bcnt;
        m_rxSeq = 0;
        m_rxBuf = data;
        m_assemblyTimer.start();
        return;
    }

    // continuation packet
    if (!m_assembling || cid != m_rxCid) {
        return; // spurious continuation packets are ignored
    }
    if (b4 != m_rxSeq) {
        abortAssembly();
        sendError(cid, ErrInvalidSeq);
        return;
    }
    ++m_rxSeq;
    m_rxBuf += report.mid(5, std::min<int>(ReportSize - 5, m_rxLen - int(m_rxBuf.size())));
    if (m_rxBuf.size() >= m_rxLen) {
        const QByteArray payload = m_rxBuf.left(m_rxLen);
        const quint8 cmd = m_rxCmd;
        abortAssembly();
        dispatch(cid, cmd, payload);
    } else {
        m_assemblyTimer.start();
    }
}

void CtapHid::handleInit(quint32 cid, const QByteArray &data, int bcnt)
{
    if (bcnt != 8) {
        sendError(cid, ErrInvalidLen);
        return;
    }
    quint32 replyCid = cid;
    if (cid == BroadcastCid) {
        replyCid = allocateChannel();
    } else if (!m_channels.contains(cid)) {
        sendError(cid, ErrInvalidChannel);
        return;
    } else {
        // Resynchronisation on an existing channel aborts whatever it was doing.
        if (m_assembling && m_rxCid == cid) {
            abortAssembly();
        }
        if (m_processing && m_busyCid == cid) {
            ++m_txToken; // drop the late response
            m_processing = false;
            m_keepaliveTimer.stop();
            m_processor->cancel();
        }
    }
    QByteArray resp = data.left(8); // nonce
    QByteArray cidBytes(4, '\0');
    qToBigEndian(replyCid, cidBytes.data());
    resp += cidBytes;
    resp += char(2);                      // CTAPHID protocol version
    resp += QByteArray("\x00\x01\x00", 3); // device version 0.1.0
    resp += char(CapCbor | CapNoMsg);
    send(cid, Init, resp);
}

quint32 CtapHid::allocateChannel()
{
    quint32 cid = 0;
    do {
        cid = qFromBigEndian<quint32>(crypto::randomBytes(4).constData());
    } while (cid == 0 || cid == BroadcastCid || m_channels.contains(cid));
    if (m_channels.size() >= MaxChannels && !(m_processing && m_channels.first() == m_busyCid)) {
        m_channels.removeFirst();
    }
    m_channels.append(cid);
    return cid;
}

void CtapHid::dispatch(quint32 cid, quint8 cmd, const QByteArray &payload)
{
    switch (cmd) {
    case Ping:
        send(cid, Ping, payload);
        return;
    case Cbor: {
        if (payload.isEmpty()) {
            sendError(cid, ErrInvalidLen);
            return;
        }
        m_processing = true;
        m_busyCid = cid;
        const quint64 token = ++m_txToken;
        m_keepaliveTimer.start();
        m_processor->process(payload, [this, cid, token](const QByteArray &response) {
            if (token != m_txToken) {
                return;
            }
            m_processing = false;
            m_keepaliveTimer.stop();
            send(cid, Cbor, response);
        });
        return;
    }
    default:
        // MSG (U2F), LOCK and WINK are not offered.
        sendError(cid, ErrInvalidCmd);
        return;
    }
}

void CtapHid::send(quint32 cid, quint8 cmd, const QByteArray &payload)
{
    QByteArray cidBytes(4, '\0');
    qToBigEndian(cid, cidBytes.data());

    QByteArray pkt = cidBytes;
    pkt += char(cmd | 0x80);
    QByteArray len(2, '\0');
    qToBigEndian(quint16(payload.size()), len.data());
    pkt += len;
    int offset = std::min<int>(ReportSize - 7, int(payload.size()));
    pkt += payload.left(offset);
    pkt.resize(ReportSize, '\0');
    Q_EMIT reportReady(pkt);

    quint8 seq = 0;
    while (offset < payload.size()) {
        QByteArray cont = cidBytes;
        cont += char(seq++);
        const int n = std::min<int>(ReportSize - 5, int(payload.size()) - offset);
        cont += payload.mid(offset, n);
        cont.resize(ReportSize, '\0');
        offset += n;
        Q_EMIT reportReady(cont);
    }
}

void CtapHid::sendError(quint32 cid, quint8 code)
{
    send(cid, Error, QByteArray(1, char(code)));
}

void CtapHid::abortAssembly()
{
    m_assembling = false;
    m_rxBuf.clear();
    m_assemblyTimer.stop();
}

} // namespace kpasskey
