// SPDX-License-Identifier: LGPL-2.1-or-later
// CTAPHID framing (CTAP 2.x, section 11.2 "USB Human Interface Device").
// Transport agnostic: consumes and produces 64 byte HID reports.
#pragma once

#include "core/authenticator.h"

#include <QByteArray>
#include <QList>
#include <QObject>
#include <QTimer>

namespace kpasskey {

class CtapHid : public QObject
{
    Q_OBJECT
public:
    static constexpr int ReportSize = 64;
    static constexpr int MaxMessageSize = ReportSize - 7 + 128 * (ReportSize - 5); // 7609
    static constexpr quint32 BroadcastCid = 0xffffffff;

    enum Cmd : quint8 {
        Ping = 0x01,
        Msg = 0x03,
        Lock = 0x04,
        Init = 0x06,
        Wink = 0x08,
        Cbor = 0x10,
        Cancel = 0x11,
        Keepalive = 0x3b,
        Error = 0x3f,
    };
    enum Err : quint8 {
        ErrInvalidCmd = 0x01,
        ErrInvalidLen = 0x03,
        ErrInvalidSeq = 0x04,
        ErrMsgTimeout = 0x05,
        ErrChannelBusy = 0x06,
        ErrInvalidChannel = 0x0b,
    };

    explicit CtapHid(CborProcessor *processor, QObject *parent = nullptr);

    // Feeds one output report written by the host (64 bytes, or 65 with a
    // leading report ID 0 as delivered by uhid).
    void handleReport(QByteArray report);

    // For tests: shorten the inter-packet timeout.
    void setAssemblyTimeout(int ms) { m_assemblyTimer.setInterval(ms); }

Q_SIGNALS:
    void reportReady(const QByteArray &report);

private:
    void handleInit(quint32 cid, const QByteArray &data, int bcnt);
    void dispatch(quint32 cid, quint8 cmd, const QByteArray &payload);
    void send(quint32 cid, quint8 cmd, const QByteArray &payload);
    void sendError(quint32 cid, quint8 code);
    void abortAssembly();
    quint32 allocateChannel();

    CborProcessor *m_processor;
    QList<quint32> m_channels; // allocated CIDs, oldest first

    // Message assembly
    bool m_assembling = false;
    quint32 m_rxCid = 0;
    quint8 m_rxCmd = 0;
    int m_rxLen = 0;
    quint8 m_rxSeq = 0;
    QByteArray m_rxBuf;
    QTimer m_assemblyTimer;

    // CBOR transaction in progress
    bool m_processing = false;
    quint32 m_busyCid = 0;
    quint64 m_txToken = 0;
    QTimer m_keepaliveTimer;
};

} // namespace kpasskey
