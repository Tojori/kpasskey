// SPDX-License-Identifier: LGPL-2.1-or-later
#include "hid/ctaphid.h"

#include <QSignalSpy>
#include <QTest>
#include <QtEndian>

using namespace kpasskey;

namespace {

class FakeProcessor : public CborProcessor
{
public:
    std::function<void(QByteArray)> pending;
    QByteArray lastRequest;
    bool deferred = false;
    Activity act = Activity::Processing;

    void process(const QByteArray &request, std::function<void(QByteArray)> done) override
    {
        lastRequest = request;
        if (deferred) {
            pending = std::move(done);
        } else {
            done(QByteArray(1, '\0') + request); // echo with status OK
        }
    }
    void cancel() override
    {
        if (pending) {
            auto d = std::move(pending);
            pending = nullptr;
            d(QByteArray(1, char(0x2D)));
        }
    }
    Activity activity() const override { return act; }
};

QByteArray initPacket(quint32 cid, quint8 cmd, const QByteArray &payload, int bcnt = -1)
{
    QByteArray p(4, '\0');
    qToBigEndian(cid, p.data());
    p += char(cmd | 0x80);
    QByteArray len(2, '\0');
    qToBigEndian(quint16(bcnt < 0 ? payload.size() : bcnt), len.data());
    p += len;
    p += payload.left(57);
    p.resize(64, '\0');
    return p;
}

QByteArray contPacket(quint32 cid, quint8 seq, const QByteArray &data)
{
    QByteArray p(4, '\0');
    qToBigEndian(cid, p.data());
    p += char(seq);
    p += data.left(59);
    p.resize(64, '\0');
    return p;
}

// Sends a full message fragmented into packets.
void sendMessage(CtapHid &hid, quint32 cid, quint8 cmd, const QByteArray &payload)
{
    hid.handleReport(initPacket(cid, cmd, payload));
    int offset = 57;
    quint8 seq = 0;
    while (offset < payload.size()) {
        hid.handleReport(contPacket(cid, seq++, payload.mid(offset, 59)));
        offset += 59;
    }
}

struct Reply {
    quint32 cid = 0;
    quint8 cmd = 0;
    QByteArray payload;
};

// Reassembles the first complete message from the captured reports.
Reply reassemble(const QList<QByteArray> &reports, quint8 skipCmd = 0)
{
    Reply r;
    int i = 0;
    for (; i < reports.size(); ++i) {
        const QByteArray &p = reports.at(i);
        if ((quint8(p.at(4)) & 0x80) && (quint8(p.at(4)) & 0x7f) != skipCmd) {
            break;
        }
    }
    if (i >= reports.size()) {
        return r;
    }
    const QByteArray &init = reports.at(i);
    r.cid = qFromBigEndian<quint32>(init.constData());
    r.cmd = quint8(init.at(4)) & 0x7f;
    const int len = qFromBigEndian<quint16>(init.constData() + 5);
    r.payload = init.mid(7, std::min(len, 57));
    for (++i; r.payload.size() < len && i < reports.size(); ++i) {
        r.payload += reports.at(i).mid(5, std::min<int>(59, len - int(r.payload.size())));
    }
    return r;
}

QList<QByteArray> reportsOf(const QSignalSpy &spy)
{
    QList<QByteArray> out;
    for (const auto &args : spy) {
        out.append(args.at(0).toByteArray());
    }
    return out;
}

} // namespace

class TestCtapHid : public QObject
{
    Q_OBJECT

    quint32 openChannel(CtapHid &hid)
    {
        QSignalSpy spy(&hid, &CtapHid::reportReady);
        const QByteArray nonce = "12345678";
        hid.handleReport(initPacket(CtapHid::BroadcastCid, CtapHid::Init, nonce));
        const Reply r = reassemble(reportsOf(spy));
        if (r.cmd != CtapHid::Init || r.payload.left(8) != nonce) {
            return 0;
        }
        return qFromBigEndian<quint32>(r.payload.constData() + 8);
    }

private Q_SLOTS:
    void initAllocatesChannel()
    {
        FakeProcessor proc;
        CtapHid hid(&proc);
        QSignalSpy spy(&hid, &CtapHid::reportReady);
        hid.handleReport(initPacket(CtapHid::BroadcastCid, CtapHid::Init, "abcdefgh"));
        const Reply r = reassemble(reportsOf(spy));
        QCOMPARE(r.cid, CtapHid::BroadcastCid);
        QCOMPARE(r.payload.size(), 17);
        QCOMPARE(r.payload.left(8), QByteArray("abcdefgh"));
        const quint32 cid = qFromBigEndian<quint32>(r.payload.constData() + 8);
        QVERIFY(cid != 0 && cid != CtapHid::BroadcastCid);
        QCOMPARE(quint8(r.payload.at(16)), quint8(0x0C)); // CBOR | NMSG
    }

    void pingMultiPacket()
    {
        FakeProcessor proc;
        CtapHid hid(&proc);
        const quint32 cid = openChannel(hid);
        QSignalSpy spy(&hid, &CtapHid::reportReady);
        QByteArray payload;
        for (int i = 0; i < 300; ++i) {
            payload += char(i);
        }
        sendMessage(hid, cid, CtapHid::Ping, payload);
        const Reply r = reassemble(reportsOf(spy));
        QCOMPARE(r.cmd, quint8(CtapHid::Ping));
        QCOMPARE(r.payload, payload);
    }

    void reportWithLeadingReportId()
    {
        FakeProcessor proc;
        CtapHid hid(&proc);
        QSignalSpy spy(&hid, &CtapHid::reportReady);
        hid.handleReport(QByteArray(1, '\0') + initPacket(CtapHid::BroadcastCid, CtapHid::Init, "abcdefgh"));
        QCOMPARE(reassemble(reportsOf(spy)).cmd, quint8(CtapHid::Init));
    }

    void cborRoundTrip()
    {
        FakeProcessor proc;
        CtapHid hid(&proc);
        const quint32 cid = openChannel(hid);
        QSignalSpy spy(&hid, &CtapHid::reportReady);
        const QByteArray req = QByteArray(1, char(0x04));
        sendMessage(hid, cid, CtapHid::Cbor, req);
        QCOMPARE(proc.lastRequest, req);
        const Reply r = reassemble(reportsOf(spy));
        QCOMPARE(r.cmd, quint8(CtapHid::Cbor));
        QCOMPARE(r.payload, QByteArray(1, '\0') + req);
    }

    void invalidSequence()
    {
        FakeProcessor proc;
        CtapHid hid(&proc);
        const quint32 cid = openChannel(hid);
        QSignalSpy spy(&hid, &CtapHid::reportReady);
        hid.handleReport(initPacket(cid, CtapHid::Ping, QByteArray(57, 'a'), 100));
        hid.handleReport(contPacket(cid, 5, QByteArray(59, 'b')));
        const Reply r = reassemble(reportsOf(spy));
        QCOMPARE(r.cmd, quint8(CtapHid::Error));
        QCOMPARE(quint8(r.payload.at(0)), quint8(CtapHid::ErrInvalidSeq));
    }

    void unknownChannel()
    {
        FakeProcessor proc;
        CtapHid hid(&proc);
        QSignalSpy spy(&hid, &CtapHid::reportReady);
        hid.handleReport(initPacket(0x01020304, CtapHid::Cbor, QByteArray(1, '\x04')));
        const Reply r = reassemble(reportsOf(spy));
        QCOMPARE(r.cmd, quint8(CtapHid::Error));
        QCOMPARE(quint8(r.payload.at(0)), quint8(CtapHid::ErrInvalidChannel));
        QVERIFY(proc.lastRequest.isEmpty());
    }

    void oversizedMessage()
    {
        FakeProcessor proc;
        CtapHid hid(&proc);
        const quint32 cid = openChannel(hid);
        QSignalSpy spy(&hid, &CtapHid::reportReady);
        hid.handleReport(initPacket(cid, CtapHid::Cbor, QByteArray(57, 'a'), 0xffff));
        QCOMPARE(quint8(reassemble(reportsOf(spy)).payload.at(0)), quint8(CtapHid::ErrInvalidLen));
    }

    void busyChannelAndCancel()
    {
        FakeProcessor proc;
        proc.deferred = true;
        proc.act = CborProcessor::Activity::WaitingForUser;
        CtapHid hid(&proc);
        const quint32 a = openChannel(hid);
        const quint32 b = openChannel(hid);
        QSignalSpy spy(&hid, &CtapHid::reportReady);

        sendMessage(hid, a, CtapHid::Cbor, QByteArray(1, '\x01'));
        QVERIFY(proc.pending);

        // second client is told the device is busy
        sendMessage(hid, b, CtapHid::Cbor, QByteArray(1, '\x02'));
        Reply busy = reassemble(reportsOf(spy));
        QCOMPARE(busy.cid, b);
        QCOMPARE(quint8(busy.payload.at(0)), quint8(CtapHid::ErrChannelBusy));

        // keepalives with status UPNEEDED while waiting for the user
        spy.clear();
        QTRY_VERIFY_WITH_TIMEOUT(!spy.isEmpty(), 1000);
        const Reply ka = reassemble(reportsOf(spy));
        QCOMPARE(ka.cmd, quint8(CtapHid::Keepalive));
        QCOMPARE(quint8(ka.payload.at(0)), quint8(2));

        // CANCEL from the owning channel ends the request with KEEPALIVE_CANCEL
        spy.clear();
        hid.handleReport(initPacket(a, CtapHid::Cancel, {}));
        const Reply done = reassemble(reportsOf(spy), CtapHid::Keepalive);
        QCOMPARE(done.cid, a);
        QCOMPARE(done.cmd, quint8(CtapHid::Cbor));
        QCOMPARE(done.payload, QByteArray(1, char(0x2D)));
    }

    void cancelFromOtherChannelIgnored()
    {
        FakeProcessor proc;
        proc.deferred = true;
        CtapHid hid(&proc);
        const quint32 a = openChannel(hid);
        const quint32 b = openChannel(hid);
        sendMessage(hid, a, CtapHid::Cbor, QByteArray(1, '\x01'));
        hid.handleReport(initPacket(b, CtapHid::Cancel, {}));
        QVERIFY(proc.pending); // still running
        proc.cancel();
    }

    void assemblyTimeout()
    {
        FakeProcessor proc;
        CtapHid hid(&proc);
        hid.setAssemblyTimeout(30);
        const quint32 cid = openChannel(hid);
        QSignalSpy spy(&hid, &CtapHid::reportReady);
        hid.handleReport(initPacket(cid, CtapHid::Ping, QByteArray(57, 'a'), 100));
        QTRY_VERIFY_WITH_TIMEOUT(!spy.isEmpty(), 1000);
        QCOMPARE(quint8(reassemble(reportsOf(spy)).payload.at(0)), quint8(CtapHid::ErrMsgTimeout));
    }

    void u2fMessageRejected()
    {
        FakeProcessor proc;
        CtapHid hid(&proc);
        const quint32 cid = openChannel(hid);
        QSignalSpy spy(&hid, &CtapHid::reportReady);
        sendMessage(hid, cid, CtapHid::Msg, QByteArray(10, 'x'));
        QCOMPARE(quint8(reassemble(reportsOf(spy)).payload.at(0)), quint8(CtapHid::ErrInvalidCmd));
    }
};

QTEST_GUILESS_MAIN(TestCtapHid)
#include "test_ctaphid.moc"
