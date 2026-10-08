// SPDX-License-Identifier: LGPL-2.1-or-later
#include "helper_device.h"

#include "core/logging.h"
#include "fido_descriptor.h"

#include <QFileInfo>
#include <QLocalSocket>

namespace kpasskey {

HelperDevice::HelperDevice(QObject *parent)
    : HidTransport(parent)
{
}

HelperDevice::~HelperDevice()
{
    destroy();
}

bool HelperDevice::isAvailable()
{
    return QFileInfo(QLatin1String(fido::HelperSocketPath)).exists();
}

bool HelperDevice::create(QString *error)
{
    if (m_socket) {
        return true;
    }
    m_socket = new QLocalSocket(this);
    m_socket->connectToServer(QLatin1String(fido::HelperSocketPath));
    if (!m_socket->waitForConnected(2000)) {
        *error = QStringLiteral("cannot connect to %1: %2").arg(QLatin1String(fido::HelperSocketPath), m_socket->errorString());
        delete m_socket;
        m_socket = nullptr;
        return false;
    }
    // The helper answers with a hello once the device exists; it closes the
    // connection instead if it refuses (no active local session, already a
    // device for this user, ...). Details are in the helper's journal.
    QByteArray hello;
    while (hello.size() < qsizetype(sizeof(fido::HelperHello)) && m_socket->waitForReadyRead(3000)) {
        hello += m_socket->read(qint64(sizeof(fido::HelperHello)) - hello.size());
    }
    if (hello != QByteArray(fido::HelperHello, sizeof(fido::HelperHello))) {
        *error = QStringLiteral("kpasskey-uhid-helper refused to create the device "
                                "(see: journalctl -u 'kpasskey-uhid@*')");
        delete m_socket;
        m_socket = nullptr;
        return false;
    }
    m_buffer = m_socket->readAll();
    connect(m_socket, &QLocalSocket::readyRead, this, &HelperDevice::onReadyRead);
    connect(m_socket, &QLocalSocket::disconnected, this, [this] {
        if (!m_destroying) {
            qCWarning(KPASSKEY_LOG) << "uhid helper closed the connection; device is gone";
            m_socket->deleteLater();
            m_socket = nullptr;
            Q_EMIT lost();
        }
    });
    qCInfo(KPASSKEY_LOG) << "virtual FIDO HID device created via kpasskey-uhid-helper";
    onReadyRead();
    return true;
}

void HelperDevice::destroy()
{
    if (!m_socket) {
        return;
    }
    m_destroying = true;
    m_socket->disconnectFromServer(); // the helper destroys the device on EOF
    delete m_socket;
    m_socket = nullptr;
    m_buffer.clear();
    m_destroying = false;
}

void HelperDevice::sendInputReport(const QByteArray &report)
{
    if (m_socket && report.size() == fido::ReportSize) {
        m_socket->write(report);
    }
}

void HelperDevice::onReadyRead()
{
    if (!m_socket) {
        return;
    }
    m_buffer += m_socket->readAll();
    while (m_buffer.size() >= fido::ReportSize) {
        Q_EMIT outputReport(m_buffer.left(fido::ReportSize));
        m_buffer.remove(0, fido::ReportSize);
    }
}

} // namespace kpasskey
