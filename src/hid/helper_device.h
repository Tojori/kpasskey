// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include "hid_transport.h"

class QLocalSocket;

namespace kpasskey {

// Production mode: the virtual device is owned by kpasskey-uhid-helper; we
// exchange raw reports with it over /run/kpasskey/uhid.sock.
class HelperDevice : public HidTransport
{
    Q_OBJECT
public:
    explicit HelperDevice(QObject *parent = nullptr);
    ~HelperDevice() override;

    static bool isAvailable();
    bool create(QString *error) override;
    void destroy() override;

public Q_SLOTS:
    void sendInputReport(const QByteArray &report) override;

private:
    void onReadyRead();

    QLocalSocket *m_socket = nullptr;
    QByteArray m_buffer;
    bool m_destroying = false;
};

} // namespace kpasskey
