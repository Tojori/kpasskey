// SPDX-License-Identifier: LGPL-2.1-or-later
// Virtual FIDO HID device via the Linux uhid driver (Documentation/hid/uhid.rst).
#pragma once

#include "hid_transport.h"

class QSocketNotifier;

namespace kpasskey {

// Direct mode: kpasskeyd itself opens /dev/uhid (development only; needs the
// uaccess udev rule). Production uses HelperDevice.
class UhidDevice : public HidTransport
{
    Q_OBJECT
public:
    explicit UhidDevice(QObject *parent = nullptr);
    ~UhidDevice() override;

    bool create(QString *error) override;
    void destroy() override;

public Q_SLOTS:
    void sendInputReport(const QByteArray &report) override;

Q_SIGNALS:
    void openedChanged(bool opened); // a host process (browser) has the hidraw node open

private:
    void readEvent();
    bool writeEvent(const void *ev, size_t size);

    int m_fd = -1;
    QSocketNotifier *m_notifier = nullptr;
};

} // namespace kpasskey
