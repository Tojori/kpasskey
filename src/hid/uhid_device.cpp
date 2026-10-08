// SPDX-License-Identifier: LGPL-2.1-or-later
#include "uhid_device.h"

#include "core/logging.h"
#include "fido_descriptor.h"

#include <QSocketNotifier>

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <linux/uhid.h>
#include <unistd.h>

namespace kpasskey {

UhidDevice::UhidDevice(QObject *parent)
    : HidTransport(parent)
{
}

UhidDevice::~UhidDevice()
{
    destroy();
}

bool UhidDevice::create(QString *error)
{
    if (m_fd >= 0) {
        return true; // already exists
    }
    m_fd =::open("/dev/uhid", O_RDWR | O_CLOEXEC | O_NONBLOCK);
    if (m_fd < 0) {
        const int e = errno;
        *error = QStringLiteral("cannot open /dev/uhid: %1").arg(QString::fromLocal8Bit(strerror(e)));
        if (e == EACCES) {
            *error += QStringLiteral(" (direct mode needs packaging/udev/70-kpasskey-uhid-dev.rules; normally use the helper, see docs/build.md)");
        }
        return false;
    }

    uhid_event ev;
    std::memset(&ev, 0, sizeof(ev));
    ev.type = UHID_CREATE2;
    std::strncpy(reinterpret_cast<char *>(ev.u.create2.name), fido::DeviceName, sizeof(ev.u.create2.name) - 1);
    std::strncpy(reinterpret_cast<char *>(ev.u.create2.phys), "kpasskeyd", sizeof(ev.u.create2.phys) - 1);
    std::strncpy(reinterpret_cast<char *>(ev.u.create2.uniq), "kpasskey-0", sizeof(ev.u.create2.uniq) - 1);
    std::memcpy(ev.u.create2.rd_data, fido::ReportDescriptor, sizeof(fido::ReportDescriptor));
    ev.u.create2.rd_size = sizeof(fido::ReportDescriptor);
    ev.u.create2.bus = BUS_USB; // browsers only enumerate USB-attached FIDO HID devices
    ev.u.create2.vendor = fido::Vendor;
    ev.u.create2.product = fido::Product;
    ev.u.create2.version = 0;
    ev.u.create2.country = 0;
    if (!writeEvent(&ev, sizeof(ev))) {
        *error = QStringLiteral("UHID_CREATE2 failed: %1").arg(QString::fromLocal8Bit(strerror(errno)));
        ::close(m_fd);
        m_fd = -1;
        return false;
    }

    m_notifier = new QSocketNotifier(m_fd, QSocketNotifier::Read, this);
    connect(m_notifier, &QSocketNotifier::activated, this, &UhidDevice::readEvent);
    qCInfo(KPASSKEY_LOG) << "virtual FIDO HID device created";
    return true;
}

void UhidDevice::destroy()
{
    if (m_fd < 0) {
        return;
    }
    delete m_notifier;
    m_notifier = nullptr;
    uhid_event ev;
    std::memset(&ev, 0, sizeof(ev));
    ev.type = UHID_DESTROY;
    writeEvent(&ev, sizeof(ev));
    ::close(m_fd);
    m_fd = -1;
}

bool UhidDevice::writeEvent(const void *ev, size_t size)
{
    const ssize_t n = ::write(m_fd, ev, size);
    return n == ssize_t(size);
}

void UhidDevice::sendInputReport(const QByteArray &report)
{
    if (m_fd < 0 || report.size() > UHID_DATA_MAX) {
        return;
    }
    uhid_event ev;
    std::memset(&ev, 0, sizeof(ev));
    ev.type = UHID_INPUT2;
    ev.u.input2.size = __u16(report.size());
    std::memcpy(ev.u.input2.data, report.constData(), size_t(report.size()));
    if (!writeEvent(&ev, sizeof(ev))) {
        qCWarning(KPASSKEY_LOG) << "failed to send input report";
    }
}

void UhidDevice::readEvent()
{
    uhid_event ev;
    std::memset(&ev, 0, sizeof(ev));
    const ssize_t n = ::read(m_fd, &ev, sizeof(ev));
    if (n <= 0) {
        return;
    }
    switch (ev.type) {
    case UHID_OUTPUT:
        if (ev.u.output.size <= UHID_DATA_MAX) {
            Q_EMIT outputReport(QByteArray(reinterpret_cast<const char *>(ev.u.output.data), ev.u.output.size));
        }
        break;
    case UHID_OPEN:
        Q_EMIT openedChanged(true);
        break;
    case UHID_CLOSE:
        Q_EMIT openedChanged(false);
        break;
    case UHID_GET_REPORT: {
        // Feature reports are not part of CTAPHID; answer so the kernel does not wait.
        uhid_event reply;
        std::memset(&reply, 0, sizeof(reply));
        reply.type = UHID_GET_REPORT_REPLY;
        reply.u.get_report_reply.id = ev.u.get_report.id;
        reply.u.get_report_reply.err = EIO;
        writeEvent(&reply, sizeof(reply));
        break;
    }
    case UHID_SET_REPORT: {
        uhid_event reply;
        std::memset(&reply, 0, sizeof(reply));
        reply.type = UHID_SET_REPORT_REPLY;
        reply.u.set_report_reply.id = ev.u.set_report.id;
        reply.u.set_report_reply.err = EIO;
        writeEvent(&reply, sizeof(reply));
        break;
    }
    default: // UHID_START, UHID_STOP
        break;
    }
}

} // namespace kpasskey
