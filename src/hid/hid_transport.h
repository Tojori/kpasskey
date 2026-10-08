// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include <QByteArray>
#include <QObject>
#include <QString>

namespace kpasskey {

// Where the 64 byte HID reports of the virtual FIDO device come from / go to.
class HidTransport : public QObject
{
    Q_OBJECT
public:
    using QObject::QObject;

    // Creates the virtual device. On failure `error` explains why.
    virtual bool create(QString *error) = 0;
    virtual void destroy() = 0;

public Q_SLOTS:
    virtual void sendInputReport(const QByteArray &report) = 0;

Q_SIGNALS:
    void outputReport(const QByteArray &report);
    // The device disappeared without destroy() (helper closed the connection).
    void lost();
};

} // namespace kpasskey
