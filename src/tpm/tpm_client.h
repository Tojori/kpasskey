// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include "core/hardware_keys.h"

#include <QObject>

class QLocalSocket;

namespace kpasskey {

// HardwareKeyStore backed by kpasskey-tpm-helper (/run/kpasskey/tpm.sock).
// Requests are synchronous (a TPM signature takes well below a second);
// the connection is kept open so the helper derives its primaries only once.
class TpmClient : public QObject, public HardwareKeyStore
{
    Q_OBJECT
public:
    explicit TpmClient(QObject *parent = nullptr);
    ~TpmClient() override;

    static bool isAvailable();
    std::optional<Key> createKey() override;
    std::optional<QByteArray> signDigest(const QByteArray &blob, const QByteArray &digest) override;

private:
    std::optional<QByteArray> request(quint8 op, const QByteArray &payload);
    bool ensureConnected();

    QLocalSocket *m_socket = nullptr;
};

} // namespace kpasskey
