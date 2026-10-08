// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include "core/user_interaction.h"

#include <QObject>
#include <QPointer>

class QDialog;

namespace kpasskey {

// Native Qt/KDE confirmation dialog providing user presence and, on the
// authenticator's own "display", account selection.
class PresenceDialog : public QObject, public PresencePrompter
{
    Q_OBJECT
public:
    explicit PresenceDialog(QObject *parent = nullptr);
    ~PresenceDialog() override;

    void requestPresence(const PresenceRequest &request, std::function<void(PresenceResult)> done) override;
    void cancel() override;

private:
    QPointer<QDialog> m_dialog;
    std::function<void(PresenceResult)> m_done;
};

} // namespace kpasskey
