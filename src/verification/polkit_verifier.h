// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include "core/user_interaction.h"

#include <QObject>

namespace kpasskey {

// User verification through polkit with an "auth_self" action (no retained
// authorization). polkit-kde-agent shows the native KDE authentication dialog
// and checks the user's credentials through the PAM stack "polkit-1" – which
// is where pam_fprintd (fingerprint) or other PAM modules plug in.
class PolkitVerifier : public QObject, public UserVerifier
{
    Q_OBJECT
public:
    static constexpr auto ActionId = "org.kde.kpasskey.verify-user";

    explicit PolkitVerifier(QObject *parent = nullptr);

    bool isAvailable() const override;

    void verify(const QString &rpId, std::function<void(bool)> done) override;
    void cancel() override;

private:
    std::function<void(bool)> m_done;
};

} // namespace kpasskey
