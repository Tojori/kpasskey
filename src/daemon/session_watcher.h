// SPDX-License-Identifier: LGPL-2.1-or-later
// Tracks whether the user's graphical logind session is the active one on its
// seat. The virtual FIDO device must only exist while it is: udev's uaccess
// hands /dev/hidraw* to whoever is in the foreground, so after a user switch
// another user could otherwise talk to our authenticator (docs/security.md T15).
#pragma once

#include <QDBusObjectPath>
#include <QObject>
#include <QString>

namespace kpasskey {

class SessionWatcher : public QObject
{
    Q_OBJECT
public:
    explicit SessionWatcher(QObject *parent = nullptr);

    // Resolves the session and starts watching. Returns false if logind is
    // unavailable; the caller then fails closed (no device).
    bool start();
    bool isActive() const { return m_active; }
    QString sessionPath() const { return m_sessionPath; }
    QString sessionId() const { return m_sessionId; }

Q_SIGNALS:
    void activeChanged(bool active);

private Q_SLOTS:
    void onSessionPropertiesChanged(const QString &interface, const QVariantMap &changed, const QStringList &invalidated);
    void onUserPropertiesChanged(const QString &interface, const QVariantMap &changed, const QStringList &invalidated);

private:
    bool resolveSession();
    void refreshActive();
    void setActive(bool active);

    QString m_userPath;
    QString m_sessionPath;
    QString m_sessionId;
    bool m_active = false;
};

} // namespace kpasskey
