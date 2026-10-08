// SPDX-License-Identifier: LGPL-2.1-or-later
#include "session_watcher.h"

#include "core/logging.h"

#include <QDBusArgument>
#include <QDBusConnection>
#include <QDBusInterface>
#include <QDBusReply>
#include <QDBusVariant>

#include <unistd.h>

namespace kpasskey {

namespace {
const QString Login1 = QStringLiteral("org.freedesktop.login1");
const QString ManagerIface = QStringLiteral("org.freedesktop.login1.Manager");
const QString UserIface = QStringLiteral("org.freedesktop.login1.User");
const QString SessionIface = QStringLiteral("org.freedesktop.login1.Session");
const QString PropsIface = QStringLiteral("org.freedesktop.DBus.Properties");

QVariant getProperty(const QString &path, const QString &iface, const QString &name)
{
    QDBusInterface props(Login1, path, PropsIface, QDBusConnection::systemBus());
    QDBusReply<QDBusVariant> reply = props.call(QStringLiteral("Get"), iface, name);
    return reply.isValid() ? reply.value().variant() : QVariant();
}
} // namespace

SessionWatcher::SessionWatcher(QObject *parent)
    : QObject(parent)
{
}

bool SessionWatcher::start()
{
    auto bus = QDBusConnection::systemBus();
    QDBusInterface manager(Login1, QStringLiteral("/org/freedesktop/login1"), ManagerIface, bus);
    QDBusReply<QDBusObjectPath> user = manager.call(QStringLiteral("GetUser"), uint(getuid()));
    if (!user.isValid()) {
        qCWarning(KPASSKEY_LOG) << "logind: cannot resolve user:" << user.error().message();
        return false;
    }
    m_userPath = user.value().path();
    bus.connect(Login1, m_userPath, PropsIface, QStringLiteral("PropertiesChanged"), this,
                SLOT(onUserPropertiesChanged(QString, QVariantMap, QStringList)));
    if (!resolveSession()) {
        return false;
    }
    refreshActive();
    return true;
}

bool SessionWatcher::resolveSession()
{
    // User.Display = the user's graphical session (so). We run as a systemd
    // user service, outside any session scope, so we cannot use our own PID.
    const QVariant display = getProperty(m_userPath, UserIface, QStringLiteral("Display"));
    QString path;
    QString sessionId;
    if (display.canConvert<QDBusArgument>()) {
        const QDBusArgument arg = display.value<QDBusArgument>();
        QString id;
        QDBusObjectPath objPath;
        arg.beginStructure();
        arg >> id >> objPath;
        arg.endStructure();
        path = objPath.path();
        sessionId = id;
    }
    if (path.isEmpty() || path == QLatin1String("/")) {
        qCWarning(KPASSKEY_LOG) << "logind: user has no graphical session";
        return false;
    }
    m_sessionId = sessionId;
    if (path == m_sessionPath) {
        return true;
    }
    auto bus = QDBusConnection::systemBus();
    if (!m_sessionPath.isEmpty()) {
        bus.disconnect(Login1, m_sessionPath, PropsIface, QStringLiteral("PropertiesChanged"), this,
                       SLOT(onSessionPropertiesChanged(QString, QVariantMap, QStringList)));
    }
    m_sessionPath = path;
    bus.connect(Login1, m_sessionPath, PropsIface, QStringLiteral("PropertiesChanged"), this,
                SLOT(onSessionPropertiesChanged(QString, QVariantMap, QStringList)));
    return true;
}

void SessionWatcher::refreshActive()
{
    setActive(getProperty(m_sessionPath, SessionIface, QStringLiteral("Active")).toBool());
}

void SessionWatcher::setActive(bool active)
{
    if (active == m_active) {
        return;
    }
    m_active = active;
    qCInfo(KPASSKEY_LOG) << "session" << (active ? "became active" : "became inactive");
    Q_EMIT activeChanged(active);
}

void SessionWatcher::onSessionPropertiesChanged(const QString &interface, const QVariantMap &changed,
                                                const QStringList &invalidated)
{
    if (interface != SessionIface) {
        return;
    }
    if (changed.contains(QStringLiteral("Active"))) {
        setActive(changed.value(QStringLiteral("Active")).toBool());
    } else if (invalidated.contains(QStringLiteral("Active"))) {
        refreshActive();
    }
}

void SessionWatcher::onUserPropertiesChanged(const QString &interface, const QVariantMap &, const QStringList &)
{
    if (interface != UserIface) {
        return;
    }
    if (resolveSession()) {
        refreshActive();
    } else {
        setActive(false); // fail closed
    }
}

} // namespace kpasskey
