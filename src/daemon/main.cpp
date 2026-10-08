// SPDX-License-Identifier: LGPL-2.1-or-later
#include "core/authenticator.h"
#include "core/logging.h"
#include "hid/ctaphid.h"
#include "hid/helper_device.h"
#include "hid/uhid_device.h"
#include "kwallet/kwallet_store.h"
#include "manager_dbus.h"
#include "session_watcher.h"
#include "tpm/tpm_client.h"
#include "ui/presence_dialog.h"
#include "verification/polkit_verifier.h"

#include <KLocalizedString>

#include <QApplication>
#include <QCommandLineParser>
#include <QDBusConnection>
#include <QDBusConnectionInterface>
#include <QTimer>

#include <sys/resource.h>

using namespace kpasskey;

namespace {

void hardenProcess()
{
    // No core dumps: they would contain decrypted private keys.
    struct rlimit noCore = {0, 0};
    setrlimit(RLIMIT_CORE, &noCore);
    // Deliberately NOT prctl(PR_SET_DUMPABLE, 0): it makes /proc/<pid> root-owned,
    // so polkitd (running as its own user) can no longer resolve our identity
    // and user verification hangs (observed with polkit 127), and
    // xdg-desktop-portal cannot register us. Protection against ptrace by
    // same-user processes comes from Yama (kernel.yama.ptrace_scope >= 1).
}

} // namespace

int main(int argc, char **argv)
{
    hardenProcess();

    QApplication app(argc, argv);
    app.setQuitOnLastWindowClosed(false);
    KLocalizedString::setApplicationDomain("kpasskey");
    app.setApplicationName(QStringLiteral("kpasskeyd"));
    app.setApplicationVersion(QStringLiteral(KPASSKEY_VERSION));
    app.setDesktopFileName(QStringLiteral("org.kde.kpasskeyd"));

    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("KWallet backed FIDO2/passkey authenticator (prototype)"));
    parser.addHelpOption();
    parser.addVersionOption();
    QCommandLineOption ephemeral(QStringLiteral("ephemeral"),
                                 QStringLiteral("Keep credentials in memory only (testing; nothing is stored)."));
    QCommandLineOption noUv(QStringLiteral("no-uv"), QStringLiteral("Do not offer user verification."));
    QCommandLineOption denySilent(QStringLiteral("deny-silent"),
                                  QStringLiteral("Answer silent (up=false) probes with NO_CREDENTIALS (privacy)."));
    QCommandLineOption ignoreSession(QStringLiteral("ignore-session"),
                                     QStringLiteral("Keep the device even when the session is inactive (testing only)."));
    parser.addOption(ephemeral);
    parser.addOption(noUv);
    parser.addOption(denySilent);
    QCommandLineOption directUhid(QStringLiteral("direct-uhid"),
                                  QStringLiteral("Open /dev/uhid directly instead of using kpasskey-uhid-helper (development only)."));
    QCommandLineOption keyBackend(QStringLiteral("key-backend"),
                                  QStringLiteral("Where new private keys live: auto (TPM if kpasskey-tpm-helper is installed), tpm, software."),
                                  QStringLiteral("backend"), QStringLiteral("auto"));
    parser.addOption(ignoreSession);
    parser.addOption(directUhid);
    parser.addOption(keyBackend);
    parser.process(app);

    // Single instance: two daemons would race on sign counters.
    auto bus = QDBusConnection::sessionBus();
    if (!bus.isConnected()
        || bus.interface()->registerService(QLatin1String(ManagerDBus::ServiceName), QDBusConnectionInterface::DontQueueService)
               != QDBusConnectionInterface::ServiceRegistered) {
        qCCritical(KPASSKEY_LOG) << "cannot own" << ManagerDBus::ServiceName << "- is kpasskeyd already running?";
        return 1;
    }

    std::unique_ptr<CredentialStore> memoryStore;
    KWalletStore *walletStore = nullptr;
    CredentialStore *store = nullptr;
    if (parser.isSet(ephemeral)) {
        memoryStore = std::make_unique<MemoryStore>();
        store = memoryStore.get();
        qCWarning(KPASSKEY_LOG) << "ephemeral mode: credentials are lost on exit";
    } else {
        walletStore = new KWalletStore(&app);
        store = walletStore;
    }

    PresenceDialog prompter;
    PolkitVerifier polkitVerifier;
    UserVerifier *verifier = parser.isSet(noUv) ? nullptr : &polkitVerifier;
    if (verifier && !verifier->isAvailable()) {
        qCWarning(KPASSKEY_LOG) << "polkit is not reachable; user verification disabled";
        verifier = nullptr;
    }

    Authenticator::Options options;
    options.allowSilentAssertions = !parser.isSet(denySilent);
    // Existing TPM-protected credentials need the TPM client even when new keys
    // are created in software, so it is always constructed when available.
    TpmClient tpm;
    if (TpmClient::isAvailable()) {
        options.hardwareKeys = &tpm;
    }
    const QString backend = parser.value(keyBackend);
    if (backend == QLatin1String("tpm") || (backend == QLatin1String("auto") && TpmClient::isAvailable())) {
        if (!TpmClient::isAvailable()) {
            qCCritical(KPASSKEY_LOG) << "--key-backend=tpm, but kpasskey-tpm-helper is not installed";
            return 4;
        }
        options.createInHardware = true;
        qCInfo(KPASSKEY_LOG) << "new passkeys are created in the TPM (ES256 only)";
    } else if (backend == QLatin1String("software") || backend == QLatin1String("auto")) {
        qCInfo(KPASSKEY_LOG) << "new passkeys are created in software and protected by KWallet only";
    } else {
        qCCritical(KPASSKEY_LOG) << "unknown --key-backend" << backend;
        return 4;
    }
    Authenticator authenticator(store, &prompter, verifier, options);
    CtapHid hid(&authenticator);
    std::unique_ptr<HidTransport> transport;
    if (parser.isSet(directUhid) || !HelperDevice::isAvailable()) {
        if (!parser.isSet(directUhid)) {
            qCWarning(KPASSKEY_LOG) << "kpasskey-uhid-helper socket not found; falling back to direct /dev/uhid";
        }
        transport = std::make_unique<UhidDevice>();
    } else {
        transport = std::make_unique<HelperDevice>();
    }
    HidTransport &device = *transport;
    QObject::connect(&device, &HidTransport::outputReport, &hid, &CtapHid::handleReport);
    QObject::connect(&hid, &CtapHid::reportReady, &device, &HidTransport::sendInputReport);

    ManagerDBus manager(store, &polkitVerifier, &authenticator);
    if (walletStore) {
        QObject::connect(walletStore, &KWalletStore::changed, &manager, &ManagerDBus::CredentialsChanged);
    }
    bus.registerObject(QLatin1String(ManagerDBus::ObjectPath), &manager,
                       QDBusConnection::ExportScriptableSlots | QDBusConnection::ExportScriptableSignals);

    SessionWatcher session;
    QTimer retry;
    retry.setInterval(2000);

    // The device only exists while our graphical session is in the foreground.
    auto setDeviceEnabled = [&](bool enabled) -> bool {
        if (!enabled) {
            retry.stop();
            authenticator.cancel(); // closes open dialogs, answers KEEPALIVE_CANCEL
            device.destroy();
            return true;
        }
        QString error;
        if (!device.create(&error)) {
            qCCritical(KPASSKEY_LOG).noquote() << error;
            return false;
        }
        return true;
    };

    // If the helper drops the device (e.g. it saw the session become inactive
    // first), retry while our session is active.
    QObject::connect(&device, &HidTransport::lost, &app, [&] {
        authenticator.cancel();
        if (parser.isSet(ignoreSession) || session.isActive()) {
            retry.start();
        }
    });
    QObject::connect(&retry, &QTimer::timeout, &app, [&] {
        if (!(parser.isSet(ignoreSession) || session.isActive())) {
            retry.stop();
            return;
        }
        QString error;
        if (device.create(&error)) {
            retry.stop();
        }
    });
    if (parser.isSet(ignoreSession)) {
        qCWarning(KPASSKEY_LOG) << "session binding disabled";
        if (!setDeviceEnabled(true)) {
            return 2;
        }
    } else {
        if (!session.start()) {
            qCCritical(KPASSKEY_LOG) << "cannot determine the logind session; refusing to create the device";
            return 3;
        }
        QObject::connect(&session, &SessionWatcher::activeChanged, &app, [&](bool active) {
            if (!setDeviceEnabled(active) && active) {
                QCoreApplication::exit(2);
            }
        });
        if (session.isActive() && !setDeviceEnabled(true)) {
            return 2;
        }
    }
    return app.exec();
}
