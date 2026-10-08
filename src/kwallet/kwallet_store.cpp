// SPDX-License-Identifier: LGPL-2.1-or-later
#include "kwallet_store.h"

#include "core/logging.h"

#include <KWallet>

namespace kpasskey {

namespace {
QString folder()
{
    return QLatin1String(KWalletStore::FolderName);
}
} // namespace

KWalletStore::KWalletStore(QObject *parent)
    : QObject(parent)
{
}

KWalletStore::~KWalletStore()
{
    delete m_wallet;
}

bool KWalletStore::isOpen() const
{
    return m_wallet && m_wallet->isOpen();
}

void KWalletStore::ensureReady(std::function<void(bool)> done)
{
    if (isOpen() && m_wallet->setFolder(folder())) {
        done(true);
        return;
    }
    if (!KWallet::Wallet::isEnabled()) {
        qCWarning(KPASSKEY_LOG) << "KWallet is disabled";
        done(false);
        return;
    }
    m_waiting.append(std::move(done));
    if (m_opening) {
        return;
    }
    m_opening = true;
    delete m_wallet;
    // Asynchronous: KWallet may show its unlock dialog. Meanwhile the CTAPHID
    // layer keeps sending keepalives to the browser.
    m_wallet = KWallet::Wallet::openWallet(KWallet::Wallet::LocalWallet(), 0, KWallet::Wallet::Asynchronous);
    if (!m_wallet) {
        onWalletOpened(false);
        return;
    }
    connect(m_wallet, &KWallet::Wallet::walletOpened, this, &KWalletStore::onWalletOpened);
    connect(m_wallet, &KWallet::Wallet::walletClosed, this, [this] {
        qCInfo(KPASSKEY_LOG) << "wallet was closed";
        if (m_wallet) {
            m_wallet->deleteLater();
        }
    });
}

void KWalletStore::onWalletOpened(bool success)
{
    m_opening = false;
    bool ok = success && isOpen();
    if (ok && !m_wallet->hasFolder(folder())) {
        ok = m_wallet->createFolder(folder());
    }
    ok = ok && m_wallet->setFolder(folder());
    if (!ok) {
        qCWarning(KPASSKEY_LOG) << "could not open the local wallet / Passkeys folder";
    }
    const auto waiting = std::move(m_waiting);
    m_waiting.clear();
    for (const auto &cb : waiting) {
        cb(ok);
    }
}

bool KWalletStore::put(const CredentialRecord &record)
{
    if (!isOpen() || !m_wallet->setFolder(folder())) {
        return false;
    }
    if (m_wallet->writePassword(record::entryKey(record.rpId, record.credentialId), record::encode(record)) != 0) {
        return false;
    }
    // No explicit sync: since KF 6.30 KWallet is a translation layer over
    // ksecretd (Secret Service) and Wallet::sync() is a deprecated no-op;
    // the write is committed by the backend when the D-Bus call returns.
    Q_EMIT changed();
    return true;
}

std::optional<CredentialRecord> KWalletStore::readEntry(const QString &key)
{
    QString json;
    if (m_wallet->readPassword(key, json) != 0) {
        return std::nullopt;
    }
    record::DecodeError err = record::DecodeError::None;
    auto r = record::decode(key, json, &err);
    // Never log the entry content.
    if (err == record::DecodeError::UnsupportedSchema) {
        qCWarning(KPASSKEY_LOG) << "skipping entry written by a newer version";
    } else if (err != record::DecodeError::None) {
        qCWarning(KPASSKEY_LOG) << "skipping corrupted or inconsistent wallet entry" << int(err);
    }
    return r;
}

std::optional<CredentialRecord> KWalletStore::find(const QString &rpId, const QByteArray &credentialId)
{
    if (!isOpen() || !m_wallet->setFolder(folder())) {
        return std::nullopt;
    }
    const QString key = record::entryKey(rpId, credentialId);
    if (!m_wallet->hasEntry(key)) {
        return std::nullopt;
    }
    return readEntry(key);
}

QList<CredentialRecord> KWalletStore::findByRp(const QString &rpId)
{
    QList<CredentialRecord> out;
    if (!isOpen() || !m_wallet->setFolder(folder())) {
        return out;
    }
    const QString prefix = rpId + QLatin1Char('/');
    const QStringList keys = m_wallet->entryList();
    for (const QString &key : keys) {
        if (key.startsWith(prefix)) {
            if (auto r = readEntry(key)) {
                out.append(std::move(*r));
            }
        }
    }
    return out;
}

QList<CredentialMetadata> KWalletStore::listAll()
{
    QList<CredentialMetadata> out;
    if (!isOpen() || !m_wallet->setFolder(folder())) {
        return out;
    }
    const QStringList keys = m_wallet->entryList();
    for (const QString &key : keys) {
        if (auto r = readEntry(key)) {
            out.append(metadataOf(*r));
        }
    }
    return out;
}

QList<CredentialRecord> KWalletStore::allRecords()
{
    QList<CredentialRecord> out;
    if (!isOpen() || !m_wallet->setFolder(folder())) {
        return out;
    }
    const QStringList keys = m_wallet->entryList();
    for (const QString &key : keys) {
        if (auto r = readEntry(key)) {
            out.append(std::move(*r));
        }
    }
    return out;
}

bool KWalletStore::remove(const QString &credentialIdB64)
{
    if (!isOpen() || !m_wallet->setFolder(folder())) {
        return false;
    }
    const QString suffix = QLatin1Char('/') + credentialIdB64;
    const QStringList keys = m_wallet->entryList();
    for (const QString &key : keys) {
        if (key.endsWith(suffix)) {
            const bool ok = m_wallet->removeEntry(key) == 0;
            Q_EMIT changed();
            return ok;
        }
    }
    return false;
}

} // namespace kpasskey
