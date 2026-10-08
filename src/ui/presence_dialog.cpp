// SPDX-License-Identifier: LGPL-2.1-or-later
#include "presence_dialog.h"

#include <KLocalizedString>

#include <QDialog>
#include <QDialogButtonBox>
#include <QIcon>
#include <QLabel>
#include <QListWidget>
#include <QPushButton>
#include <QVBoxLayout>

namespace kpasskey {

namespace {

// Everything except the RP ID is chosen by the website. All labels use
// Qt::PlainText so that site-provided strings can never inject rich text.
QLabel *plainLabel(const QString &text, QWidget *parent)
{
    auto *l = new QLabel(text, parent);
    l->setTextFormat(Qt::PlainText);
    l->setWordWrap(true);
    return l;
}

QString accountLabel(const QString &name, const QString &displayName)
{
    if (displayName.isEmpty() || displayName == name) {
        return name.isEmpty() ? i18n("(unnamed account)") : name;
    }
    return name.isEmpty() ? displayName : i18nc("display name (user name)", "%1 (%2)", displayName, name);
}

} // namespace

PresenceDialog::PresenceDialog(QObject *parent)
    : QObject(parent)
{
}

PresenceDialog::~PresenceDialog()
{
    cancel();
}

void PresenceDialog::requestPresence(const PresenceRequest &req, std::function<void(PresenceResult)> done)
{
    cancel();
    m_done = std::move(done);

    auto *dlg = new QDialog;
    dlg->setAttribute(Qt::WA_DeleteOnClose);
    dlg->setWindowIcon(QIcon::fromTheme(QStringLiteral("dialog-password")));
    dlg->setWindowFlag(Qt::WindowStaysOnTopHint);
    auto *layout = new QVBoxLayout(dlg);

    auto *site = new QLabel(dlg);
    site->setTextFormat(Qt::PlainText);
    site->setText(req.rpId); // rpId was origin-checked by the browser; it is what the key is bound to
    QFont f = site->font();
    f.setBold(true);
    f.setPointSizeF(f.pointSizeF() * 1.3);
    site->setFont(f);

    QListWidget *accounts = nullptr;
    QString okText;
    switch (req.kind) {
    case PresenceRequest::Kind::Register:
        dlg->setWindowTitle(i18n("Create passkey"));
        layout->addWidget(plainLabel(i18n("Save a new passkey in KWallet for:"), dlg));
        layout->addWidget(site);
        layout->addWidget(plainLabel(i18n("Account: %1", accountLabel(req.userName, req.userDisplayName)), dlg));
        okText = i18n("Create Passkey");
        break;
    case PresenceRequest::Kind::Authenticate:
        dlg->setWindowTitle(i18n("Sign in with passkey"));
        layout->addWidget(plainLabel(i18n("Sign in with a passkey from KWallet to:"), dlg));
        layout->addWidget(site);
        accounts = new QListWidget(dlg);
        for (const AccountChoice &a : req.accounts) {
            accounts->addItem(accountLabel(a.userName, a.userDisplayName));
        }
        accounts->setCurrentRow(0);
        layout->addWidget(accounts);
        okText = i18n("Sign In");
        break;
    case PresenceRequest::Kind::Excluded:
        dlg->setWindowTitle(i18n("Passkey already exists"));
        layout->addWidget(plainLabel(i18n("KWallet already contains a passkey for this account on:"), dlg));
        layout->addWidget(site);
        okText = i18n("OK");
        break;
    case PresenceRequest::Kind::Selection:
        dlg->setWindowTitle(i18n("Use KWallet passkeys?"));
        // The RP ID of selection probes is a placeholder (e.g. Firefox uses
        // "make.me.blink"), so it is not shown.
        layout->addWidget(plainLabel(i18n("A website wants to use a security key. Use the KWallet passkey store?"), dlg));
        site->hide();
        okText = i18n("Use KWallet");
        break;
    }
    if (req.kind != PresenceRequest::Kind::Selection && !req.rpName.isEmpty() && req.rpName != req.rpId) {
        layout->addWidget(plainLabel(i18n("Name given by the website (unverified): %1", req.rpName), dlg));
    }
    if (req.userVerificationFollows) {
        layout->addWidget(plainLabel(i18n("You will be asked to confirm your identity next."), dlg));
    }

    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, dlg);
    buttons->button(QDialogButtonBox::Ok)->setText(okText);
    // Cancel is the default so that an accidental Enter key never approves.
    buttons->button(QDialogButtonBox::Cancel)->setDefault(true);
    buttons->button(QDialogButtonBox::Cancel)->setFocus();
    layout->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::accepted, dlg, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, dlg, &QDialog::reject);

    connect(dlg, &QDialog::finished, this, [this, accounts](int code) {
        PresenceResult r;
        r.approved = code == QDialog::Accepted;
        r.selectedIndex = accounts ? std::max(0, accounts->currentRow()) : 0;
        m_dialog = nullptr;
        auto done = std::move(m_done);
        m_done = nullptr;
        if (done) {
            done(r);
        }
    });

    m_dialog = dlg;
    dlg->show();
    dlg->raise();
    dlg->activateWindow();
}

void PresenceDialog::cancel()
{
    m_done = nullptr; // contract: no callback after cancel()
    if (m_dialog) {
        m_dialog->disconnect(this);
        m_dialog->close();
        m_dialog = nullptr;
    }
}

} // namespace kpasskey
