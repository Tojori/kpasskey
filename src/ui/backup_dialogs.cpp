// SPDX-License-Identifier: LGPL-2.1-or-later
#include "backup_dialogs.h"

#include "core/backup.h"
#include "core/crypto.h"

#include <KLocalizedString>

#include <QDate>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDir>
#include <QFileDialog>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPushButton>
#include <QVBoxLayout>

namespace kpasskey::ui {

namespace {
const QString FileFilter = QStringLiteral("KDE Passkey backup (*.kpasskey-backup)");
}

QString generatePassphrase()
{
    static const char alphabet[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // Crockford base32
    const QByteArray rnd = crypto::randomBytes(25);
    QString out;
    for (int i = 0; i < 25; ++i) {
        if (i && i % 5 == 0) {
            out += QLatin1Char('-');
        }
        out += QLatin1Char(alphabet[quint8(rnd.at(i)) % 32]); // 256 % 32 == 0: unbiased
    }
    return out;
}

std::optional<QString> askExportPath()
{
    const QString suggestion = QDir::home().filePath(
        QStringLiteral("passkeys-%1.kpasskey-backup").arg(QDate::currentDate().toString(Qt::ISODate)));
    const QString path = QFileDialog::getSaveFileName(nullptr, i18n("Export passkeys"), suggestion, FileFilter);
    if (path.isEmpty()) {
        return std::nullopt;
    }
    return path;
}

std::optional<QString> askImportPath()
{
    const QString path = QFileDialog::getOpenFileName(nullptr, i18n("Import passkeys"), QDir::homePath(), FileFilter);
    if (path.isEmpty()) {
        return std::nullopt;
    }
    return path;
}

std::optional<QString> askPassphrase(bool confirm)
{
    QDialog dlg;
    dlg.setWindowTitle(confirm ? i18n("Protect the passkey backup") : i18n("Unlock the passkey backup"));
    auto *layout = new QVBoxLayout(&dlg);
    auto *intro = new QLabel(&dlg);
    intro->setWordWrap(true);
    intro->setTextFormat(Qt::PlainText);
    intro->setText(confirm ? i18n("The backup contains your private passkeys. It is encrypted with this passphrase "
                                  "(at least %1 characters). Without the passphrase the backup cannot be restored; "
                                  "store it safely, e.g. on paper.",
                                  backup::MinPassphraseLength)
                           : i18n("Enter the passphrase of the backup."));
    layout->addWidget(intro);

    auto *form = new QFormLayout;
    auto *pass = new QLineEdit(&dlg);
    pass->setEchoMode(QLineEdit::Password);
    form->addRow(i18n("Passphrase:"), pass);
    QLineEdit *repeat = nullptr;
    QLabel *generated = nullptr;
    if (confirm) {
        repeat = new QLineEdit(&dlg);
        repeat->setEchoMode(QLineEdit::Password);
        form->addRow(i18n("Repeat:"), repeat);
    }
    layout->addLayout(form);

    auto *buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dlg);
    QPushButton *ok = buttons->button(QDialogButtonBox::Ok);
    if (confirm) {
        generated = new QLabel(&dlg);
        generated->setTextInteractionFlags(Qt::TextSelectableByMouse);
        generated->setTextFormat(Qt::PlainText);
        generated->hide();
        layout->addWidget(generated);
        QPushButton *gen = buttons->addButton(i18n("Generate"), QDialogButtonBox::ActionRole);
        QObject::connect(gen, &QPushButton::clicked, &dlg, [pass, repeat, generated] {
            const QString p = generatePassphrase();
            pass->setText(p);
            repeat->setText(p);
            generated->setText(i18n("Generated passphrase (write it down now, it is shown only here):\n%1", p));
            generated->show();
        });
    }
    layout->addWidget(buttons);
    auto validate = [=] {
        const bool long_enough = pass->text().size() >= (confirm ? backup::MinPassphraseLength : 1);
        ok->setEnabled(long_enough && (!repeat || repeat->text() == pass->text()));
    };
    QObject::connect(pass, &QLineEdit::textChanged, &dlg, validate);
    if (repeat) {
        QObject::connect(repeat, &QLineEdit::textChanged, &dlg, validate);
    }
    validate();
    QObject::connect(buttons, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    QObject::connect(buttons, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    if (dlg.exec() != QDialog::Accepted) {
        return std::nullopt;
    }
    QString result = pass->text();
    pass->clear();
    if (repeat) {
        repeat->clear();
    }
    return result;
}

void showInfo(const QString &title, const QString &text)
{
    QMessageBox box(QMessageBox::Information, title, text);
    box.setTextFormat(Qt::PlainText);
    box.exec();
}

void showError(const QString &title, const QString &text)
{
    QMessageBox box(QMessageBox::Warning, title, text);
    box.setTextFormat(Qt::PlainText);
    box.exec();
}

} // namespace kpasskey::ui
