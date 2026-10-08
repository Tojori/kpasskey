// SPDX-License-Identifier: LGPL-2.1-or-later
#pragma once

#include <QString>
#include <optional>

namespace kpasskey::ui {

// All dialogs are modal (nested event loop). Return nullopt on cancel.
std::optional<QString> askExportPath();
std::optional<QString> askImportPath();
// confirm=true: export (two fields, minimum length, generator button).
std::optional<QString> askPassphrase(bool confirm);
void showInfo(const QString &title, const QString &text);
void showError(const QString &title, const QString &text);

// Random passphrase: 5 groups of 5 Crockford base32 characters (125 bit).
QString generatePassphrase();

} // namespace kpasskey::ui
