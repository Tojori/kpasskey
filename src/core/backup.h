// SPDX-License-Identifier: LGPL-2.1-or-later
// Encrypted backup file around a CXF document (project-specific container;
// CXF itself is a plaintext format, and CXP (HPKE transfer between
// providers) is still a draft). Layout: docs/storage-format.md#backup.
#pragma once

#include "crypto.h"

#include <QByteArray>
#include <QString>
#include <optional>

namespace kpasskey::backup {

inline constexpr char FormatId[] = "kpasskey-backup";
inline constexpr int FormatVersion = 1;
inline constexpr int MinPassphraseLength = 12;

struct KdfParams {
    quint32 iterations = 3;
    quint32 memoryKiB = 64 * 1024; // 64 MiB
    quint32 lanes = 1;
};

// Encrypts `cxfJson` with a key derived from `passphrase` (Argon2id).
std::optional<QByteArray> encrypt(const SecretBytes &cxfJson, const QString &passphrase, KdfParams params = {});

enum class DecryptError { None, NotABackup, UnsupportedVersion, BadParameters, WrongPassphraseOrCorrupt };
// Returns the CXF JSON; fails closed on any inconsistency.
std::optional<SecretBytes> decrypt(const QByteArray &file, const QString &passphrase, DecryptError *error = nullptr);

} // namespace kpasskey::backup
