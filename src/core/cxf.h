// SPDX-License-Identifier: LGPL-2.1-or-later
// FIDO Credential Exchange Format (CXF) 1.0, Proposed Standard with errata of
// 2026-03-09: https://fidoalliance.org/specs/cx/cxf-v1.0-ps-errata-20260309.html
// Only the "passkey" credential type is produced and consumed.
#pragma once

#include "credential.h"

#include <QList>
#include <QString>

namespace kpasskey::cxf {

inline constexpr int VersionMajor = 1;
inline constexpr int VersionMinor = 0;
// Header.exporterRpId must be an RP ID; the project owns no domain yet, so a
// reserved placeholder is used (docs/storage-format.md).
inline constexpr char ExporterRpId[] = "kpasskey.invalid";
inline constexpr char ExporterDisplayName[] = "KDE Passkey (KWallet)";

struct ExportReport {
    int exported = 0;
    int skippedHardwareBound = 0; // TPM keys cannot leave the TPM
    int skippedNonZeroCounter = 0; // CXF §3.3.12: MUST be excluded
};

// Builds a CXF 1.0 JSON document with one Account containing one Item per
// passkey. The result contains private keys: handle as secret.
SecretBytes exportJson(const QList<CredentialRecord> &records, ExportReport *report);

struct ImportResult {
    QList<CredentialRecord> records;
    int skippedOtherTypes = 0;  // passwords, TOTP, notes, ... (not supported)
    int skippedInvalid = 0;     // malformed or unsupported passkeys (e.g. RS256)
    QString error;              // non-empty: the document as a whole was rejected
};

// Parses a CXF document. Imported passkeys get sign count 0 (CXF requirement),
// are backup eligible and discoverable.
ImportResult importJson(const QByteArray &json);

} // namespace kpasskey::cxf
