// SPDX-License-Identifier: LGPL-2.1-or-later
// Logging policy: never log key material, user handles, client data hashes or
// full CBOR payloads. RP IDs and status codes are fine.
#pragma once

#include <QLoggingCategory>

Q_DECLARE_LOGGING_CATEGORY(KPASSKEY_LOG)
