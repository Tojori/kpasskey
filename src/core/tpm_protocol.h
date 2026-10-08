// SPDX-License-Identifier: LGPL-2.1-or-later
// Wire protocol between kpasskeyd and kpasskey-tpm-helper (Unix socket,
// /run/kpasskey/tpm.sock). Shared by both; no Qt.
//
// request:  u8 op | u32 big-endian length | payload
// response: u8 status | u32 big-endian length | payload
#pragma once

#include <cstddef>
#include <cstdint>

namespace kpasskey::tpmproto {

inline constexpr char SocketPath[] = "/run/kpasskey/tpm.sock";
inline constexpr size_t MaxPayload = 4096;

enum Op : uint8_t {
    // payload: empty. response: key blob = marshalled TPM2B_PUBLIC || TPM2B_PRIVATE
    // of a new, non-exportable ECC P-256 signing key under the helper's primary key.
    CreateKey = 1,
    // payload: 32 byte SHA-256 digest || key blob. response: r (32) || s (32).
    SignDigest = 2,
};

enum Status : uint8_t {
    Ok = 0,
    BadRequest = 1,
    TpmError = 2, // includes "wrong user": keys are bound to the creating uid
};

} // namespace kpasskey::tpmproto
