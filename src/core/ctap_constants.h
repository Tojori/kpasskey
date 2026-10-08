// SPDX-License-Identifier: LGPL-2.1-or-later
// Constants from the FIDO CTAP 2.x specification (Client to Authenticator Protocol).
#pragma once

#include <QtGlobal>
#include <cstdint>

namespace kpasskey::ctap {

// authenticator* command bytes (CTAP 2.0, section 6)
enum Command : uint8_t {
    MakeCredential = 0x01,
    GetAssertion = 0x02,
    GetInfo = 0x04,
    ClientPin = 0x06,
    Reset = 0x07,
    GetNextAssertion = 0x08,
    Selection = 0x0B, // CTAP 2.1 authenticatorSelection
};

// CTAP status codes (CTAP 2.x, section 6.3 / 8.2)
enum Status : uint8_t {
    Ok = 0x00,
    ErrInvalidCommand = 0x01,
    ErrInvalidParameter = 0x02,
    ErrInvalidLength = 0x03,
    ErrChannelBusy = 0x06,
    ErrCborUnexpectedType = 0x11,
    ErrInvalidCbor = 0x12,
    ErrMissingParameter = 0x14,
    ErrCredentialExcluded = 0x19,
    ErrUnsupportedAlgorithm = 0x26,
    ErrOperationDenied = 0x27,
    ErrKeyStoreFull = 0x28,
    ErrUnsupportedOption = 0x2B,
    ErrInvalidOption = 0x2C,
    ErrKeepaliveCancel = 0x2D,
    ErrNoCredentials = 0x2E,
    ErrUserActionTimeout = 0x2F,
    ErrNotAllowed = 0x30,
    ErrPinAuthInvalid = 0x33,
    ErrPinNotSet = 0x35,
    ErrInvalidSubcommand = 0x3E,
    ErrUnauthorizedPermission = 0x40,
    ErrOther = 0x7F,
};

// authenticatorData flags (WebAuthn L3, section 6.1)
enum AuthDataFlag : uint8_t {
    FlagUP = 0x01,
    FlagUV = 0x04,
    FlagBE = 0x08,
    FlagBS = 0x10,
    FlagAT = 0x40,
    FlagED = 0x80,
};

// COSE algorithm identifiers (IANA COSE registry)
enum CoseAlg : int {
    ES256 = -7,
    EdDSA = -8,
};

// authenticatorClientPIN subcommands (CTAP 2.1, section 6.5.5)
enum ClientPinSubcommand : int {
    GetPinRetries = 0x01,
    GetKeyAgreement = 0x02,
    GetPinUvAuthTokenUsingUvWithPermissions = 0x06,
    GetUvRetries = 0x07,
};

// pinUvAuthToken permissions (CTAP 2.1, section 6.5.5.7)
enum Permission : quint8 {
    PermMakeCredential = 0x01,
    PermGetAssertion = 0x02,
};

constexpr int ClientDataHashSize = 32;
constexpr int MaxUserIdSize = 64;          // WebAuthn: user.id is at most 64 bytes
constexpr int MaxCredentialIdSize = 1023;  // CTAP 2.1: credential IDs are at most 1023 bytes
constexpr int CredentialIdSize = 32;       // our own, randomly generated IDs
constexpr int MinCredentialIdSize = 16;    // WebAuthn: at least 16 bytes of entropy (imported IDs)
constexpr int MaxRpIdLength = 253;

} // namespace kpasskey::ctap
