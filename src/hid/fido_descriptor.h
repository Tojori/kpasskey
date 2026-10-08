// SPDX-License-Identifier: LGPL-2.1-or-later
// The fixed virtual FIDO device, shared by kpasskeyd (direct /dev/uhid mode)
// and kpasskey-uhid-helper.
#pragma once

#include <cstdint>

namespace kpasskey::fido {

// Standard FIDO HID report descriptor (CTAP 2.x, section 11.2.8.1):
// usage page 0xF1D0, usage 0x01 (CTAPHID), 64 byte input and output reports.
// systemd's 60-fido-id.rules recognises this descriptor and tags the hidraw
// node with ID_SECURITY_TOKEN=1 / uaccess for the active session user.
inline constexpr unsigned char ReportDescriptor[] = {
    0x06, 0xD0, 0xF1, // Usage Page (FIDO Alliance)
    0x09, 0x01,       // Usage (CTAPHID)
    0xA1, 0x01,       // Collection (Application)
    0x09, 0x20,       //   Usage (Input Report Data)
    0x15, 0x00,       //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08,       //   Report Size (8)
    0x95, 0x40,       //   Report Count (64)
    0x81, 0x02,       //   Input (Data, Var, Abs)
    0x09, 0x21,       //   Usage (Output Report Data)
    0x15, 0x00,       //   Logical Minimum (0)
    0x26, 0xFF, 0x00, //   Logical Maximum (255)
    0x75, 0x08,       //   Report Size (8)
    0x95, 0x40,       //   Report Count (64)
    0x91, 0x02,       //   Output (Data, Var, Abs)
    0xC0,             // End Collection
};

inline constexpr int ReportSize = 64;
inline constexpr char DeviceName[] = "KDE Passkey (KWallet)";
// Placeholder IDs; a real release needs an assigned USB VID/PID (e.g. pid.codes).
inline constexpr uint32_t Vendor = 0x1209;
inline constexpr uint32_t Product = 0x0001; // pid.codes test PID, NOT for distribution

// kpasskeyd <-> helper protocol over the Unix socket: after the device was
// created the helper sends this 8 byte hello; afterwards both sides exchange
// raw 64 byte HID reports, nothing else.
inline constexpr char HelperSocketPath[] = "/run/kpasskey/uhid.sock";
inline constexpr char HelperHello[8] = {'K', 'P', 'K', 'U', 'H', 'I', 'D', '1'};

} // namespace kpasskey::fido
