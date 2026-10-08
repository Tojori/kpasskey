# kpasskey – KWallet-backed passkey authenticator for KDE Plasma (prototype)

**English** · [Deutsch](README.de.md)

[![CI](https://github.com/Tojori/kpasskey/actions/workflows/ci.yml/badge.svg)](https://github.com/Tojori/kpasskey/actions/workflows/ci.yml)

> **Status: prototype, not for daily use.** Registration and sign-in work with **unmodified Firefox and Chromium** (tested on webauthn.io, CachyOS / Plasma 6.7). Before using it, read the [threat model](docs/security.md), especially T5: other processes of the same user can read KWallet. See also the [roadmap](docs/roadmap.md).

kpasskey stores WebAuthn/FIDO2 passkeys in the KDE Wallet and makes them available to Firefox and Chromium **without browser patches or extensions**.

## How it works

As of October 2026 there is **no browser interface on Linux for OS platform authenticators**. The freedesktop effort [credentialsd](https://github.com/linux-credentials/credentialsd) is working on one, but it is experimental: it needs a patched xdg-desktop-portal and a browser extension, and there is no provider interface yet.

kpasskey therefore uses the path both browsers already support today: **CTAP 2.1 over USB HID**. The daemon `kpasskeyd` has a virtual FIDO2 security key created by the small, sandboxed `kpasskey-uhid-helper`, which is the only component allowed to access `/dev/uhid`.

```text
Website ─WebAuthn─▶ Firefox/Chromium ─CTAP2/HID─▶ /dev/hidraw ◀─uhid─ kpasskey-uhid-helper ◀─socket─ kpasskeyd ─┬─▶ KWallet (folder "Passkeys")
                                                                                                                ├─▶ Qt dialog (confirmation, account choice)
                                                                                                                └─▶ polkit → PAM (password/fingerprint) = UV
```

- By default, private keys (P-256 / Ed25519, OpenSSL) are stored **in KWallet** and can be restored from wallet backups. Optionally (`--key-backend=tpm`), new keys are **created inside a TPM 2.0** by the sandboxed `kpasskey-tpm-helper` and never leave it; they are then useless on any other machine, but also **lost for good** if the TPM is reset or the mainboard replaced. No cryptographic primitives are implemented here (OpenSSL 3, tpm2-tss).
- **User verification** is a fresh authentication via polkit/PAM (`auth_self`, nothing cached), so fingerprint readers work through `pam_fprintd`. Merely unlocking KWallet does **not** count as user verification ([why](docs/architecture.md#3-user-verification-warum-kwallet-unlock-keine-uv-ist)).
- **User presence** and account selection use a native Qt dialog that shows the RP ID; site-supplied names are shown as plain text and marked as unverified.
- Browsers see a **security key** (`usb` transport), not a "platform authenticator" ([consequences](docs/browser-compat.md)).
- The device only exists while your local graphical session is active (logind), and is removed on user switch.

## Tested

| Test | Result |
|---|---|
| Firefox and Chromium (native, unmodified) on webauthn.io: register + sign in (discoverable, UV required) | ✅ |
| python-fido2 (client + relying-party verification) over the real hidraw device, with KWallet and polkit | ✅ |
| Keys created in and used from a real **TPM 2.0** (wallet holds only the TPM-bound blob) | ✅ |
| 80 unit/security tests, interop test, ASan/UBSan, libFuzzer (3 targets), CI on every push | ✅ |
| Flatpak/Snap browsers, other distributions | not yet |

## Quick start

Dependencies (Arch/CachyOS): `cmake qt6-base kwallet ki18n polkit-qt6 openssl systemd-libs tpm2-tss` (optional: `python-fido2 python-cryptography` for the interop test).

```sh
# build and test (no root needed)
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo && cmake --build build -j && ctest --test-dir build --output-on-failure
# install (daemon, uhid helper, polkit action, units) and start
sudo scripts/dev-install.sh build "$USER"
systemctl --user daemon-reload && systemctl --user enable --now kpasskeyd.service
```

Then register a passkey on e.g. <https://webauthn.io>: the browser asks for a security key, KDE shows the password dialog (user verification) and a confirmation dialog. Uninstall with `sudo scripts/dev-uninstall.sh`. Options, fuzzing and details: [docs/build.md](docs/build.md).

## Documentation

The design documents are currently in German:

| Document | Contents |
|---|---|
| [docs/research.md](docs/research.md) | State of the art (WebAuthn, CTAP, credentialsd, libwebauthn, KWallet, polkit, TPM2), each claim labelled as standard / implemented / experimental / draft |
| [docs/architecture.md](docs/architecture.md) | Corrected assumptions, target architecture, user verification semantics |
| [docs/security.md](docs/security.md) | Threat model (T1–T16) including system test findings |
| [docs/dbus-api.md](docs/dbus-api.md) | Management D-Bus API, supported CTAP commands, proposal for a credentialsd provider API |
| [docs/storage-format.md](docs/storage-format.md) | KWallet schema v1, validation, migration, AAGUID |
| [docs/build.md](docs/build.md) | Build, test, install, fuzzing, sanitizers |
| [docs/testing.md](docs/testing.md) | Test strategy and observed browser CTAP flows |
| [docs/browser-compat.md](docs/browser-compat.md) | Firefox/Chromium details and limitations |
| [docs/roadmap.md](docs/roadmap.md) | Path to a production-ready provider (TPM2, KDE UI, credentialsd) |
| [docs/upstream/](docs/upstream/) | Findings in other projects (polkitd abort on `unix-session` subjects, polkit#699) |

## Known limitations

- Not a platform authenticator from the browser's point of view: `authenticatorAttachment: "platform"` requests and `isUserVerifyingPlatformAuthenticatorAvailable()` do not use it.
- The authenticator never sees the origin, only the RP ID (a CTAP limitation); phishing protection comes from the browser's origin check plus the signed RP ID hash.
- Same-user processes can read KWallet. With the TPM backend this no longer exposes keys, but such malware could still ask the TPM helper to sign (binding signatures to user verification via TPM policy is on the roadmap).
- The USB VID:PID `1209:0001` is a pid.codes test ID and the AAGUID `a4499400-63e6-4329-b1e1-883b52c928b2` is not yet registered in the community list.

## License

LGPL-2.1-or-later (see [LICENSE](LICENSE)); every source file carries an SPDX header.

`org.kde.kpasskey` is a placeholder name; this is not (yet) an official KDE project.
