# kpasskey – KWallet-basierter Passkey-Authenticator für KDE Plasma (Prototyp)

> **Status: Prototyp, nicht für den Alltag.** Registrierung und Anmeldung funktionieren mit unverändertem **Firefox und Chromium** (getestet auf webauthn.io, CachyOS / Plasma 6.7). Vor dem Einsatz bitte das [Sicherheitsmodell](docs/security.md) lesen, insbesondere T5: Prozesse desselben Benutzers können KWallet auslesen. Siehe auch die [Roadmap](docs/roadmap.md).

kpasskey speichert WebAuthn-/FIDO2-Passkeys im KDE Wallet und stellt sie Firefox und Chromium zur Verfügung, **ohne Browser-Patches oder Erweiterungen**.

## Wie es funktioniert (Kurzfassung)

Unter Linux gibt es (Stand Oktober 2026) **keine Browser-Schnittstelle für OS-Platform-Authenticators**. Das Freedesktop-Projekt [credentialsd](https://github.com/linux-credentials/credentialsd) arbeitet daran, ist aber experimentell. Es benötigt einen gepatchten xdg-desktop-portal und eine Browser-Extension, und eine Provider-Schnittstelle existiert noch nicht.

kpasskey nutzt deshalb den Weg, den beide Browser heute schon unterstützen: **CTAP 2.1 über USB-HID**. Der Daemon `kpasskeyd` lässt einen virtuellen FIDO2-Security-Key anlegen. Das übernimmt der kleine, sandboxed `kpasskey-uhid-helper`, der als einziger auf `/dev/uhid` zugreifen darf.

```text
Website ─WebAuthn─▶ Firefox/Chromium ─CTAP2/HID─▶ /dev/hidraw ◀─uhid─ kpasskey-uhid-helper ◀─Socket─ kpasskeyd ─┬─▶ KWallet (Ordner „Passkeys“)
                                                                                                                ├─▶ Qt-Dialog (Bestätigung, Kontoauswahl)
                                                                                                                └─▶ polkit → PAM (Passwort/Fingerabdruck) = UV
```

- Private Schlüssel (P-256/Ed25519, erzeugt mit OpenSSL) liegen **nur verschlüsselt im KWallet**.
- **User Verification** = frische Authentifizierung über polkit/PAM (`auth_self`). Eine bloße KWallet-Entsperrung zählt **nicht** als UV ([warum](docs/architecture.md#3-user-verification-warum-kwallet-unlock-keine-uv-ist)).
- Der Browser sieht einen **Security Key**, keinen „Platform Authenticator“ ([Konsequenzen](docs/browser-compat.md)).

## Dokumentation

| Dokument | Inhalt |
|---|---|
| [docs/research.md](docs/research.md) | Stand der Technik mit Kennzeichnung (Standard / implementiert / experimentell / Entwurf) |
| [docs/architecture.md](docs/architecture.md) | Korrektur der Ausgangsannahmen, Zielarchitektur, UV-Semantik |
| [docs/security.md](docs/security.md) | Threat Model (T1–T16) |
| [docs/dbus-api.md](docs/dbus-api.md) | Verwaltungs-API, CTAP-Umfang, Vorschlag für eine credentialsd-Provider-API |
| [docs/storage-format.md](docs/storage-format.md) | KWallet-Schema v1, Validierung, Migration |
| [docs/build.md](docs/build.md) | Bauen, Testen, Installieren |
| [docs/testing.md](docs/testing.md) | Teststrategie und Abdeckung |
| [docs/browser-compat.md](docs/browser-compat.md) | Firefox/Chromium im Detail |
| [docs/roadmap.md](docs/roadmap.md) | Weg zum produktionsreifen Provider (TPM2, KDE-UI, credentialsd) |
| [docs/upstream/](docs/upstream/) | Befunde zu Fremdprojekten (polkitd-Absturz, polkit#699) |

## Schnellstart

```sh
# bauen und testen (kein Root nötig)
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo && cmake --build build -j && ctest --test-dir build --output-on-failure
# installieren (Daemon, Helfer, polkit-Aktion, Units) und starten
sudo scripts/dev-install.sh build "$USER"
systemctl --user daemon-reload && systemctl --user enable --now kpasskeyd.service
```

Abhängigkeiten, Optionen, Fuzzing und Deinstallation: [docs/build.md](docs/build.md).

## Repository-Struktur

```text
├── CMakeLists.txt
├── data/                     polkit-Aktion, systemd-User-Unit
├── docs/
├── packaging/
│   ├── arch/PKGBUILD         Skizze
│   └── udev/                 uhid-Regeln (Helfer-Gruppe; -dev = nur Entwicklung)
├── scripts/                  dev-install.sh / dev-uninstall.sh (Root, nur Test)
├── fuzz/                     libFuzzer-Ziele + Seed-Korpus
├── src/
│   ├── core/                 CTAP2-Engine, Datensatz, Store-Interface, OpenSSL-Wrapper, PIN/UV-Protokoll 2
│   ├── hid/                  CTAPHID-Framing, Transport (Helfer-Socket / direktes uhid)
│   ├── helper/               kpasskey-uhid-helper (einziger /dev/uhid-Nutzer, ohne Qt)
│   ├── kwallet/              KWallet-Backend
│   ├── verification/         polkit-UV
│   ├── ui/                   Qt-Bestätigungsdialog
│   └── daemon/               main, Verwaltungs-D-Bus, logind-Sitzungsbindung
└── tests/
    ├── common/               Fakes, Helfer (inkl. Plattformseite PIN/UV-Protokoll 2)
    ├── unit/                 Authenticator, CTAPHID
    ├── security/             Negativ-/Angriffstests
    └── integration/          stdio-Harness + python-fido2-Interop
```

## Lizenz

LGPL-2.1-or-later (siehe [LICENSE](LICENSE)); jede Quelldatei trägt einen SPDX-Header.

Hinweis: `org.kde.kpasskey` ist ein Platzhalter-Name; dies ist (noch) kein offizielles KDE-Projekt.
