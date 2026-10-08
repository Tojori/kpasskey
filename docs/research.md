# Stand der Technik (Recherche, Stand 2026-10-08)

Kennzeichnung jeder Aussage:
**[Standard]** normativ spezifiziert · **[implementiert]** in ausgelieferter Software vorhanden ·
**[experimentell]** existiert, aber nicht für Endnutzer/Upstream freigegeben · **[Entwurf]** Vorschlag/Spezifikation in Arbeit ·
**[projektspezifisch]** Entscheidung dieses Projekts · **[unverifiziert]** nach bestem Wissen, nicht im Rahmen dieser Recherche geprüft.

## 1. WebAuthn / FIDO2 / CTAP2 / Passkeys

| Aussage | Status |
|---|---|
| WebAuthn (W3C, Level 3) definiert die Browser-API `navigator.credentials.create/get`. Der **Client (Browser)** prüft Origin ↔ RP-ID und baut `clientDataJSON`; der Authenticator sieht nur `rpId` und `SHA-256(clientDataJSON)`. | [Standard] |
| CTAP 2.0/2.1/2.2 (FIDO Alliance) definiert das Protokoll Client ↔ Authenticator (CBOR-Kommandos, Transporte USB-HID, NFC, BLE, Hybrid). | [Standard] |
| Über CTAP gibt es **keinen** Origin. Phishing-Schutz entsteht dadurch, dass der Browser nur die zum Origin passende RP-ID weitergibt und `rpIdHash` signiert wird. | [Standard] |
| `authenticatorAttachment: "platform"` und `isUserVerifyingPlatformAuthenticatorAvailable()` beziehen sich auf Authenticators, die der **Browser** als Plattform-Authenticator kennt (Windows Hello, macOS/iOS, Android, ggf. browser-eigene). | [Standard] |
| Built-in UV in CTAP 2.1: `getPinUvAuthTokenUsingUvWithPermissions` mit PIN/UV-Auth-Protokoll 1 oder 2; Option `pinUvAuthToken`. | [Standard] |
| Yubicos `python-fido2` 2.2.1 verlangt bei UV-fähigen Authenticators eine nicht-leere `pinUvAuthProtocols`-Liste (Code-Inspektion `fido2/client/__init__.py`, `ctap2/pin.py`). Reines CTAP-2.0-„uv“ reicht für diesen Client nicht. | [implementiert] (geprüft) |

## 2. Linux: Wie sprechen Browser heute mit Authenticators?

| Aussage | Status |
|---|---|
| Firefox (authenticator-rs) und Chromium (`device/fido`) öffnen FIDO-Geräte unter Linux **direkt über `/dev/hidraw*`**. Es gibt keinen Betriebssystem-Dienst dazwischen. | [implementiert] |
| systemd `60-fido-id.rules` erkennt FIDO-HID-Geräte am Report-Descriptor (Usage Page 0xF1D0) und gibt dem aktiven Sitzungsnutzer per `uaccess` Zugriff. Lokal vorhanden: `/usr/lib/udev/rules.d/60-fido-id.rules`. | [implementiert] (geprüft) |
| Virtuelle FIDO-Geräte über `/dev/uhid` werden von Firefox und Chromium als normaler USB-Security-Key erkannt (Vorbilder: tpm-fido, fidorium, vauth, PassKeeZ/keypass). | [implementiert] (Drittprojekte) |
| Chrome speichert Passkeys auch unter Linux im **Google Password Manager** (browser-eigener, cloud-synchronisierter Authenticator, kein OS-Dienst). | [implementiert] |
| Upstream-Firefox und -Chromium haben **keine** Schnittstelle, um einen OS-/Drittanbieter-„Platform Authenticator“ unter Linux einzubinden (kein Gegenstück zu Windows-WebAuthn-API oder macOS-Credential-Provider). | [implementiert] (Ist-Zustand) |
| Snap-Chromium greift auf FIDO-hidraw nur über das `u2f-devices`-Interface zu, das bekannte Vendor/Product-IDs auflistet. Ein virtuelles Gerät mit unbekannter VID/PID wird dort vermutlich blockiert. | [unverifiziert] |

## 3. credentialsd / Credentials for Linux

Quelle: <https://github.com/linux-credentials/credentialsd> (geklont und gelesen), FOSDEM 2026.

| Aussage | Status |
|---|---|
| Aktuelle Version **0.3.1 (2026-09-05)**, LGPL-3.0, Rust. Rollen: Gateway, Flow Controller, Credential Manager (Daemon) sowie UI Controller (`credentialsd-ui`, GTK4-Referenz-UI). | [implementiert] |
| Seit 0.3.0 hängt credentialsd von einem **gepatchten xdg-desktop-portal** ab (Fork `linux-credentials/xdg-desktop-portal`), der als „Trusted Caller“ fungiert. | [experimentell] |
| Öffentliche Schnittstelle: `org.freedesktop.portal.experimental.Credential` (`CreateCredential`, `GetCredential`, Properties wie `PasskeyPlatformAuthenticator`, `UserVerifyingPlatformAuthenticator`). Handler: `org.freedesktop.handler.portal.experimental.Credential`. Daneben gibt es `xyz.iinuwa.credentialsd.Credentials1`. | [Entwurf]/[experimentell] |
| UI-Backend-Schnittstelle: `org.freedesktop.impl.portal.experimental.Credential` (Bus-Name `xyz.iinuwa.credentialsd.UiControl`, `credentialsd.portal`) plus `…Credential.Ceremony` (`Start`, `NotifyStateChanged`, `Cancel`, Signal `UserInteracted`). **Hier kann eine KDE-UI ansetzen.** | [experimentell] |
| Authenticator-Zugriff (USB, Hybrid/caBLE, NFC) läuft über **libwebauthn**. | [implementiert] |
| Firefox-Integration über eine Web-Extension (Firefox 140+), die `navigator.credentials.*` überschreibt und per Native Messaging (Python-Proxy) D-Bus anspricht, sowie über einen gepatchten Firefox als Flatpak (OBS). Chromium-Extension als unpacked extension. | [experimentell] |
| **Platform Authenticator** (Issue #8) und **API für Drittanbieter-Credential-Provider** (Issue #26, z. B. Passwortmanager) sind **offen und nicht spezifiziert**. | [Entwurf] (nur Diskussion) |
| Die Herkunft (Origin) wird bisher vom Aufrufer übernommen. „Application identity / origin binding“ steht in ARCHITECTURE.md als Zukunftsziel. | [Entwurf] |

## 4. Bibliotheken

| Bibliothek | Rolle | Eignung für dieses Projekt | Status |
|---|---|---|---|
| **libfido2** (Yubico, C) | Client-seitig: spricht mit Authenticators (HID/NFC). Liefert u. a. die Tools `fido2-token`, `fido2-cred`, `fido2-assert`. | Implementiert **keinen** Authenticator, ist aber nützlich als unabhängiger Test-Client. | [implementiert] |
| **libwebauthn** (linux-credentials, Rust) | Client-/Plattform-Seite: USB, BLE, Hybrid; Basis von credentialsd. | Implementiert **keinen** Authenticator. Relevant erst bei Integration in credentialsd. | [implementiert] |
| **python-fido2** (Yubico) | Client + RP-Server-Verifikation | Unabhängiger Interop-Test (hier verwendet) | [implementiert] |
| **OpenSSL 3** | Kryptografie (ECDSA P-256, Ed25519, ECDH, HKDF, AES, HMAC) | Einzige Krypto-Quelle des Prototyps | [implementiert] |
| passkey-rs (1Password, Rust) | Enthält eine Authenticator-Implementierung | Option für eine spätere Rust-Variante | [unverifiziert] |

Folgerung **[projektspezifisch]**: Für die Authenticator-Rolle gibt es keine passende C/C++-Bibliothek. Das CTAP-Protokoll (CBOR-Parsing über `QCborValue`, Zustandsmaschine) wird daher selbst implementiert. **Alle kryptografischen Primitive kommen aus OpenSSL.**

## 5. KDE / KWallet / Portale / PAM / polkit / TPM2

| Aussage | Status |
|---|---|
| Auf diesem System (Plasma 6.7.5, KF 6.30): `kwalletd6` stellt die KWallet-API bereit, `ksecretd` stellt `org.freedesktop.secrets` und `org.freedesktop.impl.portal.desktop.kwallet` bereit (per `busctl --user list` geprüft). | [implementiert] (geprüft) |
| KWallet ist seit dem Umbau eine **Übersetzungsschicht über Secret Service (ksecretd)**. `KWallet::Wallet::sync()` ist laut Header seit 6.30 „deprecated, not implemented“ (Compiler-Warnung beim Build). | [implementiert] (geprüft) |
| KWallet / Secret Service bieten **keine Isolation zwischen Prozessen desselben Benutzers** (die `appid` der KWallet-API wird vom Aufrufer selbst angegeben). Flatpak-Apps haben standardmäßig keinen Bus-Zugriff darauf. | [implementiert] |
| xdg-desktop-portal hat einen Secret-Portal (`org.freedesktop.portal.Secret`), aber **keinen** WebAuthn-/Credential-Portal im Upstream. | [implementiert] / Credential-Portal: [Entwurf] |
| polkit 127 (lokal) mit `polkit-kde-agent` (6.7.5): `auth_self` erzwingt bei jeder Prüfung eine Authentifizierung über den PAM-Stack `polkit-1`. Dort greifen z. B. `pam_fprintd` (Fingerabdruck) oder `pam_faillock`. | [implementiert] |
| TPM2: Schlüssel können im TPM erzeugt oder an das TPM gebunden („wrapped“) werden (tpm2-tss / tpm2-tools). Für Passkeys auf Linux nutzen das z. B. tpm-fido und fidorium. credentialsd nennt „TPM-backed platform authenticators“ als Zukunftsthema. | [implementiert] (Drittprojekte) / [Entwurf] (credentialsd) |
