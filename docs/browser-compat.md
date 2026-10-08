# Browser-Kompatibilität

## Antworten auf die Leitfragen

| Frage | Firefox (Linux) | Chromium/Chrome (Linux) |
|---|---|---|
| Welche API ruft die Website auf? | WebAuthn `navigator.credentials.create/get` [Standard] | gleich [Standard] |
| Womit spricht der Browser Authenticators an? | authenticator-rs, direkt über `/dev/hidraw*` (CTAPHID) [implementiert] | `device/fido`, direkt über hidraw (udev-Enumeration) [implementiert]; zusätzlich Hybrid (Telefon via QR/BLE) und Google Password Manager (browser-eigener Authenticator) [implementiert] |
| Welche D-Bus-Schnittstelle braucht es? | **keine** für den HID-Pfad. Für credentialsd: Web-Extension → Native Messaging → D-Bus (`org.freedesktop.portal.experimental.Credential`) [experimentell] | **keine** für den HID-Pfad. credentialsd-Extension als unpacked extension [experimentell] |
| Ist xdg-desktop-portal beteiligt? | Nein (HID). Ja, aber nur über den gepatchten Portal im credentialsd-Pfad [experimentell] | Nein (HID). Ja, nur im credentialsd-Pfad [experimentell] |
| Rolle von credentialsd | optional, experimentell. Es kann unseren virtuellen Key über libwebauthn als USB-Gerät nutzen. | gleich |
| Browserabhängig | UI, Gerätewahl, Fehlertexte, Umgang mit `pinUvAuthToken`, Hybrid, Flatpak/Snap-Sandbox | gleich, plus GPM-Integration |
| Standardisiert | WebAuthn, CTAP 2.x, CTAPHID, FIDO-HID-Report-Descriptor, udev `ID_SECURITY_TOKEN` (systemd-Konvention) | gleich |

## Wird der Dienst „automatisch als lokaler Platform Authenticator“ erkannt?

**Nein, und das ist mit heutigen Upstream-Browsern unter Linux nicht möglich.** Erkannt wird er **automatisch als Security Key** (cross-platform, Transport `usb`), sobald `kpasskeyd` läuft. Praktische Folgen:

| Website-Anforderung | Ergebnis mit kpasskey |
|---|---|
| keine `authenticatorAttachment`-Vorgabe (häufigster Fall) | funktioniert |
| `authenticatorAttachment: "cross-platform"` | funktioniert |
| `authenticatorAttachment: "platform"` | **funktioniert nicht** (der Browser fragt nur eigene Platform-Authenticators) |
| Upgrade-Banner auf Basis von `isUserVerifyingPlatformAuthenticatorAvailable()` | wird nicht angezeigt |
| Conditional UI / Autofill (`mediation: "conditional"`) | hängt vom Browser ab; für Security Keys meist **nicht** angeboten |
| `hints: ["client-device"]` | wird ggf. zugunsten anderer Authenticators priorisiert |

## Firefox im Detail

- Nativ installiert: hidraw-Zugriff über `uaccess`. Das sollte ohne Konfiguration funktionieren.
- Flatpak (`org.mozilla.firefox`): benötigt Gerätezugriff (`--device=all`). Das offizielle Flatpak hat ihn nach meinem Kenntnisstand [unverifiziert]; prüfbar mit `flatpak info --show-permissions org.mozilla.firefox`.
- Snap: Zugriff nur über das Interface `u2f-devices`, das bekannte VID/PIDs auflistet. Unser Test-VID:PID ist dort vermutlich nicht enthalten [unverifiziert].
- UV-Pfad: Firefox nutzt bei CTAP-2.1-Geräten mit `pinUvAuthToken` den Token-Pfad (`getPinUvAuthTokenUsingUvWithPermissions`); sonst die Option `uv`. Beide sind implementiert. Welchen Pfad die jeweilige Version wählt, muss die E2E-Checkliste zeigen.

## Chromium/Chrome im Detail

- Nativ installiert: wie Firefox.
- Flatpak (`com.google.Chrome`, `org.chromium.Chromium`): Gerätezugriff vorhanden [unverifiziert].
- Snap-Chromium: siehe Snap-Hinweis oben.
- Chrome zeigt im eigenen Dialog parallel „Security Key verwenden“, Hybrid und GPM an. Der Nutzer muss im Chrome-Dialog ggf. erst „USB-Sicherheitsschlüssel“ wählen; danach erscheint der KDE-Dialog. Mit `authenticatorSelection` (0x0B) bzw. der Zero-Length-pinUvAuthParam-Probe zeigt der KDE-Dialog „KWallet verwenden?“.
- Chrome sendet zur `excludeCredentials`-Prüfung stille `getAssertion` (`up=false`). Diese werden beantwortet (UP=0) und erhöhen den Zähler (beobachtet mit python-fido2, das genauso vorgeht).

## Getestet (2026-10-08)

Firefox und Chromium (beide nativ aus den CachyOS-Paketen, ohne Erweiterung) registrieren und melden sich auf webauthn.io erfolgreich mit kpasskey an; beide verwenden den CTAP-2.1-Token-Pfad (`getPinUvAuthTokenUsingUvWithPermissions`). Details: `testing.md`. Flatpak/Snap-Varianten: noch ungetestet.

## Bekannte Einschränkungen

1. Kein „Platform Authenticator“ aus Browsersicht (s. o.).
2. Der KDE-Dialog kennt den **Origin nicht**, nur die RP-ID (Grenze von CTAP).
3. Zwei Dialoge bei UV (Browser + KDE-Bestätigung + polkit-Passwort). Eine kombinierte UX kommt mit Phase 2 bzw. dem credentialsd-Pfad.
4. Unter Wayland kann KWin den Dialog bei Fokus-Diebstahl-Schutz in den Hintergrund legen. Eine Lösung über `xdg-activation`-Token gibt es mit dem credentialsd-Pfad (Window Handles) bzw. KWin-Regeln.
