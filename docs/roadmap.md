# Roadmap: vom Prototyp zum produktionsreifen KDE-Passkey-Provider

## Phase 0 – Prototyp (dieser Stand) ✅
- CTAP 2.1 Authenticator (ES256/EdDSA, rk, built-in UV via polkit, pinUvAuthToken Protokoll 2, selection)
- Virtuelles FIDO-HID-Gerät (uhid), KWallet-Speicher mit Schema v1, Qt-Bestätigungsdialog
- Verwaltungs-D-Bus-API, 73 Unit-/Security-Tests, Interop gegen python-fido2

## Phase 1 – Alltagstauglich auf Entwicklerrechnern
1. ✅ **Browser-E2E** Firefox und Chromium nativ (webauthn.io). Noch offen: Flatpak-Varianten, weitere Seiten (demo.yubico.com, echte Dienste), Rest der Checkliste in `testing.md`.
2. ✅ **Sitzungsbindung**: Das uhid-Gerät existiert nur, solange die eigene logind-Sitzung aktiv ist (`SessionWatcher`).
3. ✅ polkit außerhalb des Session-Scopes: funktioniert mit `unix-process`-Subjekt (Befunde siehe `security.md` T12). Auch als systemd-User-Dienst bestätigt.
4. ✅ **Fuzzing** (libFuzzer, 3 Ziele) und ASan/UBSan-Build (`KPASSKEY_SANITIZE`); noch offen: CI-Einbindung.
5. ✅ Eigene AAGUID (Eintrag in die Community-Liste beim Release). Offen: eigene USB-VID/PID (pid.codes-Antrag), Icon und Übersetzungen (ki18n, `.po`).
6. ✅ Option `--deny-silent` (stille Prüfanfragen ablehnen).
7. ✅ Entwickler-Installationsskripte (`scripts/dev-install.sh`, `dev-uninstall.sh`), udev-Regel auf `uaccess` umgestellt (keine Gruppe, folgt der aktiven Sitzung).

## Phase 2 – Sicherheitshärtung
1. ✅ **uhid-Helper** (umgesetzt als unprivilegierter Systembenutzer statt root): socket-aktivierter root-Dienst (≈200 Zeilen, keine Parser außer Längenprüfung), erzeugt **nur** das feste FIDO-Gerät pro berechtigter Sitzung und reicht 64-Byte-Reports über einen Unix-Socket durch (`SO_PEERCRED` und logind-Sitzungsprüfung). Danach entfällt die udev-Regel für `/dev/uhid`.
2. **Prozess-Trennung** nach credentialsd-Vorbild: UI in eigenem Prozess (Qt/Kirigami), der Daemon ohne GUI-Bibliotheken; seccomp/Landlock für den Daemon.
3. **UV ohne Policy-Lücke**: eigene PAM-Konversation in einem privilegierten Helper oder Nachweis, dass polkit tatsächlich eine Challenge durchgeführt hat; kombinierter Dialog (Bestätigung und Passwort/Fingerabdruck in einem Fenster).
4. **KCM** „Passkeys“ in den Systemeinstellungen (auflisten, umbenennen, löschen mit UV), basierend auf `org.kde.kpasskey.Manager1`.

## Phase 3 – Hardware-Bindung (TPM2)
1. Schema v2: `private_key.protection = "tpm2"`. Schlüssel werden **im TPM erzeugt** (ECC P-256, `TPM2_Create` unter einem persistenten Primary in der Owner-Hierarchie). KWallet speichert nur das TPM-Blob, ein Diebstahl des Wallets oder Home-Verzeichnisses ist damit wertlos.
2. Integritäts-MAC über die Datensätze mit TPM-gebundenem HMAC-Schlüssel (gegen eingeschleuste Credentials).
3. Optionale TPM-Policy mit Auth-Wert, der aus der UV abgeleitet wird; DA-Lockout nutzen; Sessions mit Parameter-Verschlüsselung.
4. Fallback ohne TPM: weiterhin `protection = "kwallet"`, in der UI klar gekennzeichnet.
5. Migration v1→v2 nur auf Nutzerwunsch, weil gerätegebundene Schlüssel bei TPM-Verlust unwiederbringlich sind.

## Phase 4 – Standardpfad credentialsd / Freedesktop
1. **KDE-UI-Backend** für `org.freedesktop.impl.portal.experimental.Credential` (Qt/Kirigami) und Upstream-Beitrag zu credentialsd bzw. xdg-desktop-portal-kde. Das ist unabhängig vom KWallet-Speicher sofort wertvoll für KDE.
2. Mitarbeit an credentialsd **#26 (Third-party providers)** und **#8 (Platform authenticator)**: Den `kpasskeycore` als Provider anbieten. Ab dann erhält der Dienst den geprüften Origin und gilt bei Unterstützung durch Browser als Platform-/Provider-Authenticator (`isUVPAA`, `authenticatorAttachment: "platform"`).
3. Ab diesem Punkt wird der uhid-Pfad optional (Kompatibilitätsmodus für Browser ohne Portal-Unterstützung).
4. Speicher-Abstraktion zusätzlich über den Secret Service (`org.freedesktop.secrets`), damit es auch außerhalb von Plasma läuft (ksecretd, gnome-keyring, oo7).

## Phase 5 – Release
- Security-Review bzw. externer Audit, FIDO Conformance Tools, Reproducible Builds
- Verpackung (Arch, Fedora, openSUSE, Debian; Flatpak ist für den Daemon ungeeignet)
- Dokumentation für Endnutzer: gerätegebundene Passkeys, Backup-Strategie (zweiter Authenticator)
- Optional: KDE-Inkubator → Umbenennung auf `org.kde.*`-Namen erst dann
