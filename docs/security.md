# Sicherheitsmodell / Threat Model

## Schutzziele

1. Private Schlüssel verlassen den Dienst nie über CTAP, D-Bus, Logs oder Fehlermeldungen.
2. Eine Signatur entsteht nur für die RP-ID, an die das Credential gebunden ist, und nur nach User Presence (außer bei stillen Prüfanfragen mit UP=0, die RPs ablehnen).
3. Das UV-Flag wird nur gesetzt, wenn für diese Zeremonie tatsächlich eine Verifikation stattgefunden hat.
4. Signaturzähler sind monoton; ein Zählerwert wird nie zweimal verwendet.
5. Fehler führen zum Abbruch („fail closed“) und nie zu einer Signatur.

## Vertrauensgrenzen

```text
[Website] ─untrusted─▶ [Browser] ─trusted for origin─▶ [hidraw/uhid] ─▶ [kpasskeyd]
                                                                         │
             [andere Prozesse des Benutzers] ─── gleicher UID ───────────┤  ← schwächste Grenze
                                                                         ▼
                                                          [kwalletd6/ksecretd]  [polkit]
```

Der wichtigste Befund vorweg: **Auf einem klassischen Linux-Desktop sind alle nicht-sandboxed Prozesse eines Benutzers gleich vertrauenswürdig.** Sie können KWallet über D-Bus lesen, das hidraw-Gerät öffnen und Fenster zeichnen. Davor schützt erst das Sandboxing (Flatpak) oder TPM-gebundene Schlüssel (Roadmap). Das gilt genauso für Browser-Passwörter, SSH-Agenten und Cookies.

## Bedrohungen

### T1 Kompromittierter Browser
1. **Szenario:** Code-Ausführung im Browserprozess.
2. **Auswirkung:** Der Browser kann für **jede** RP-ID Anfragen stellen und Origin-Prüfungen umgehen. Ist er nicht sandboxed, kann er als gleicher Benutzer auch KWallet direkt auslesen.
3. **Schutz:** Jede Signatur braucht eine Bestätigung im Dialog (UP), der die angefragte RP-ID anzeigt. Bei UV kommt der polkit-Dialog dazu. Über CTAP sind Schlüssel nicht exportierbar.
4. **Restrisiko:** hoch. Ein kompromittierter Browser im selben UID ist gleichbedeutend mit Schlüsselverlust, solange keine TPM-Bindung besteht (Roadmap Phase 3). Bei Flatpak-Browsern ohne Secret-Service-Zugriff ist es geringer.

### T2 Bösartige Website
1. **Szenario:** Eine Seite ruft WebAuthn mit manipulierten Parametern auf.
2. **Auswirkung:** Sie kann nur ihre eigene RP-ID verwenden (Browserregel). Sie kontrolliert `rp.name`, `user.name` und `displayName`.
3. **Schutz:** Alle seitenkontrollierten Strings werden mit `Qt::PlainText` angezeigt (keine Rich-Text-Injektion), auf 64 Zeichen gekürzt und als „unverifiziert“ markiert. Die RP-ID wird separat und hervorgehoben angezeigt. Strikte CBOR-Typprüfung; `user.id` maximal 64 Byte.
4. **Restrisiko:** gering. Social Engineering über irreführende Namen bleibt möglich.

### T3 Phishing
1. **Szenario:** `bank-example.evil` möchte ein Credential von `bank.example` nutzen.
2. **Auswirkung:** keine, solange der Browser korrekt arbeitet.
3. **Schutz:** Der Browser bindet die RP-ID an den Origin. Der Dienst sucht Credentials **ausschließlich innerhalb der angefragten RP-ID** (`<rpId>/<credId>`) und signiert `SHA-256(rpId)`. RP-IDs müssen ASCII-Kleinbuchstaben sein, IDN daher als `xn--`-Punycode; das erschwert Homograph-Täuschung im Dialog. (Tests: `credentialIsScopedToItsRpId`, Interop „cross-origin rpId refused“.)
4. **Restrisiko:** sehr gering. Passkeys sind gerade wegen dieser Bindung phishing-resistent.

### T4 Manipuliertes D-Bus-Programm
1. **Szenario:** Ein lokaler Prozess ruft `org.kde.kpasskey` auf oder gibt sich als polkit/KWallet aus.
2. **Auswirkung:** Die Verwaltungs-API liefert nur Metadaten (keine Schlüssel). Löschen braucht UV. Der Name `org.kde.kpasskey` wird mit `DontQueueService` belegt; eine zweite Instanz beendet sich.
3. **Schutz:** polkit läuft auf dem **System-Bus**, wo Namen wie `org.freedesktop.PolicyKit1` nur root/polkitd besitzen kann. Ein Nutzerprozess kann sich also nicht als polkit ausgeben. KWallet liegt auf dem Session-Bus. Wer dort den Namen vor kwalletd belegt, könnte ein falsches Wallet vortäuschen. Das ist der allgemeine Session-Bus-Schwachpunkt.
4. **Restrisiko:** mittel (Session-Bus-Namenskaperung, Metadaten-Lesen).

### T5 Lokaler Angreifer (gleicher Benutzer, nicht sandboxed)
1. **Szenario:** Malware läuft als derselbe Benutzer.
2. **Auswirkung:** Sie kann a) KWallet-Einträge lesen und damit die privaten Schlüssel stehlen, b) über hidraw Anfragen stellen, c) Dialoge nachahmen.
3. **Schutz:** b) braucht UP/UV im Dialog. `RLIMIT_CORE=0` verhindert Core-Dumps mit Schlüsselmaterial; ptrace-Attach durch Geschwisterprozesse verhindert Yama (`kernel.yama.ptrace_scope ≥ 1`, Standard auf Arch/CachyOS).
4. **Restrisiko:** **hoch, und unvermeidbar ohne Hardware-Bindung**. Lösung: Phase 3, private Schlüssel nur TPM-gewrappt speichern. Dann bleibt ein Signier-Orakel mit UP/UV-Pflicht, aber kein Schlüsseldiebstahl.

### T6 Zugriff auf das Home-Verzeichnis (offline, z. B. gestohlene Festplatte/Backup)
1. **Szenario:** Kopie von `~/.local/share/kwalletd/`.
2. **Auswirkung:** Die Wallet-Datei ist verschlüsselt. Ihre Stärke hängt am Wallet-Passwort. Mit `pam_kwallet` ist das das Login-Passwort, gegen das ein Offline-Brute-Force möglich ist.
3. **Schutz:** KWallet-Verschlüsselung; Empfehlung: Festplattenverschlüsselung (LUKS), starkes Passwort.
4. **Restrisiko:** mittel. Mit TPM-Wrapping (Phase 3) sind die Schlüssel ohne das konkrete Gerät wertlos.

### T7 Zugriff auf KWallet (online) / T8 gestohlene KWallet-Daten
Siehe T5/T6. Zusätzlich sind Einträge **integritätsgeprüft**: Eintragsname ↔ `rp_id`/`credential_id`, und der Public Key wird aus dem Private Key neu abgeleitet und verglichen. Ein umbenannter oder vertauschter Eintrag wird verworfen (Tests `recordMovedToOtherRpIsRejected`, `swappedPublicKeyIsRejected`). Gegen jemanden mit Schreibzugriff schützt das nicht vollständig: Er kann ein selbst erzeugtes, konsistentes Credential einschleusen, also eine Art „Session Fixation“. Abhilfe in Phase 3: ein MAC über den Datensatz mit einem TPM-gebundenen Schlüssel.

### T9 Replay
1. **Szenario:** Eine abgefangene Assertion wird erneut gesendet.
2. **Schutz:** Die RP-Challenge steckt in `clientDataHash` und wird signiert (Test `signatureBindsClientDataHash`, Interop „replayed assertion rejected“). Der Signaturzähler ist pro Credential monoton und wird vor der Signaturausgabe persistiert. Kann er nicht gespeichert werden, gibt es keine Signatur (`noSignatureWhenCounterCannotBePersisted`).
3. **Restrisiko:** gering. Wird die Wallet-Datei auf einen anderen Rechner kopiert (Klon), erkennt die RP das über einen Zählerrückschritt. Das ist so gewollt.

### T10 Credential-ID-Leaks
1. **Szenario:** Die Credential-ID wird bekannt (sie ist laut Spezifikation nicht geheim).
2. **Auswirkung:** Die IDs sind 32 Zufallsbytes ohne kodierte Information. Mit einer ID kann ein lokaler Prozess über eine stille Anfrage (UP=0) prüfen, ob das Credential existiert.
3. **Schutz:** Die Lookup-Logik ist RP-gebunden. Falsche Längen und veränderte IDs liefern `NO_CREDENTIALS` (`manipulatedCredentialIds`).
4. **Restrisiko:** gering (Existenz-Orakel für lokale Prozesse). Mit `kpasskeyd --deny-silent` lassen sich stille Anfragen abschalten (Test `silentProbesCanBeDisabled`). Für die Login-Funktion ist das unschädlich, weil eine normale Anmeldung immer UP verlangt.

### T11 RP-ID-Manipulation
Der Dienst prüft, dass die RP-ID ein plausibler ASCII-Domainname ist (kein Schema, Port, Pfad, keine Großbuchstaben). Die eigentliche Bindung leistet `rpIdHash`; RPs prüfen ihn (Test `signatureBindsRpIdHash`). Einträge können nicht auf eine andere RP „umgehängt“ werden (T8).

### T12 Fehlende/vorgetäuschte User Verification
1. **Szenario:** Eine RP verlangt UV, die Verifikation scheitert oder wird übersprungen.
2. **Schutz:** Das UV-Flag wird nur nach polkit-`Yes` oder einem gültigen pinUvAuthToken gesetzt. `No`, `Challenge`, `Unknown` und Fehler werten als fehlgeschlagen. Ist polkit nicht erreichbar, wird `uv` in `getInfo` gar nicht erst angeboten. Tokens sind 30 s gültig, an RP-ID und Berechtigungen gebunden und werden durch eine neue Anfrage ungültig. Der MAC wird in konstanter Zeit verglichen.
3. **Restrisiko:** **Administratoren können per polkit-Regel `YES` erzwingen**; dann wäre UV wertlos, ohne dass der Dienst es merkt. Das ist dokumentiert. Phase 2 prüft, ob eine Challenge tatsächlich stattfand, bzw. führt die PAM-Konversation im eigenen Helper. Außerdem: Läuft der Daemon außerhalb eines logind-Session-Scopes (systemd --user), greift polkit auf `allow_any` zurück. Deshalb steht dort auch `auth_self`. Ob der KDE-Agent den Dialog dann zeigt, muss im Integrationstest auf jeder Zielplattform geprüft werden.
4. **Befunde aus dem Systemtest (2026-10-08, polkit 127-3.1, Plasma 6.7.5):**
   - Subjekt `unix-process` (eigene PID, wie `pkcheck --process`): **funktioniert**, Dialog von polkit-kde-agent. Wird verwendet.
   - Subjekt `system-bus-name` (mit Details): Die Anfrage erhielt **nie eine Antwort**, der Daemon lief in den Timeout.
   - Subjekt `unix-session`: **polkitd bricht mit einer GLib-Assertion ab (SIGABRT)**, auch bei einem direkten `busctl`-Aufruf ohne kpasskey. Das ist ein lokal auslösbarer DoS in polkit und sollte an polkit-Upstream bzw. CachyOS gemeldet werden.
   - Nach einem Qt-Update ohne Neuanmeldung (Plasma und polkit-kde-agent noch mit gelöschter alter `libQt6Core`) erscheint kein Passwortdialog. Abhilfe: neu anmelden.
   - `prctl(PR_SET_DUMPABLE, 0)` wurde entfernt: Es macht `/proc/<pid>` root-eigen und stört polkit/xdg-desktop-portal. Der ptrace-Schutz kommt jetzt von Yama (`ptrace_scope=1`); Core-Dumps bleiben über `RLIMIT_CORE=0` / `LimitCORE=0` abgeschaltet.

### T13 Race Conditions
- Es wird immer nur **eine** CTAP-Anfrage gleichzeitig bearbeitet; andere Kanäle erhalten `CHANNEL_BUSY` (Test `busyChannelAndCancel`).
- Abgebrochene Anfragen werden über eine Generation-ID verworfen. Ein später Klick auf „Erstellen“ nach einem Browser-`CANCEL` bewirkt nichts (`lateUserApprovalAfterCancelIsIgnored`).
- Der Datensatz wird **nach** dem Dialog neu gelesen, bevor der Zähler erhöht wird.
- Nur eine Daemon-Instanz läuft (D-Bus-Name).
- Restrisiko: Ein anderer Prozess kann denselben KWallet-Eintrag zwischen Lesen und Schreiben ändern (TOCTOU). Folge im schlimmsten Fall ist ein Zählerrückschritt, den die RP erkennt.

### T14 D-Bus-Permission-Probleme
Die Verwaltungs-API liegt auf dem Session-Bus und ist damit nur für Prozesse derselben Sitzung erreichbar. Sie gibt keine Schlüssel heraus; Löschen erfordert UV. Signale enthalten keine Daten. Flatpak-Apps erreichen sie ohne `--talk-name=org.kde.kpasskey` nicht.

### T15 Privilege Escalation
- Der Daemon läuft unprivilegiert, ohne setuid und mit `NoNewPrivileges`.
- **uhid-Zugriff (Phase 2, umgesetzt):** Nur der Systembenutzer `kpasskey-uhid` darf `/dev/uhid` öffnen (udev-Gruppe, keine Benutzer-ACLs). Ihn nutzt ausschließlich `kpasskey-uhid-helper`: socket-aktiviert (`/run/kpasskey/uhid.sock`), ohne Capabilities, stark sandboxed (`DevicePolicy=closed`, nur `/dev/uhid`, `PrivateNetwork`, `SystemCallFilter=@system-service`, …), ohne Qt, ohne CTAP-Parsing. Er
  1. identifiziert den Aufrufer per `SO_PEERCRED`,
  2. verlangt eine **aktive, lokale** logind-Sitzung dieses Benutzers,
  3. erlaubt ein Gerät pro Benutzer (`flock`),
  4. kann **nur** das feste FIDO-Gerät anlegen (fester Report-Descriptor, Name, VID/PID), also **keine Tastaturen** und keine Eingabe-Injektion,
  5. reicht ausschließlich 64-Byte-Reports durch und
  6. entfernt das Gerät, sobald die Verbindung endet oder die Sitzung inaktiv wird (`sd_login_monitor`).

  Restrisiko: Jeder lokale Benutzer mit aktiver Sitzung kann sich ein eigenes FIDO-Gerät anlegen lassen. Mehr als ein Security Key ist damit nicht zu gewinnen. Der Direktmodus (`kpasskeyd --direct-uhid` mit `70-kpasskey-uhid-dev.rules`) bleibt nur für die Entwicklung und hat das alte Risiko: Eingabe-Injektion durch alle Prozesse des aktiven Benutzers.
- Mehrere Benutzer an einem Seat: **behoben (Phase 1).** `SessionWatcher` beobachtet über logind die grafische Sitzung des Benutzers (`User.Display` → `Session.Active`). Wird sie inaktiv (Benutzerwechsel, Sperrbildschirm eines anderen Seats), bricht der Daemon offene Zeremonien ab und entfernt das uhid-Gerät; bei Reaktivierung legt er es neu an. Ist logind nicht erreichbar, wird kein Gerät angelegt (fail closed). Restrisiko: Das Zeitfenster zwischen Sitzungswechsel und Signal liegt im Millisekundenbereich.

### T16 TPM-Angriffe (Phase 3)
- Signier-Orakel: Ein TPM verhindert Schlüsseldiebstahl, nicht den Missbrauch durch einen online-Angreifer mit gleichem UID. UP/UV bleibt nötig.
- Bus-Sniffing (diskretes TPM, LPC/SPI): TPM2-Sessions mit Parameter-Verschlüsselung verwenden.
- Wörterbuchangriffe auf TPM-Auth-Werte: DA-Lockout des TPM nutzen.
- Firmware-TPM-Schwachstellen und Rollback: Bindung an PCRs ist umstritten (Updates brechen den Zugriff). Policy mit `PolicyAuthorize` oder ohne PCR, dafür mit Auth-Wert.
- Verlust von TPM/Mainboard bedeutet Verlust aller Passkeys. Das muss kommuniziert werden (BE=0, also gerätegebunden). Passkeys sollten daher nie der einzige Faktor eines Kontos sein.

## Umsetzung im Code

| Maßnahme | Ort |
|---|---|
| Keine Schlüssel in Logs | `logging.h` (Policy), keine `QDebug`-Operatoren für `SecretBytes`/`CredentialRecord` |
| Schlüsselpuffer überschreiben | `SecretBytes` (`OPENSSL_cleanse`, best effort, siehe Grenzen von QByteArray-Sharing) |
| Keine Core-Dumps | `main.cpp: hardenProcess()`, systemd `LimitCORE=0`; ptrace-Schutz über Yama |
| Zähler vor Signatur persistieren | `Authenticator::getAssertionConfirmed` |
| Integritätsprüfung der Datensätze | `record::decode` |
| Fail-closed UV | `PolkitVerifier`, `Authenticator::checkPinUvAuth` |
| CTAPHID-Robustheit | `CtapHid` (Längen, Sequenzen, Timeouts, unbekannte Kanäle) |
