# Architektur

## 1. Korrektur der ursprünglichen Annahmen

| Ursprüngliche Annahme | Bewertung | Begründung |
|---|---|---|
| Browser greifen direkt über D-Bus auf `credentialsd` zu. | **Falsch (heute)** | Upstream-Firefox/-Chromium kennen credentialsd nicht. Es geht nur über eine Web-Extension mit Native-Messaging-Proxy oder einen gepatchten Firefox (beides experimentell). Seit 0.3 ist zudem ein gepatchtes xdg-desktop-portal nötig. |
| `xdg-desktop-portal` ist zwingend erforderlich. | **Teilweise falsch** | Für Browser, die per HID mit Authenticators sprechen, spielt der Portal keine Rolle. Nur der credentialsd-Pfad (≥ 0.3) setzt den experimentellen Credential-Portal voraus, und der ist nicht upstream. |
| KWallet-Entsperrung zählt als FIDO2 User Verification. | **Falsch** | Siehe Abschnitt 3. |
| `libwebauthn` ist die richtige Bibliothek. | **Falsch für die Authenticator-Rolle** | libwebauthn (wie libfido2) ist eine *Client*-Bibliothek, die vorhandene Authenticators anspricht. Ein Authenticator, der Schlüssel hält und signiert, ist darin nicht enthalten. libwebauthn wird erst relevant, wenn der Dienst in credentialsd integriert wird (der credentialsd-Daemon nutzt es). |
| Ein eigener Platform Authenticator wird von Firefox/Chromium akzeptiert. | **Nicht als „platform“** | Es gibt unter Linux keine Browser-API für OS-Platform-Authenticators. Machbar ist ein Authenticator, den der Browser als **USB-Security-Key (cross-platform)** sieht: ein virtuelles CTAPHID-Gerät über `/dev/uhid`. Folgen: `isUserVerifyingPlatformAuthenticatorAvailable()` bleibt `false`, und Anfragen mit `authenticatorAttachment: "platform"` erreichen den Dienst nicht. |
| Der Dienst führt eine strikte Origin-Validierung durch. | **Nicht möglich auf CTAP-Ebene** | Ein Authenticator sieht nie den Origin, nur `rpId` und `clientDataHash`. Die Origin↔RP-ID-Prüfung macht der Browser. Der Dienst kann nur die RP-ID syntaktisch prüfen, Credentials strikt nach RP-ID trennen und `rpIdHash` signieren. |

## 2. Gewählte Architektur (zweigleisig)

**Track A – sofort nutzbar (dieser Prototyp)** [projektspezifisch]: ein virtueller FIDO2-Security-Key mit KWallet-Speicher.

```text
Website (JS: navigator.credentials.create/get)
   │  WebAuthn  [Standard]
   ▼
Firefox (authenticator-rs) / Chromium (device/fido)
   │  - prüft Origin ↔ RP-ID, baut clientDataJSON      ← Phishing-Schutz liegt HIER
   │  - erkennt FIDO-HID per Usage Page 0xF1D0
   │  CTAP 2.1 über CTAPHID, 64-Byte-Reports  [Standard]
   ▼
/dev/hidrawN  (udev 60-fido-id.rules → uaccess für aktive Sitzung)
   │
   ▼  Linux-Kernel: uhid
/dev/uhid
   │
   ▼
kpasskeyd  (Benutzer-Daemon, systemd --user)            [projektspezifisch]
   ├── HelperDevice   Unix-Socket → kpasskey-uhid-helper (einziger /dev/uhid-Nutzer)
   ├── CtapHid        CTAPHID-Framing, Kanäle, KEEPALIVE, CANCEL
   ├── Authenticator  CTAP2: getInfo, makeCredential, getAssertion,
   │                  clientPIN (nur UV-Token, Protokoll 2), selection
   ├── PresenceDialog Qt-Dialog: User Presence + Kontoauswahl
   ├── PolkitVerifier User Verification → polkit (auth_self)
   │        │ D-Bus (System-Bus)
   │        ▼
   │     polkitd → polkit-kde-agent (KDE-Dialog) → PAM „polkit-1“
   │                                         (Passwort, pam_fprintd, …)
   ├── KWalletStore   KF6Wallet-API (Session-Bus)
   │        ▼
   │     kwalletd6 (KWallet-API) → ksecretd (Secret Service) → Wallet-Datei
   └── ManagerDBus    org.kde.kpasskey (Verwaltung, nicht für Browser)
```

**Track B – Standardpfad, sobald verfügbar** [Entwurf]:

```text
Browser ──(künftig nativ / heute Web-Extension)──▶ xdg-desktop-portal
   org.freedesktop.portal.experimental.Credential
        ▼
credentialsd  (Gateway, Flow Controller, Credential Manager; libwebauthn)
   │                                  │
   │ impl.portal.experimental.Credential (UI-Backend)
   │                                  ▼
   │                        KDE-UI-Backend (Qt/Kirigami) ← KDE-Beitrag
   ▼
Authenticators: USB/NFC/Hybrid … und künftig „Provider“ (Issue #26)
   └── kpasskey-Kern als Provider (KWallet + polkit-UV)
```

Zusammenspiel: Weil credentialsd USB-HID-Geräte über libwebauthn anspricht, ist der Track-A-Dienst **heute schon** über credentialsd erreichbar, und zwar als „Security Key“. Sobald credentialsd eine Provider-Schnittstelle (#26) oder einen Platform Authenticator (#8) definiert, wird der Kern (`kpasskeycore`) hinter dieser Schnittstelle angeboten. Ab dann zählt er als echter Platform-/Provider-Authenticator mit Origin-Informationen.

### Übergänge im Detail

1. **Website → Browser**: WebAuthn-API. Der Browser bestimmt den Origin und erzwingt, dass `rp.id` ein registrierbares Suffix des Origins ist. `clientDataJSON` enthält Challenge, Origin und Typ.
2. **Browser → hidraw**: CTAPHID (Init/Continuation-Pakete, Kanal-IDs). Der Browser findet das Gerät über udev; Zugriff hat nur der aktive Sitzungsnutzer.
3. **hidraw → uhid → kpasskeyd**: Der Kernel reicht die Output-Reports als `UHID_OUTPUT`-Events weiter (inkl. Report-ID-Byte 0). Antworten gehen als `UHID_INPUT2` zurück.
4. **CtapHid → Authenticator**: Vollständig zusammengesetzte CBOR-Nachricht. Während Benutzerinteraktion sendet CtapHid alle 100 ms `KEEPALIVE` (Status `UPNEEDED`); `CANCEL` bricht Dialoge ab.
5. **Authenticator → PresenceDialog**: Bestätigung (UP) und Kontoauswahl. Der Dialog zeigt die **RP-ID** fett; `rp.name` und Benutzernamen werden als Klartext und „vom Website-Betreiber angegeben (unverifiziert)“ angezeigt.
6. **Authenticator → PolkitVerifier**: UV per polkit-Aktion `org.kde.kpasskey.verify-user` (`auth_self`, ohne Caching). Die RP-ID steht in den Details.
7. **Authenticator → KWalletStore**: Lesen und Schreiben pro Credential. Der Zähler wird **vor** der Herausgabe der Signatur persistiert.
8. **ManagerDBus**: Auflisten und Löschen (Löschen nur nach UV) für eine spätere KCM.

## 3. User Verification: Warum KWallet-Unlock keine UV ist

FIDO-UV bedeutet laut WebAuthn §6.2.3 „the authenticator *locally authorizes* the invocation of the operation“: Der berechtigte Benutzer wird **für diese Zeremonie** verifiziert.

- KWallet wird typischerweise **einmal pro Sitzung** entsperrt, oft automatisch beim Login über `pam_kwallet`, und bleibt offen. Wer später an einem entsperrten, unbeaufsichtigten Rechner sitzt, könnte sonst Anmeldungen mit UV=1 erzeugen.
- Die Entsperrung ist nicht an eine RP oder eine Zeremonie gebunden. Jeder Prozess des Benutzers kann sie auslösen bzw. von ihr profitieren.
- RPs verlassen sich bei UV=1 auf Zwei-Faktor-Qualität (Besitz + Wissen/Biometrie). Ein „Dauer-offen“-Zustand liefert das nicht.

Daher **[projektspezifisch]**:

| Mechanismus | Rolle |
|---|---|
| KWallet-Unlock | Nur **Speicherverfügbarkeit**. Ist das Wallet gesperrt, schlägt die Anfrage mit `OPERATION_DENIED` fehl, ohne UV-Flag. |
| Qt-Bestätigungsdialog | **User Presence (UP)** |
| polkit `auth_self` → PAM | **User Verification (UV)**, frisch für jede Zeremonie (bzw. pro pinUvAuthToken, max. 30 s, RP-gebunden) |
| Fingerabdruck | über `pam_fprintd` im PAM-Stack `polkit-1`, ohne Code-Änderung |
| PIN (CTAP clientPIN) | bewusst **nicht** angeboten. Eine zweite, schwächere Geheimnisebene neben dem Konto-Passwort bringt hier keinen Gewinn. |
| TPM2 | Roadmap: Schlüsselschutz („wrapping“) statt UV. Wenn eine TPM-PIN/Policy genutzt wird, kann daraus zusätzlich UV werden. |

## 4. Verhalten gegenüber CTAP

- `getInfo`: `versions = [FIDO_2_0, FIDO_2_1]`, `options = {rk, up, uv, plat:false, pinUvAuthToken}`, `pinUvAuthProtocols = [2]`, `transports = [usb]`, `algorithms = [ES256, EdDSA]`. `clientPin` fehlt bewusst (keine PIN).
- Attestation: `packed` **Self-Attestation**. AAGUID `a4499400-63e6-4329-b1e1-883b52c928b2` (siehe `storage-format.md`).
- Flags: `BE = BS = 0`, weil KWallet-Credentials nicht synchronisiert werden und damit gerätegebunden sind.
- Mehrere Konten: Der Dienst hat ein eigenes Display (den Dialog) und wählt selbst. `getNextAssertion` wird daher nicht benötigt.
- `authenticatorReset` über CTAP ist gesperrt; Löschen geschieht nur über die Verwaltungs-API mit UV.

## 5. Prozess- und Rechte-Modell

| Komponente | läuft als | Privilegien |
|---|---|---|
| kpasskeyd | Benutzer, `systemd --user` | Unix-Socket zum Helfer, Session-Bus, System-Bus (polkit); **kein** Zugriff auf `/dev/uhid` |
| polkitd | root/polkitd | Standard |
| polkit-kde-agent | Benutzer | Standard (vertrauenswürdiger Auth-Dialog) |
| kwalletd6 / ksecretd | Benutzer | Standard |
| kpasskey-uhid-helper | Systembenutzer `kpasskey-uhid`, socket-aktiviert pro Verbindung, sandboxed | einziger Zugriff auf `/dev/uhid`; kann **ausschließlich** das feste FIDO-Gerät erzeugen und Reports weiterreichen |
| kpasskey-tpm-helper | Systembenutzer `kpasskey-tpm` (Gruppe `tss`), socket-aktiviert, sandboxed | einziger Zugriff auf `/dev/tpmrm0`; erzeugt nicht exportierbare P-256-Schlüssel und signiert Digests (uid-gebunden) |
