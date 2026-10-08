# D-Bus-API

## Grundsatzentscheidung

**Es gibt (noch) keine standardisierte D-Bus-Schnittstelle, über die Browser einen Linux-Platform-Authenticator ansprechen.** Der einzige ernsthafte Standardisierungskandidat ist der experimentelle Credential-Portal von credentialsd (`org.freedesktop.portal.experimental.Credential`). Er richtet sich an *Clients* (Browser/Apps), nicht an Authenticators, und eine Provider-Schnittstelle für Authenticators ist noch nicht definiert (credentialsd-Issues #8, #26).

Daraus folgt **[projektspezifisch]**:

1. Für Browser definiert dieses Projekt **keine eigene WebAuthn-D-Bus-API**. Browser sprechen den Standard **CTAP 2.1 über CTAPHID**.
2. Für die Desktop-Integration (Verwaltung, künftige KCM) gibt es eine kleine **Verwaltungs-API** auf dem Session-Bus.
3. Für den Standardpfad ist der vorgesehene KDE-Beitrag ein **UI-Backend für `org.freedesktop.impl.portal.experimental.Credential`** (analog zu `credentialsd-ui`) sowie, sobald spezifiziert, die Provider-Schnittstelle von credentialsd.

## Verwaltungs-API (implementiert)

> `org.kde.kpasskey` ist ein **Platzhalter**. Der `org.kde.*`-Namensraum darf nur verwendet werden, wenn das Projekt ein KDE-Projekt wird. Andernfalls ist ein eigener Reverse-DNS-Name zu wählen.

| | |
|---|---|
| Bus | Session-Bus |
| Bus-Name | `org.kde.kpasskey` (exklusiv, `DontQueueService`) |
| Objektpfad | `/org/kde/kpasskey` |
| Interface | `org.kde.kpasskey.Manager1` |

### Methoden

| Methode | Signatur | Beschreibung | Berechtigung |
|---|---|---|---|
| `ListCredentials(s rp_id) → a(sssxx)` | in: RP-ID oder `""` für alle; out: `(credential_id_b64url, rp_id, user_name, created_unix, last_used_unix)` | Nur Metadaten, niemals Schlüssel oder User-Handles | jeder Prozess der Sitzung |
| `DeleteCredential(s credential_id)` | in: Credential-ID (base64url) | Löscht nach **frischer UV** (polkit `org.kde.kpasskey.verify-user`) | UV erforderlich |
| `GetStatus() → a{sv}` | `version`, `busy`, `user_verification`, `storage` | Diagnose | jeder Prozess der Sitzung |
| `ExportCredentials() → a{sv}` | out: `exported`, `skipped_hardware_bound`, `skipped_nonzero_counter`, `path` | **Löst nur aus:** UV, Dateiauswahl und Passphrase laufen über die Dialoge von kpasskeyd. Schlüssel und Passphrase kommen nie auf den Bus. Schreibt ein verschlüsseltes CXF-Backup (siehe `storage-format.md`). | UV erforderlich |
| `ImportCredentials() → a{sv}` | out: `imported`, `skipped_existing`, `skipped_invalid`, `skipped_other_types` | wie oben, liest ein Backup ein | UV erforderlich |

### Signale

| Signal | Bedeutung |
|---|---|
| `CredentialsChanged()` | Ein Credential wurde angelegt, aktualisiert oder gelöscht (ohne Daten) |

### Fehler

| Fehlername | Wann |
|---|---|
| `org.kde.kpasskey.Error.NotFound` | Credential-ID unbekannt |
| `org.kde.kpasskey.Error.NotAuthorized` | UV fehlgeschlagen oder abgebrochen |
| `org.kde.kpasskey.Error.WalletUnavailable` | KWallet deaktiviert oder Öffnen abgelehnt |
| `org.kde.kpasskey.Error.Busy` | Eine WebAuthn-Zeremonie oder ein Backup läuft gerade |
| `org.kde.kpasskey.Error.Cancelled` | Datei- oder Passphrase-Dialog abgebrochen |
| `org.kde.kpasskey.Error.Failed` | Datei nicht les-/schreibbar, kein gültiges Backup |

### Beispiele

```sh
busctl --user call org.kde.kpasskey /org/kde/kpasskey org.kde.kpasskey.Manager1 GetStatus
busctl --user call org.kde.kpasskey /org/kde/kpasskey org.kde.kpasskey.Manager1 ListCredentials s ""
busctl --user call org.kde.kpasskey /org/kde/kpasskey org.kde.kpasskey.Manager1 DeleteCredential s "<id>"
busctl --user --timeout=600 call org.kde.kpasskey /org/kde/kpasskey org.kde.kpasskey.Manager1 ExportCredentials
busctl --user --timeout=600 call org.kde.kpasskey /org/kde/kpasskey org.kde.kpasskey.Manager1 ImportCredentials
```

## polkit-Aktion (implementiert)

| Aktion | Defaults | Zweck |
|---|---|---|
| `org.kde.kpasskey.verify-user` | `auth_self` für any/inactive/active, **kein** `_keep` | User Verification. Details-Map: `rp_id` |

## CTAP-Schnittstelle zum Browser (Standard)

CTAP 2.1 über CTAPHID auf einem virtuellen USB-HID-Gerät (`/dev/hidrawN`), Name „KDE Passkey (KWallet)“, VID:PID `1209:0001` (**pid.codes-Test-ID, vor einem Release ersetzen**).

| Kommando | Unterstützt |
|---|---|
| `authenticatorMakeCredential (0x01)` | ja (ES256, EdDSA; rk; uv; pinUvAuthParam Protokoll 2; excludeList) |
| `authenticatorGetAssertion (0x02)` | ja (allowList, discoverable, up=false still, uv, pinUvAuthParam) |
| `authenticatorGetInfo (0x04)` | ja |
| `authenticatorClientPIN (0x06)` | nur `getKeyAgreement`, `getPinUvAuthTokenUsingUvWithPermissions` (mc/ga), `getUVRetries` |
| `authenticatorReset (0x07)` | **nein** (`NOT_ALLOWED`), Löschen nur mit UV über die Verwaltungs-API |
| `authenticatorGetNextAssertion (0x08)` | nein, nicht nötig (eigene Kontoauswahl) |
| `authenticatorSelection (0x0B)` | ja |
| CTAPHID `MSG` (U2F/CTAP1) | nein (`NMSG`-Capability) |

## Vorschlag: Provider-Schnittstelle für credentialsd [Entwurf, projektspezifisch]

Nur als Diskussionsbeitrag zu credentialsd #26 gedacht, **nicht implementiert und kein Standard**. Er lehnt sich an die dort diskutierte Idee an (`Authenticator`-Interface mit `GetCredential`/`CreateCredential`):

```text
Interface  org.freedesktop.experimental.CredentialProvider1   (Vorschlag)
  CreateCredential(a{sv} request) -> a{sv}     # request enthält origin, rp_id, client_data_hash, …
  GetCredential(a{sv} request) -> a{sv}
  Property  s DisplayName, as SupportedTypes
Registrierung: nur per Nutzer-Opt-in über die Systemeinstellungen (Schutz vor Selbstregistrierung bösartiger Provider, siehe #26)
Aufrufer:     nur credentialsd (Peer-Prüfung über SO_PEERCRED / Bus-Policy)
```

Mit diesem Modell erhielte der Provider zusätzlich den vom Trusted Caller geprüften Origin und könnte ihn im KDE-Dialog anzeigen. Über CTAPHID ist das nicht möglich.
