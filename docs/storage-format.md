# KWallet-Datenmodell

## Ort

| | |
|---|---|
| Wallet | `KWallet::Wallet::LocalWallet()` (Standard: `kdewallet`) |
| Ordner | `Passkeys` |
| Eintragstyp | Passwort (`writePassword`) |
| Eintragsname | `<rp_id>/<base64url(credential_id)>` |
| Wert | kompaktes JSON (UTF-8), siehe unten |

Hinweis zur Plattform: Seit KF 6.30 übersetzt `kwalletd6` die KWallet-API auf den Secret Service von `ksecretd`. Ordner und Eintrag werden dort zu Items mit Attributen. Die Persistenz übernimmt `ksecretd`; `Wallet::sync()` ist dort ein No-Op.

## Bewertung des ursprünglich vorgeschlagenen Schemas

| Vorschlag | Bewertung / Änderung |
|---|---|
| Eintrag = `<credential-id>` | Erweitert zu `<rp_id>/<credential_id>`. So lässt sich nach RP filtern, ohne jeden Eintrag zu entschlüsseln, und ein Eintrag kann nicht unbemerkt einer anderen RP zugeordnet werden (Name und Inhalt werden gegeneinander geprüft). |
| `version` | als `schema` (Ganzzahl) übernommen, plus `type` für künftige Credential-Arten |
| `flags` | **ersetzt** durch explizite Felder (`discoverable`, `uv_at_creation`, `backup_eligible`), damit es keine Bitfeld-Mehrdeutigkeiten zwischen Versionen gibt |
| `private_key` als Rohwert | als Objekt `{format, protection, data}`, damit später TPM-gewrappte Schlüssel ohne Schemabruch möglich sind |
| `public_key` | als COSE_Key gespeichert (genau die Bytes, die der RP mitgeteilt wurden) und beim Laden gegen den Private Key geprüft |
| fehlte | `alg`, `rp_name`, `user_display_name`, `created`, `last_used` |

## Schema v1

```json
{
  "schema": 1,
  "type": "webauthn.public-key",
  "credential_id": "<base64url, 32 Zufallsbytes>",
  "rp_id": "example.com",
  "rp_name": "Example (von der Website, unverifiziert)",
  "user_handle": "<base64url, 1..64 Bytes>",
  "user_name": "alice@example.com",
  "user_display_name": "Alice",
  "alg": -7,
  "public_key_cose": "<base64url, kanonisches CBOR COSE_Key>",
  "private_key": {
    "format": "pkcs8-der",
    "protection": "kwallet",
    "data": "<base64url PKCS#8 PrivateKeyInfo>"
  },
  "sign_count": 0,
  "discoverable": true,
  "uv_at_creation": true,
  "backup_eligible": false,
  "created": "2026-10-08T12:00:00Z",
  "last_used": "2026-10-08T12:05:00Z"
}
```

| Feld | Sensibel | Zweck |
|---|---|---|
| `credential_id` | nein (laut Spezifikation öffentlich) | Lookup; zufällig, ohne kodierte Information |
| `rp_id` | gering | RP-Bindung; muss zum Eintragsnamen passen |
| `user_handle` | mittel (Pseudonym) | wird bei discoverable Login zurückgegeben |
| `user_name`/`user_display_name` | mittel (personenbezogen) | Anzeige; nur nach UV an den Client |
| `public_key_cose` | nein | Integritätsprüfung |
| `private_key.data` | **hoch** | Signatur; nur entschlüsselt im Speicher von kpasskeyd/ksecretd |
| `sign_count` | nein | Klon-/Replay-Erkennung durch die RP |

Was **nicht** gespeichert wird: Challenges, clientDataJSON, Origins, Browserinformationen, PINs oder UV-Geheimnisse.

## Validierung beim Laden (`record::decode`)

1. JSON und alle Typen gültig, Pflichtfelder vorhanden, `schema` bekannt.
2. `credential_id` hat genau 32 Byte, `user_handle` 1–64 Byte, `alg` wird unterstützt, `0 ≤ sign_count ≤ 2^32−1`.
3. `rp_id` ist plausibel **und** `entryKey(rp_id, credential_id)` entspricht dem Eintragsnamen.
4. Der aus `private_key` abgeleitete COSE-Public-Key ist byte-gleich mit `public_key_cose`.

Ungültige Einträge werden übersprungen (Log ohne Inhalt) und niemals überschrieben.

## Schema v2: TPM-geschützte Schlüssel

Bei `--key-backend=tpm` (Standard `auto`, sobald `kpasskey-tpm-helper` installiert ist) entstehen neue Schlüssel **im TPM**. Der Eintrag unterscheidet sich nur im Objekt `private_key`:

```json
"schema": 2,
"private_key": {
  "format": "tpm2b-public-private",
  "protection": "tpm2",
  "data": "<base64url: TPM2B_PUBLIC || TPM2B_PRIVATE (TPM-Marshalling)>"
}
```

- `TPM2B_PRIVATE` ist vom TPM mit dem Speicher-Primärschlüssel verschlüsselt. Auf einem anderen Rechner oder nach einem TPM-Reset ist das Blob **wertlos**. Ein Diebstahl des Wallets bzw. des Home-Verzeichnisses verrät keinen nutzbaren Schlüssel.
- Nur ES256 (TPMs bieten kein Ed25519).
- Validierung beim Laden: Das Blob wird mit `tss2-mu` entpackt. Geprüft werden Typ ECC P-256, ECDSA/SHA-256, `fixedTPM`/`fixedParent`/`sign`, nicht `restricted`/`decrypt`, und der öffentliche Punkt muss byte-gleich mit `public_key_cose` sein.
- Wallet-geschützte Einträge bleiben bei **Schema 1**. Ältere Builds lesen sie weiter und überspringen v2-Einträge, ohne sie anzufassen.

## Migration und Versionierung

- `schema > 1` (von einer neueren Version geschrieben): Der Eintrag wird **nicht angefasst** (`UnsupportedSchema`), damit kein Downgrade Daten zerstört.
- `schema < aktuell`: Migrationskette in `record::decode` (`v1→v2→…`). Geschrieben wird immer im aktuellen Schema, und zwar erst beim nächsten regulären Update des Eintrags (Lazy Migration).
- v2 (umgesetzt): `private_key.protection = "tpm2"`, siehe oben. Geplant für v3: ein Integritäts-MAC über den Datensatz mit einem TPM-gebundenen Schlüssel.

## AAGUID

| | |
|---|---|
| AAGUID | `a4499400-63e6-4329-b1e1-883b52c928b2` (zufällig erzeugte v4-UUID, 2026-10-08) |
| Bedeutung | identifiziert das **Modell** „KDE Passkey (KWallet)“; bei allen Installationen gleich und deshalb nicht personenbezogen |
| Attestation | `packed` Self-Attestation (ohne Zertifikat). RPs können die AAGUID also nicht kryptografisch prüfen; sie dient nur der Anzeige. |

Damit Websites (z. B. webauthn.io oder Passwortmanager) den Namen „KDE Passkey“ anzeigen statt „Unavailable“, muss die AAGUID in die Community-Liste [passkeydeveloper/passkey-authenticator-aaguids](https://github.com/passkeydeveloper/passkey-authenticator-aaguids) eingetragen werden (Pull Request mit Name und Icons). Das gehört zum Release, nicht zum Prototyp. Bis dahin zeigen RPs die AAGUID ohne Namen an. Credentials, die vor dieser Änderung angelegt wurden, behalten die Null-AAGUID; sie steckt nur in der Attestation bei der Registrierung.
