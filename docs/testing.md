# Teststrategie

## Ebenen

| Ebene | Werkzeug | Ort | Läuft in CI |
|---|---|---|---|
| Unit: CTAP2-Engine | QtTest + `MemoryStore` + Fakes | `tests/unit/test_authenticator.cpp` | ja |
| Unit: CTAPHID-Framing | QtTest | `tests/unit/test_ctaphid.cpp` | ja |
| Security (negativ/adversarial) | QtTest | `tests/security/test_security.cpp` | ja |
| Interop (unabhängige Implementierung) | python-fido2 (Client + RP-Server) über `stdio_harness` | `tests/integration/fido2_interop.py` | ja (falls `fido2` installiert) |
| System: virtuelles Gerät + KWallet + polkit | python-fido2 `--hidraw`, `fido2-token` | manuell / VM | nein (braucht Sitzung) |
| Browser E2E | Firefox, Chromium, webauthn.io | Checkliste unten | manuell |

Stand dieses Prototyps: **80 QtTest-Fälle + 14 Interop-Prüfungen bestehen**, auch unter ASan/UBSan inklusive LeakSanitizer (lokal ausgeführt).

## Systemtest auf echter Hardware-Schnittstelle (2026-10-08)

CachyOS, Plasma 6.7.5, Qt 6.12, polkit 127, KF 6.30; python-fido2 über `/dev/hidraw8` (virtuelles uhid-Gerät):

| Schritt | Ergebnis |
|---|---|
| udev erkennt das Gerät (`ID_FIDO_TOKEN=1`, `ID_SECURITY_TOKEN=1`, uaccess-ACL) | ✅ |
| `getInfo` über hidraw | ✅ CTAP 2.0/2.1, uv, pinUvAuthToken, Protokoll 2 |
| UV-Token über polkit-Dialog (Passwort) | ✅ |
| Registrierung (rk, UV required), RP-Verifikation | ✅ UP=1, UV=1, BE=0 |
| Login (discoverable, UV required), RP-Verifikation | ✅ counter=1 |
| dasselbe mit echtem KWallet (Ordner „Passkeys“), `ListCredentials` per D-Bus | ✅ |
| **Firefox** (nativ, unverändert) auf webauthn.io: Registrierung + Login (discoverable, UV required) | ✅ |
| **Chromium** (nativ, unverändert) auf webauthn.io: Registrierung + Login | ✅ |
| `kpasskeyd` als **systemd-User-Dienst**: polkit-Dialog erscheint, Registrierung OK | ✅ |
| Gerät über **kpasskey-uhid-helper** (Systembenutzer, sandboxed; `/dev/uhid` = `root:kpasskey-uhid 0660`, kein Benutzer-ACL): Registrierung + Login | ✅ |
| hidraw-Knoten des Helfer-Geräts: ACL für den Sitzungsbenutzer über systemd `60-fido-id`/uaccess | ✅ |
| **TPM 2.0** (`kpasskey-tpm-helper`, echtes TPM): Schlüssel erzeugen (0,32 s), Attribute `fixedTPM\|fixedParent\|sensitiveDataOrigin\|userWithAuth\|noDA\|sign`, Signatur (0,19 s) mit Python `cryptography` verifiziert | ✅ |
| TPM: manipuliertes Blob wird vom TPM abgewiesen (`TPM_RC_INTEGRITY`) | ✅ |
| TPM: Registrierung + Login über den Dienst; Wallet-Eintrag ist Schema 2 / `protection: tpm2` | ✅ |
| TPM: Blob eines anderen Benutzers wird abgewiesen | nicht getestet (zweites Konto mit aktiver Sitzung nötig) |

Beobachtete CTAP-Abläufe (aus dem Daemon-Log):

| | Firefox (authenticator-rs) | Chromium (`device/fido`) |
|---|---|---|
| Registrierung | getInfo → clientPIN getKeyAgreement → getPinUvAuthTokenUsingUvWithPermissions (polkit) → makeCredential (UP-Dialog) | gleich, getKeyAgreement zweimal |
| Login mit allowCredentials | prüft **jedes** Credential einzeln per stiller getAssertion (`up=false`, `0x2e` = nicht vorhanden), danach getAssertion mit UP-Dialog | getAssertion direkt mit UP-Dialog |
| kein passendes Credential | Dummy-makeCredential `make.me.blink` mit leerem pinUvAuthParam (Selection-Dialog), danach `NotAllowedError` | – |

webauthn.io zeigt das Credential als „device-bound passkey“, Transport `usb`, AAGUID `00000000-…` („Name: Unavailable“, eigene AAGUID → Roadmap).

## Fuzzing (libFuzzer + ASan/UBSan, `fuzz/`)

| Ziel | Eingabe | Lauf (2026-10-08, je 4 min) | Ergebnis |
|---|---|---|---|
| `fuzz_authenticator` | CTAP-Kommando + CBOR, steuerbarer Fake-Nutzer | 57.822 Läufe, cov 1066 | keine Funde |
| `fuzz_ctaphid` | Folgen von 64-Byte-Reports, echter Authenticator dahinter | 11,9 Mio. Läufe, cov 1085 | keine Funde |
| `fuzz_record` | Wallet-Eintragsname + JSON (angreiferkontrolliert) | 54,4 Mio. Läufe, cov 173 | keine Funde |

Seed-Korpus: `fuzz/corpus/`. Für CI empfohlen: regelmäßige längere Läufe (z. B. OSS-Fuzz/ClusterFuzzLite).

## Abdeckung der geforderten Fälle

### Funktionalität
| Fall | Test |
|---|---|
| Credential Creation | `makeCredentialEs256`, `makeCredentialEdDsaPreferred`, Interop „registration verified by RP“ |
| Credential Discovery | `discoverableAssertionAndCounter`, `allowListAssertion` |
| Assertion | `discoverableAssertionAndCounter`, Interop (3× Login, RP-Verifikation) |
| User Verification | `assertionWithUvReturnsUserInfo`, `tokenBasedRegistrationAndLogin`, Interop (UV required) |
| Credential Deletion | `deletion` (Store); D-Bus `DeleteCredential` manuell |
| Multiple Credentials | `multipleCredentialsSelection`, `residentKeyReplacedForSameUser` |
| Multiple RP IDs | `multipleCredentialsSelection`, Interop „other RP: no credentials“ |
| KWallet Lock/Unlock | `walletLocked` (Store nicht bereit → `OPERATION_DENIED`, danach OK); echtes KWallet manuell: Wallet in kwalletmanager schließen, Login erneut versuchen → Unlock-Dialog, KEEPALIVE hält den Browser |

### Security
| Fall | Test |
|---|---|
| falsche RP-ID | `credentialIsScopedToItsRpId`, `signatureBindsRpIdHash`, `implausibleRpIdsRejected` |
| falscher Origin | Aufgabe des Browsers/Clients: Interop „cross-origin rpId refused by the client“; RP-seitig prüft `Fido2Server` den Origin |
| falsche Challenge | `signatureBindsClientDataHash`, Interop „replayed assertion rejected“ |
| Replay | `replayIsDetectableViaCounter`, `noSignatureWhenCounterCannotBePersisted` |
| manipulierte Credential-ID | `manipulatedCredentialIds` |
| beschädigte KWallet-Daten | `corruptedRecordIsIgnored`, `recordMovedToOtherRpIsRejected`, `swappedPublicKeyIsRejected`, `futureSchemaIsNotTouched` |
| ungültige Signatur | `signatureBindsRpIdHash` / `…ClientDataHash` (Verifikation schlägt fehl) |
| falsche User Verification | `failedUvYieldsNoCredential`, `failedUvYieldsNoAssertion`, `uvFlagNeverSetWithoutVerification`, `token*`-Tests, `invalidPlatformKeyRejected` |
| konkurrierende Requests | `concurrentRequestIsRejected`, `lateUserApprovalAfterCancelIsIgnored`, `busyChannelAndCancel`, `cancelFromOtherChannelIgnored` |
| Timeouts | `userActionTimeout`, `tokenExpires`, `assemblyTimeout` |
| Protokoll-Robustheit | `malformedRequests`, `invalidSequence`, `unknownChannel`, `oversizedMessage`, `u2fMessageRejected` |

## Nächste Testschritte (Roadmap)

- **KWallet-Integrationstest** in einer Wegwerf-Sitzung (`dbus-run-session` + `kwalletd6` + `ksecretd` mit Test-Wallet).
- **FIDO Conformance Tools** (FIDO Alliance) vor einer Zertifizierung bzw. einem Release.

## Browser-E2E-Checkliste (manuell)

Für **Firefox** und **Chromium**, jeweils nativ installiert und als Flatpak:

1. <https://webauthn.io>: Registrierung mit „Discoverable Credential: required“ und „User Verification: required“, danach Login ohne Benutzernamen.
2. <https://demo.yubico.com/webauthn-developers>: Registrierung und Authentifizierung, Flags prüfen (UP, UV, BE=0).
3. Abbruch im Browser-Dialog: Der KDE-Dialog muss sich schließen (CTAPHID CANCEL).
4. Abbruch im KDE-Dialog: Der Browser zeigt einen Fehler, und es entsteht kein Credential.
5. KWallet vorher schließen: Der Unlock-Dialog erscheint, der Browser wartet (KEEPALIVE).
6. Zwei Konten für dieselbe RP: Die Auswahl erfolgt im KDE-Dialog.
7. `excludeCredentials`: erneute Registrierung desselben Kontos → „bereits registriert“.
8. Zweite Browserinstanz parallel → `CHANNEL_BUSY` bzw. der Browser wartet.
