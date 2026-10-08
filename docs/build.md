# Build- und Installationsanleitung (Prototyp)

## Abhängigkeiten

| Paket (Arch/CachyOS) | Zweck |
|---|---|
| `cmake`, `gcc` (C++20) | Build |
| `qt6-base` (Core, DBus, Widgets, Test) | Laufzeit, CBOR, UI, Tests |
| `kwallet` (KF6Wallet), `ki18n` | Speicher, Übersetzungen |
| `polkit-qt6`, `polkit`, `polkit-kde-agent` | User Verification |
| `openssl` ≥ 3.0 | sämtliche Kryptografie |
| optional `python-fido2` bzw. venv mit `fido2` | Interop-Test |
| optional `libfido2` | Test mit `fido2-token` |

Debian/Ubuntu (ungeprüft): `qt6-base-dev libkf6wallet-dev libkf6i18n-dev libpolkit-qt6-1-dev libssl-dev`.

## Bauen und testen (ohne Root)

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j
ctest --test-dir build --output-on-failure
```

Interop-Test mit Yubicos python-fido2 (spielt Browser **und** RP):

```sh
python3 -m venv .venv && .venv/bin/pip install fido2
cmake -S . -B build -DPython3_EXECUTABLE=$PWD/.venv/bin/python
ctest --test-dir build -R interop --output-on-failure
# oder direkt:
.venv/bin/python tests/integration/fido2_interop.py --harness build/tests/stdio_harness
```

## Installation für einen echten Browser-Test

Das Skript installiert Daemon, polkit-Aktion, User-Unit und den **uhid-Helfer**: Systembenutzer `kpasskey-uhid`, `/run/kpasskey`, udev-Regel (nur diese Gruppe darf `/dev/uhid` öffnen) und `kpasskey-uhid.socket`. Eine frühere `uaccess`-Regel samt ACL wird dabei entfernt.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo && cmake --build build -j
sudo scripts/dev-install.sh build "$USER"     # Daemon, polkit-Aktion, User-Unit, udev-Regel
systemctl --user daemon-reload
systemctl --user start kpasskeyd.service
journalctl --user -u kpasskeyd -f
```

Der Daemon verbindet sich mit `/run/kpasskey/uhid.sock`. Der Helfer legt das Gerät nur an, solange die grafische Sitzung des Benutzers aktiv und lokal ist, und entfernt es beim Benutzerwechsel. Der Daemon prüft dasselbe zusätzlich selbst. Logs des Helfers: `journalctl -u 'kpasskey-uhid@*'`.

Prüfen:

```sh
ls -l /dev/hidraw* ; udevadm info /dev/hidrawN | grep -E 'ID_SECURITY_TOKEN|ID_FIDO_TOKEN'
fido2-token -L                     # (libfido2) sollte "KDE Passkey (KWallet)" zeigen
.venv/bin/python tests/integration/fido2_interop.py --hidraw
```

Optionen von `kpasskeyd`:

| Option | Wirkung |
|---|---|
| `--ephemeral` | Credentials nur im Speicher (Test ohne KWallet) |
| `--no-uv` | keine User Verification anbieten |
| `--deny-silent` | stille Prüfanfragen (`up=false`) mit `NO_CREDENTIALS` beantworten (Datenschutz) |
| `--ignore-session` | Gerät unabhängig vom Sitzungsstatus anlegen (nur Test; der Helfer prüft trotzdem) |
| `--key-backend=software\|tpm` | wo neue Schlüssel entstehen. **Standard `software`**: KWallet-geschützt und über ein Wallet-Backup wiederherstellbar. `tpm` nur bewusst wählen: an dieses TPM gebunden, bei TPM-Reset oder Mainboard-Tausch **unwiederbringlich verloren**. Vorhandene Passkeys der jeweils anderen Art funktionieren weiter. |
| `--direct-uhid` | `/dev/uhid` selbst öffnen statt über den Helfer (nur Entwicklung, braucht `packaging/udev/70-kpasskey-uhid-dev.rules`) |

Hinweis: Qt schreibt Logs bei Start über systemd ins Journal. Für Ausgabe auf stderr: `QT_FORCE_STDERR_LOGGING=1`.

## Deinstallation

```sh
systemctl --user disable --now kpasskeyd.service
sudo scripts/dev-uninstall.sh
# Credentials: KWallet-Manager → Ordner "Passkeys" löschen
```

## Fuzzing und Sanitizer

```sh
# ASan + UBSan für alle Tests (gcc oder clang)
cmake -S . -B build-san -DKPASSKEY_SANITIZE=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build-san -j
ASAN_OPTIONS=alloc_dealloc_mismatch=0 ctest --test-dir build-san --output-on-failure

# libFuzzer (nur clang)
CC=clang CXX=clang++ cmake -S . -B build-fuzz -DKPASSKEY_FUZZ=ON -DKPASSKEY_BUILD_DAEMON=OFF -DBUILD_TESTING=OFF
cmake --build build-fuzz -j
mkdir -p /tmp/fz && cp fuzz/corpus/ctaphid/* /tmp/fz/
ASAN_OPTIONS=alloc_dealloc_mismatch=0 build-fuzz/fuzz/fuzz_ctaphid -max_total_time=600 -max_len=8192 /tmp/fz
```

`alloc_dealloc_mismatch=0` ist nötig, weil das nicht instrumentierte `libQt6Core` intern mit `operator new(nothrow)` reserviert und mit `free` freigibt (Qt-JSON/CBOR). Das ist ein falsches Positiv, kein Fehler in kpasskey.
