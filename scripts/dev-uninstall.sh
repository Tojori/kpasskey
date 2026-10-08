#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Removes what scripts/dev-install.sh installed. Run as root. Stored passkeys
# stay in KWallet (folder "Passkeys") until you delete them there. The system
# users kpasskey-uhid / kpasskey-tpm are kept (remove with userdel).
# TPM-protected passkeys become unusable without kpasskey-tpm-helper.
set -euo pipefail

prefix=/usr/local
if [[ "$EUID" -ne 0 ]]; then
    echo "must run as root" >&2
    exit 1
fi
systemctl disable --now kpasskey-uhid.socket kpasskey-tpm.socket 2>/dev/null || true
rm -f /etc/udev/rules.d/70-kpasskey-uhid.rules \
      "$prefix/lib/udev/rules.d/70-kpasskey-uhid.rules"
udevadm control --reload
udevadm trigger --action=change /dev/uhid
rm -f /usr/share/polkit-1/actions/org.kde.kpasskey.policy
rm -f "$prefix/libexec/kpasskeyd" "$prefix/libexec/kpasskey-uhid-helper" "$prefix/libexec/kpasskey-tpm-helper" \
      "$prefix/share/polkit-1/actions/org.kde.kpasskey.policy" \
      "$prefix/lib/systemd/user/kpasskeyd.service" \
      "$prefix/lib/systemd/system/kpasskey-uhid.socket" \
      "$prefix/lib/systemd/system/kpasskey-uhid@.service" \
      "$prefix/lib/systemd/system/kpasskey-tpm.socket" \
      "$prefix/lib/systemd/system/kpasskey-tpm@.service" \
      "$prefix/lib/sysusers.d/kpasskey.conf" \
      "$prefix/lib/tmpfiles.d/kpasskey.conf"
rm -rf /run/kpasskey
systemctl daemon-reload
echo "removed. As your user: systemctl --user stop kpasskeyd.service; systemctl --user daemon-reload"
