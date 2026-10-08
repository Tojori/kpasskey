#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Installs kpasskey for local testing. Run as root:
#   sudo scripts/dev-install.sh <build-dir> <user>
# Undo with scripts/dev-uninstall.sh.
#
# /dev/uhid is only accessible to the system user "kpasskey-uhid" which runs
# the sandboxed, socket-activated kpasskey-uhid-helper (docs/security.md T15).
set -euo pipefail

build_dir=${1:?usage: $0 <build-dir> <user>}
user=${2:?usage: $0 <build-dir> <user>}
src_dir=$(cd "$(dirname "$0")/.." || exit 1; pwd)
prefix=/usr/local

if [[ "$EUID" -ne 0 ]]; then
    echo "must run as root" >&2
    exit 1
fi
if [[ ! -x "$build_dir/kpasskeyd" || ! -x "$build_dir/kpasskey-uhid-helper" || ! -x "$build_dir/kpasskey-tpm-helper" ]]; then
    echo "kpasskeyd / helpers missing in $build_dir - build first" >&2
    exit 1
fi
id "$user" >/dev/null

echo "== installing to $prefix"
cmake --install "$build_dir" --prefix "$prefix"

echo "== polkit action"
# polkitd only reads /usr/share/polkit-1/actions
ln -sf "$prefix/share/polkit-1/actions/org.kde.kpasskey.policy" /usr/share/polkit-1/actions/org.kde.kpasskey.policy

echo "== system user, runtime dir"
systemd-sysusers "$prefix/lib/sysusers.d/kpasskey.conf"
systemd-tmpfiles --create "$prefix/lib/tmpfiles.d/kpasskey.conf"

echo "== udev: /dev/uhid only for group kpasskey-uhid (removing the old user ACL rule)"
rm -f /etc/udev/rules.d/70-kpasskey-uhid.rules
# Drop ACLs left by the earlier uaccess rule FIRST: while an ACL exists, the
# chmod 0660 done by udev only changes the ACL mask, and removing the ACL
# afterwards would fall back to the old "group::---" entry (mode 0600).
setfacl -b /dev/uhid 2>/dev/null || true
udevadm control --reload
udevadm trigger --action=change /dev/uhid
udevadm settle
ls -l /dev/uhid
getfacl -p /dev/uhid 2>/dev/null | grep -E "^(user|group):" || true

echo "== helper sockets"
systemctl daemon-reload
systemctl enable --now kpasskey-uhid.socket
if [[ -e /dev/tpmrm0 ]] && getent group tss >/dev/null; then
    systemctl enable --now kpasskey-tpm.socket
else
    echo "no TPM 2.0 resource manager (/dev/tpmrm0) or group tss: TPM key helper not enabled"
fi
ls -l /run/kpasskey/

echo
echo "Done. As $user (no root):"
echo "  systemctl --user daemon-reload && systemctl --user restart kpasskeyd.service"
echo "  journalctl --user -u kpasskeyd -f        # daemon"
echo "  journalctl -u 'kpasskey-uhid@*' -u 'kpasskey-tpm@*' -f   # helpers"
