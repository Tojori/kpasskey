#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Interop test: Yubico python-fido2 (client + relying party) against kpasskey.

Plays the roles of the browser (origin -> rpId check, clientDataJSON) and of
the relying party (challenge, origin, rpIdHash, signature, flags and counter
verification) using an independent, widely used implementation.

Usage:
    fido2_interop.py --harness build/tests/stdio_harness     # no root needed
    fido2_interop.py --hidraw                                # against running kpasskeyd
"""
import argparse
import os
import subprocess
import sys

from fido2.client import ClientError, DefaultClientDataCollector, Fido2Client, UserInteraction
from fido2.hid import CtapHidDevice, list_devices
from fido2.hid.base import CtapHidConnection, HidDescriptor
from fido2.server import Fido2Server
from fido2.webauthn import (
    PublicKeyCredentialRpEntity,
    PublicKeyCredentialUserEntity,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

RP = PublicKeyCredentialRpEntity(id="example.com", name="Example")
ORIGIN = "https://example.com"


class PipeConnection(CtapHidConnection):
    def __init__(self, proc):
        self.proc = proc

    def write_packet(self, data):
        # python-fido2 passes the 64 byte report without report ID
        self.proc.stdin.write(data)
        self.proc.stdin.flush()

    def read_packet(self):
        out = b""
        while len(out) < 64:
            chunk = self.proc.stdout.read(64 - len(out))
            if not chunk:
                raise OSError("harness closed")
            out += chunk
        return out

    def close(self):
        self.proc.stdin.close()
        self.proc.wait(timeout=5)


def harness_device(path, *extra):
    proc = subprocess.Popen([path, *extra], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    desc = HidDescriptor("harness", 0x1209, 0x0001, 64, 64, "kpasskey harness", None)
    return CtapHidDevice(desc, PipeConnection(proc))


def hidraw_device():
    for dev in list_devices():
        if dev.descriptor.product_name and "KDE Passkey" in dev.descriptor.product_name:
            return dev
    sys.exit("kpasskeyd device not found (is kpasskeyd running?)")


class Prompt(UserInteraction):
    def prompt_up(self):
        print("  -> confirm the request in the KDE dialog")


def client_for(dev, origin=ORIGIN):
    return Fido2Client(dev, client_data_collector=DefaultClientDataCollector(origin), user_interaction=Prompt())


def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        sys.exit(1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--harness")
    ap.add_argument("--hidraw", action="store_true")
    args = ap.parse_args()
    dev = hidraw_device() if args.hidraw else harness_device(args.harness)

    client = client_for(dev)
    info = client.info
    check("FIDO_2_0" in info.versions, "getInfo advertises FIDO_2_0")
    check(info.options.get("uv") is True and info.options.get("rk") is True, "getInfo: rk + built-in uv")

    server = Fido2Server(RP)
    user = PublicKeyCredentialUserEntity(id=os.urandom(16), name="alice@example.com", display_name="Alice")

    # --- registration (discoverable, UV required) ---
    options, state = server.register_begin(
        user,
        resident_key_requirement=ResidentKeyRequirement.REQUIRED,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    reg = client.make_credential(options.public_key)
    auth_data = server.register_complete(state, reg)
    cred = auth_data.credential_data
    check(auth_data.is_user_verified() and auth_data.is_user_present(), "registration verified by RP, UP+UV set")
    check(not auth_data.is_backup_eligible(), "BE=0 (device-bound credential)")

    # --- excludeCredentials ---
    options, state = server.register_begin(user, credentials=[cred])
    try:
        client.make_credential(options.public_key)
        check(False, "excludeCredentials must fail")
    except ClientError as e:
        check(e.code == ClientError.ERR.DEVICE_INELIGIBLE, "excludeCredentials -> already registered")

    # --- discoverable login (empty allowCredentials), counter monotonic ---
    last = -1
    for i in range(3):
        options, state = server.authenticate_begin(user_verification=UserVerificationRequirement.REQUIRED)
        result = client.get_assertion(options.public_key)
        response = result.get_response(0)
        server.authenticate_complete(state, [cred], response)
        counter = response.response.authenticator_data.counter
        check(counter > last, f"assertion {i + 1} verified by RP, counter {counter} increases")
        last = counter
    check(response.response.user_handle == user.id, "userHandle returned for discoverable login")

    # --- allowCredentials login ---
    options, state = server.authenticate_begin([cred])
    response = client.get_assertion(options.public_key).get_response(0)
    server.authenticate_complete(state, [cred], response)
    check(True, "allowCredentials login verified by RP")

    # --- wrong challenge / replay at the RP ---
    options, state2 = server.authenticate_begin([cred])
    try:
        server.authenticate_complete(state2, [cred], response)  # replay old response
        check(False, "replayed assertion must be rejected")
    except ValueError:
        check(True, "replayed assertion (wrong challenge) rejected by RP")

    # --- phishing: other origin cannot use example.com ---
    phish = client_for(dev, origin="https://example.com.evil.test")
    options, state = server.authenticate_begin([cred])
    try:
        phish.get_assertion(options.public_key)
        check(False, "cross-origin request must be refused by the client")
    except ClientError as e:
        check(e.code == ClientError.ERR.BAD_REQUEST, "cross-origin rpId refused by the client (browser role)")

    # --- different RP has no access ---
    other = Fido2Server(PublicKeyCredentialRpEntity(id="other.example", name="Other"))
    options, state = other.authenticate_begin()
    try:
        client_for(dev, "https://other.example").get_assertion(options.public_key)
        check(False, "other RP must not see example.com credentials")
    except ClientError as e:
        check(e.code == ClientError.ERR.DEVICE_INELIGIBLE, "other RP: no credentials")

    if not args.hidraw:
        dev._connection.close()
        dev = harness_device(args.harness, "--deny-uv")
        options, state = Fido2Server(RP).register_begin(user, user_verification=UserVerificationRequirement.REQUIRED)
        try:
            client_for(dev).make_credential(options.public_key)
            check(False, "failed UV must fail registration")
        except ClientError:
            check(True, "failed user verification -> registration refused")
        dev._connection.close()
    print("all interop checks passed")


if __name__ == "__main__":
    main()
