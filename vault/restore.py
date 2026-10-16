#!/usr/bin/env python3
"""Restore a portable credential from an encrypted backup file.

Prompts for the passphrase, decrypts, writes the credential JSON.
Deliberately reports "wrong passphrase or corrupted backup" without
distinguishing the two.
"""
import argparse
import base64
import getpass
import hashlib
import json
import sys

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.exceptions import InvalidTag
except ImportError:
    sys.exit("Missing dependency: pip install cryptography")


def main():
    p = argparse.ArgumentParser(
        description="Decrypt an encrypted backup back into a portable credential."
    )
    p.add_argument("backup", help="backup file from backup.py")
    p.add_argument("-o", "--output", required=True,
                   help="where to write the restored credential JSON")
    a = p.parse_args()

    with open(a.backup) as f:
        b = json.load(f)

    if b.get("format") != "ucii-encrypted-backup":
        sys.exit("Not a UCII encrypted backup (bad format field).")
    if b.get("format_version") != 1:
        sys.exit(f"Unsupported backup version: {b.get('format_version')}")
    if b.get("kdf") != "scrypt" or b.get("cipher") != "aes-256-gcm":
        sys.exit("Unsupported KDF or cipher.")

    kp = b["kdf_params"]
    passphrase = getpass.getpass("Backup passphrase: ")
    # maxmem: see backup.py — OpenSSL's default 32MB cap is just under what
    # N=2^15/r=8 needs. Local ceiling only; output unaffected.
    maxmem = 128 * kp["n"] * kp["r"] * kp["p"] * 2
    key = hashlib.scrypt(passphrase.encode(), salt=base64.b64decode(kp["salt"]),
                         n=kp["n"], r=kp["r"], p=kp["p"], dklen=32,
                         maxmem=maxmem)
    nonce = base64.b64decode(b["nonce"])
    ciphertext = base64.b64decode(b["ciphertext"])

    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    except InvalidTag:
        sys.exit("Wrong passphrase or corrupted backup.")

    with open(a.output, "wb") as f:
        f.write(plaintext)

    print(f"Restored credential -> {a.output}")
    print("WARNING: this file IS your identity. Anyone holding it is you.")


if __name__ == "__main__":
    main()
