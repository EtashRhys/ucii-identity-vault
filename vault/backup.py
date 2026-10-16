#!/usr/bin/env python3
"""Passphrase-encrypt a portable credential into a backup file.

Format is defined in spec/backup-format.md: scrypt (stdlib) -> AES-256-GCM.
Needs: pip install cryptography
"""
import argparse
import base64
import getpass
import hashlib
import json
import os
import sys

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    sys.exit("Missing dependency: pip install cryptography")

FORMAT = "ucii-encrypted-backup"
VERSION = 1
# scrypt params: N=2^15, r=8, p=1 (interactive), 16-byte salt
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**15, 8, 1
SALT_LEN = 16
MIN_PASSPHRASE = 12


def main():
    p = argparse.ArgumentParser(
        description="Lock a portable credential with a passphrase."
    )
    p.add_argument("credential", help="portable credential JSON from export.py")
    p.add_argument("-o", "--output", required=True, help="where to write the backup file")
    a = p.parse_args()

    with open(a.credential, "rb") as f:
        plaintext = f.read()

    pw1 = getpass.getpass("Backup passphrase: ")
    pw2 = getpass.getpass("Confirm passphrase: ")
    if pw1 != pw2:
        sys.exit("Passphrases don't match.")
    if len(pw1) < MIN_PASSPHRASE:
        sys.exit(f"Passphrase must be at least {MIN_PASSPHRASE} characters.")

    salt = os.urandom(SALT_LEN)
    # maxmem: OpenSSL's default scrypt cap is 32MB; N=2^15/r=8 needs ~33.5MB.
    # This only raises the local memory ceiling — output is unaffected.
    maxmem = 128 * SCRYPT_N * SCRYPT_R * SCRYPT_P * 2
    key = hashlib.scrypt(pw1.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R,
                         p=SCRYPT_P, dklen=32, maxmem=maxmem)
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)

    backup = {
        "format": FORMAT,
        "format_version": VERSION,
        "kdf": "scrypt",
        "kdf_params": {
            "n": SCRYPT_N,
            "r": SCRYPT_R,
            "p": SCRYPT_P,
            "salt": base64.b64encode(salt).decode(),
        },
        "cipher": "aes-256-gcm",
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }

    with open(a.output, "w") as f:
        json.dump(backup, f, indent=2)

    print(f"Backup written -> {a.output}")
    print("Without the passphrase this file is a brick. Don't lose the passphrase.")


if __name__ == "__main__":
    main()
