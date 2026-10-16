#!/usr/bin/env python3
"""Export a UCII identity to a portable credential file.

Takes raw key files and an identity ID, writes the portable credential JSON
defined in spec/credential-format.md. This tool only touches files you hand
it — it never talks to the UCII server.
"""
import argparse
import base64
import datetime
import json
import sys

FORMAT = "ucii-portable-credential"
VERSION = 1


def read_key(path):
    with open(path, "rb") as f:
        return base64.b64encode(f.read()).decode()


def main():
    p = argparse.ArgumentParser(
        description="Export a UCII identity to a portable credential file."
    )
    p.add_argument("--identity-id", required=True, help="your permanent UCII identity ID")
    p.add_argument("--ed25519-pub", required=True)
    p.add_argument("--ed25519-priv", required=True)
    p.add_argument("--ml-dsa-65-pub", required=True)
    p.add_argument("--ml-dsa-65-priv", required=True)
    p.add_argument("-o", "--output", required=True, help="where to write the credential JSON")
    a = p.parse_args()

    cred = {
        "format": FORMAT,
        "format_version": VERSION,
        "identity_id": a.identity_id,
        "public_keys": {
            "ed25519": read_key(a.ed25519_pub),
            "ml_dsa_65": read_key(a.ml_dsa_65_pub),
        },
        "private_keys": {
            "ed25519": read_key(a.ed25519_priv),
            "ml_dsa_65": read_key(a.ml_dsa_65_priv),
        },
        "issued_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }

    with open(a.output, "w") as f:
        json.dump(cred, f, indent=2)

    print(f"Exported identity {a.identity_id} -> {a.output}")
    print("WARNING: this file IS your identity. Anyone holding it is you.")
    print("Lock it with backup.py before it goes anywhere.")


if __name__ == "__main__":
    main()
