#!/usr/bin/env python3
"""Import a portable credential: validate it and write key files to a directory.

Private key files are written with mode 0600. Key lengths are validated
against spec/credential-format.md before anything is written.
"""
import argparse
import base64
import json
import os
import sys

EXPECTED_SIZES = {
    "ed25519": {"pub": 32, "priv": 64},
    "ml_dsa_65": {"pub": 1952, "priv": 4032},
}


def main():
    p = argparse.ArgumentParser(description="Import a UCII portable credential file.")
    p.add_argument("credential", help="portable credential JSON from export.py / restore.py")
    p.add_argument("-d", "--dir", required=True, help="directory to write key files into")
    a = p.parse_args()

    with open(a.credential) as f:
        cred = json.load(f)

    if cred.get("format") != "ucii-portable-credential":
        sys.exit("Not a UCII portable credential (bad format field).")
    if cred.get("format_version") != 1:
        sys.exit(f"Unsupported credential version: {cred.get('format_version')}")

    identity_id = cred["identity_id"]
    os.makedirs(a.dir, exist_ok=True)

    written = []
    for section, suffix in (("public_keys", "pub"), ("private_keys", "priv")):
        for alg, b64 in cred[section].items():
            raw = base64.b64decode(b64)
            expect = EXPECTED_SIZES.get(alg, {}).get(suffix)
            if expect and len(raw) != expect:
                sys.exit(f"Bad key length for {alg}.{suffix}: got {len(raw)}, expected {expect}")
            path = os.path.join(a.dir, f"{identity_id}.{alg}.{suffix}")
            with open(path, "wb") as f:
                f.write(raw)
            if suffix == "priv":
                os.chmod(path, 0o600)
            written.append(path)

    print(f"Imported identity {identity_id} -> {a.dir}")
    for w in written:
        print(f"  {w}")


if __name__ == "__main__":
    main()
