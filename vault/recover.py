#!/usr/bin/env python3
"""UCII guardian recovery client (key custody phase 1).

Subcommands:
  genkeys   — generate a fresh ML-DSA-65 + ed25519 keypair
  register  — owner signs + registers the 2-of-3 guardian set
  attest    — a guardian signs an attestation to new keys
  submit    — submit 2 attestations, open the 24h-delayed attempt
  status    — show recovery attempts + panel notifications
  object    — object to a pending attempt (UNSIGNED, per Brad's
              decision Oct 26; signed objection is phase 1b)
  complete  — complete a delayed attempt (after completes_at)

Key files: secret keys are bytes, base64 in files created 0600.
These files ARE your identity. Anyone holding them is you.
Secrets are never printed.

Canonical JSON (matches the server exactly):
  json.dumps(obj, sort_keys=True, separators=(",", ":"),
             ensure_ascii=False)
"""

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone


def canon(obj):
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def b64(raw):
    return base64.b64encode(raw).decode("ascii")


def read_b64(path):
    with open(path) as f:
        return base64.b64decode(f.read().strip())


def write_secret(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(base64.b64encode(raw))
    print(f"Wrote {path} (0600). This file IS your identity.")


def mldsa():
    try:
        from pq_auth.pqc.signatures import MLDSA  # server checkout
    except ImportError:
        try:
            import oqs
        except ImportError:
            sys.exit("Missing dependency: liboqs-python")
        return _OQSMLDSA(oqs)
    return MLDSA()


class _OQSMLDSA:
    """Minimal ML-DSA-65 wrapper when the server package is absent."""

    def __init__(self, oqs):
        self.oqs = oqs

    def generate_keypair(self):
        with self.oqs.Signature("ML-DSA-65") as s:
            return bytes(s.generate_keypair()), bytes(s.export_secret_key())

    def sign(self, message, secret_key):
        with self.oqs.Signature("ML-DSA-65", secret_key) as s:
            return bytes(s.sign(message))


def call(api_base, method, path, body=None):
    req = urllib.request.Request(
        api_base + path,
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, json.loads(resp.read().decode() or "{}")
    except urllib.error.HTTPError as err:
        raw = err.read().decode()
        try:
            return err.code, json.loads(raw or "{}")
        except json.JSONDecodeError:
            return err.code, {"raw": raw[:300]}


def now_iso():
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def cmd_genkeys(args):
    dsa = mldsa()
    pub, sec = dsa.generate_keypair()
    write_secret(args.mldsa_sec, sec)
    with open(args.mldsa_pub, "w") as f:
        f.write(b64(pub) + "\n")
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        from cryptography.hazmat.primitives import serialization

        key = Ed25519PrivateKey.generate()
        ed_pub = key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        ed_sec = key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    except ImportError:
        sys.exit("Missing dependency: pip install cryptography")
    write_secret(args.ed_sec, ed_sec)
    with open(args.ed_pub, "w") as f:
        f.write(b64(ed_pub) + "\n")
    print("Public keys written (shareable). Secret keys written 0600.")


def cmd_register(args):
    dsa = mldsa()
    payload = {
        "identity_id": args.identity_id,
        "guardians": args.guardians.split(","),
        "nonce": args.nonce,
    }
    sig = dsa.sign(canon(payload), read_b64(args.owner_key))
    status, body = call(args.api_base, "POST", "/v1/identity/guardians",
                        {**payload, "signature": b64(sig)})
    print(f"HTTP {status}")
    print(json.dumps(body, indent=2))
    if status != 200:
        sys.exit(1)


def cmd_attest(args):
    dsa = mldsa()
    with open(args.new_mldsa_pub) as f:
        new_ml = f.read().strip()
    with open(args.new_ed_pub) as f:
        new_ed = f.read().strip()
    att = {
        "type": "ucii-recovery-attestation",
        "identity_id": args.identity_id,
        "new_public_keys": {"ed25519": new_ed, "ml_dsa_65": new_ml},
        "guardian_id": args.guardian_id,
        "nonce": args.nonce,
        "created_at": now_iso(),
    }
    sig = dsa.sign(canon(att), read_b64(args.guardian_key))
    out = {"guardian_id": args.guardian_id, "attestation": att,
           "signature": b64(sig)}
    with open(args.output, "w") as f:
        json.dump(out, f, indent=2)
    print(f"Attestation -> {args.output} (collect 2, then submit)")


def cmd_submit(args):
    with open(args.new_mldsa_pub) as f:
        new_ml = f.read().strip()
    with open(args.new_ed_pub) as f:
        new_ed = f.read().strip()
    attestations = []
    for path in args.attestations:
        with open(path) as f:
            attestations.append(json.load(f))
    status, body = call(
        args.api_base, "POST", "/v1/identity/recover",
        {"identity_id": args.identity_id,
         "new_public_keys": {"ed25519": new_ed, "ml_dsa_65": new_ml},
         "attestations": attestations},
    )
    print(f"HTTP {status}")
    print(json.dumps(body, indent=2))
    if status != 200:
        sys.exit(1)
    print(f"Attempt {body.get('id')} completes after "
          f"{body.get('completes_at')}. Check the panel.")


def cmd_status(args):
    status, body = call(
        args.api_base, "GET",
        f"/v1/identity/{args.identity_id}/recovery")
    print(f"HTTP {status}")
    print(json.dumps(body, indent=2))


def cmd_complete(args):
    status, body = call(args.api_base, "POST",
                        "/v1/identity/recover/complete",
                        {"attempt_id": args.attempt_id})
    print(f"HTTP {status}")
    print(json.dumps(body, indent=2))
    if status != 200:
        sys.exit(1)


def cmd_object(args):
    # Unsigned objection, per Brad's decision Oct 26: the panel and
    # client call object with attempt_id only. Griefing bound (needs
    # identity ID + attempt ID, resubmittable, 3 attempts/day cap) and
    # the authenticated kill backstop are documented in case study 007.
    # Signed objection is a phase 1b follow-up.
    status, body = call(args.api_base, "POST",
                        "/v1/identity/recover/object",
                        {"attempt_id": args.attempt_id,
                         "reason": args.reason})
    print(f"HTTP {status}")
    print(json.dumps(body, indent=2))
    if status != 200:
        sys.exit(1)

def main():
    p = argparse.ArgumentParser(description="UCII guardian recovery client")
    p.add_argument("--api-base", default="https://ucii.sportgen-ai.com")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("genkeys")
    g.add_argument("--mldsa-pub", required=True)
    g.add_argument("--mldsa-sec", required=True)
    g.add_argument("--ed-pub", required=True)
    g.add_argument("--ed-sec", required=True)
    g.set_defaults(fn=cmd_genkeys)

    r = sub.add_parser("register")
    r.add_argument("--identity-id", required=True)
    r.add_argument("--guardians", required=True,
                   help="comma-separated, exactly 3 guardian identity IDs")
    r.add_argument("--owner-key", required=True,
                   help="owner ML-DSA secret key file (base64)")
    r.add_argument("--nonce", required=True)
    r.set_defaults(fn=cmd_register)

    a = sub.add_parser("attest")
    a.add_argument("--identity-id", required=True)
    a.add_argument("--guardian-id", required=True)
    a.add_argument("--guardian-key", required=True,
                   help="guardian ML-DSA secret key file (base64)")
    a.add_argument("--new-mldsa-pub", required=True)
    a.add_argument("--new-ed-pub", required=True)
    a.add_argument("--nonce", required=True)
    a.add_argument("--output", required=True)
    a.set_defaults(fn=cmd_attest)

    s = sub.add_parser("submit")
    s.add_argument("--identity-id", required=True)
    s.add_argument("--new-mldsa-pub", required=True)
    s.add_argument("--new-ed-pub", required=True)
    s.add_argument("--attestations", nargs=2, required=True,
                   help="two attestation JSON files from attest")
    s.set_defaults(fn=cmd_submit)

    t = sub.add_parser("status")
    t.add_argument("--identity-id", required=True)
    t.set_defaults(fn=cmd_status)

    c = sub.add_parser("complete")
    c.add_argument("--attempt-id", required=True)
    c.set_defaults(fn=cmd_complete)

    o = sub.add_parser("object")
    o.add_argument("--attempt-id", required=True)
    o.add_argument("--reason", default=None)
    o.set_defaults(fn=cmd_object)

    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
