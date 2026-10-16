"""
Reference implementation of the UCII Identity Vault recovery endpoints.

This is the PROTOCOL, not the deployment. Production runs on the operator's
box against the real UCII identity database. Wire the TODOs to your store,
your ML-DSA-65 verifier, and your notification path.

Endpoints (spec/recovery-protocol.md):
  POST /v1/identity/guardians  - owner registers N guardians + threshold M
  POST /v1/identity/recover    - submit M attestations, start the 24h clock

Security rules enforced here:
  - Guardians only settable by the owner's own signature, before loss.
  - Recovery needs M valid, fresh, non-duplicate attestations from
    REGISTERED guardians, all agreeing on the same new keys.
  - 24-hour delay + owner notification before keys rotate.
  - Old keys revoked on completion. No exceptions.
"""

import base64
import json
import time
import uuid
from datetime import datetime, timedelta, timezone

from flask import Flask, jsonify, request

app = Flask(__name__)

RECOVERY_DELAY = timedelta(hours=24)
ATTESTATION_FRESHNESS = timedelta(days=7)
MAX_ATTEMPTS = 3  # open/recent recovery attempts per identity

# ---------------------------------------------------------------------------
# Storage adapters — TODO: replace with the real UCII identity database.
# ---------------------------------------------------------------------------

_identities = {}   # identity_id -> {"guardians": [...], "threshold_m": int,
                   #                 "contact_email": str, "revoked_keys": [...]}
_nonces_seen = set()
_recoveries = {}   # identity_id -> {"state": "pending"|"done",
                   #                 "new_public_keys": {...}, "deadline": iso,
                   #                 "attempts": int}


def verify_ml_dsa_65(public_key_b64, message: bytes, signature_b64) -> bool:
    """TODO: wire to the real ML-DSA-65 verifier."""
    raise NotImplementedError("wire to UCII crypto")


def notify_owner_old_contacts(identity_id, contact_email):
    """TODO: email/SMS the owner that a recovery is in progress."""
    raise NotImplementedError("wire to notification path")


def revoke_keys(identity_id, old_public_keys):
    """TODO: mark the old keypair revoked in the identity DB."""
    raise NotImplementedError("wire to UCII identity DB")


def issue_credential(identity_id, new_public_keys):
    """TODO: issue the new portable credential for the same identity ID."""
    raise NotImplementedError("wire to UCII issuance")


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


# ---------------------------------------------------------------------------
# POST /v1/identity/guardians
# ---------------------------------------------------------------------------

@app.post("/v1/identity/guardians")
def set_guardians():
    body = request.get_json(force=True)
    identity_id = body["identity_id"]
    guardians = body["guardians"]
    m = body["threshold_m"]

    ident = _identities.get(identity_id)
    if not ident:
        return jsonify(error="unknown identity"), 404
    if not (1 <= m <= len(guardians)):
        return jsonify(error="threshold M must be between 1 and N"), 400
    for g in guardians:
        if g not in _identities:
            return jsonify(error=f"guardian {g} holds no UCII identity"), 400

    # Must be signed by the identity's CURRENT key — only the owner sets guardians.
    signed = {k: body[k] for k in ("identity_id", "guardians", "threshold_m", "nonce")}
    if not verify_ml_dsa_65(ident["current_ml_dsa_65_pub"], canonical(signed),
                            body["signature"]):
        return jsonify(error="bad owner signature"), 403

    ident["guardians"] = guardians
    ident["threshold_m"] = m
    return jsonify(ok=True, guardians=guardians, threshold_m=m)


# ---------------------------------------------------------------------------
# POST /v1/identity/recover
# ---------------------------------------------------------------------------

@app.post("/v1/identity/recover")
def recover():
    body = request.get_json(force=True)
    identity_id = body["identity_id"]
    new_keys = body["new_public_keys"]
    attestations = body["attestations"]

    ident = _identities.get(identity_id)
    if not ident or not ident.get("guardians"):
        return jsonify(error="no guardians registered for this identity"), 404

    rec = _recoveries.get(identity_id, {"attempts": 0})
    if rec.get("state") == "pending":
        return jsonify(error="recovery already in progress"), 409
    if rec["attempts"] >= MAX_ATTEMPTS:
        return jsonify(error="too many recovery attempts"), 429

    m = ident["threshold_m"]
    seen_guardians = set()
    for a in attestations:
        gid = a["guardian_id"]
        if gid in seen_guardians:
            return jsonify(error=f"duplicate attestation from {gid}"), 400
        if gid not in ident["guardians"]:
            return jsonify(error=f"{gid} is not a registered guardian"), 403
        seen_guardians.add(gid)

        att = a["attestation"]
        if att.get("type") != "ucii-recovery-attestation":
            return jsonify(error="bad attestation type"), 400
        if att["identity_id"] != identity_id:
            return jsonify(error="attestation for wrong identity"), 400
        if att["new_public_keys"] != new_keys:
            return jsonify(error="guardians disagree on the new keys"), 400
        if att["nonce"] in _nonces_seen:
            return jsonify(error="replayed attestation"), 400
        created = datetime.fromisoformat(att["created_at"])
        if datetime.now(timezone.utc) - created > ATTESTATION_FRESHNESS:
            return jsonify(error="stale attestation"), 400

        gpub = _identities[gid]["current_ml_dsa_65_pub"]
        if not verify_ml_dsa_65(gpub, canonical(att), a["signature"]):
            return jsonify(error=f"bad guardian signature from {gid}"), 403
        _nonces_seen.add(att["nonce"])

    if len(attestations) < m:
        return jsonify(error=f"need {m} attestations, got {len(attestations)}"), 400

    # All checks passed. Start the 24-hour clock and notify the owner.
    deadline = datetime.now(timezone.utc) + RECOVERY_DELAY
    _recoveries[identity_id] = {
        "state": "pending",
        "new_public_keys": new_keys,
        "deadline": deadline.isoformat(),
        "attempts": rec["attempts"] + 1,
    }
    notify_owner_old_contacts(identity_id, ident.get("contact_email"))

    # TODO: a scheduler finalizes after the deadline: if no owner objection,
    # revoke_keys(identity_id, old_keys); issue_credential(identity_id, new_keys);
    # mark state "done".
    return jsonify(ok=True, state="pending",
                   completes_after=deadline.isoformat(),
                   note="owner has 24h to object via old contact methods")


if __name__ == "__main__":
    app.run(port=8471)
