# Social recovery protocol

Version: 1

## Purpose

Lose everything — credential file, backup, passphrase — and your trusted circle vouches you back into existence. M-of-N guardians sign attestations; the server issues a fresh credential for the same identity ID. Same identity, new keys.

## Roles

- **Owner**: the human whose identity is being recovered. Holds a UCII identity, has lost all key material.
- **Guardian**: someone the owner trusts, holding their own UCII identity. Registered *before* any loss.
- **Server**: the UCII operator's box. Verifies attestations, enforces the delay, revokes old keys, issues the new credential.

## Step 1 — Guardian registration (before loss)

The owner registers N guardians and a threshold M (e.g. 3-of-5):

```
POST /v1/identity/guardians
{
  "identity_id": "<uuid>",
  "guardians": ["<guardian-uuid>", ...],
  "threshold_m": 3,
  "nonce": "<random>",
  "signature": "<owner's ML-DSA-65 signature over canonical JSON>"
}
```

Rules:

- Must be signed by the identity's **current** key. Only the owner sets guardians.
- Every guardian must hold a valid UCII identity of their own.
- The guardian list can only be changed by the owner signing a new registration. It **cannot** be changed during recovery — that's the attack this rule kills.

## Step 2 — Recovery request

The owner generates a fresh keypair locally, then collects attestations. Each guardian signs this exact JSON (canonical form: keys sorted, no whitespace):

```json
{
  "type": "ucii-recovery-attestation",
  "identity_id": "<owner-uuid>",
  "new_public_keys": {
    "ed25519": "<base64>",
    "ml_dsa_65": "<base64>"
  },
  "guardian_id": "<guardian-uuid>",
  "nonce": "<random>",
  "created_at": "<iso8601>"
}
```

Signature: the guardian's ML-DSA-65 signature over the canonical JSON, base64-encoded.

The owner (or anyone helping them) submits:

```
POST /v1/identity/recover
{
  "identity_id": "<uuid>",
  "new_public_keys": { "ed25519": "<base64>", "ml_dsa_65": "<base64>" },
  "attestations": [
    { "guardian_id": "<uuid>", "attestation": { ... }, "signature": "<base64>" },
    ...
  ]
}
```

## Step 3 — Server verification

The server checks, in order:

1. The identity exists and a guardian list is on record.
2. At least M attestations, each from a **registered** guardian, no duplicates.
3. Every attestation signature verifies against that guardian's current public key.
4. All attestations reference the **same** new public keys.
5. Attestation timestamps are fresh (within 7 days) and nonces have never been seen.
6. No recovery is already in progress for this identity.

Then: start a **24-hour delay timer** and notify the owner's old contact methods (email on file, etc.). The delay is the last line of defense against a compromised guardian set — the real owner gets a day to shout.

After the delay with no owner objection: revoke the old keys, issue a new credential bound to the new public keys, same identity ID.

## Step 4 — Completion

- Old keypair revoked immediately and permanently. If the "loss" was actually theft, the stolen keys are dead on arrival.
- New credential issued for the same `identity_id`.
- Rate limits: max 3 open or recent recovery attempts per identity, exponential backoff on failures.

## Threat model (plain language)

| Attack | Defense |
|---|---|
| Attacker adds themselves as guardian, then "recovers" your identity | Guardians can only be set by the owner's own signature, before loss |
| M guardians collude to steal the identity | 24-hour delay + notification gives the real owner time to object |
| Stolen old keys used after recovery | Old keys revoked the moment recovery completes |
| Replay of an old attestation | Nonces tracked server-side, 7-day freshness window |
| Brute-forcing recovery attempts | Rate limits + exponential backoff |

## Deliberately out of v1

- Guardian signing UX (how a guardian actually produces their signature — that's a client build).
- Dead-man's switch / inactivity-triggered recovery. Out on purpose: too easy to get wrong, too catastrophic when wrong.
