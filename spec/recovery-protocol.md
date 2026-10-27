# Social recovery protocol

Version: 2

## What changed from v1 (summary)

- Threshold is FIXED: exactly 3 guardians, threshold always 2.
  `threshold_m` is REMOVED from the registration request — any
  client sending it is speaking v1, not v2.
- The standard story is 2 of your 3 DEVICES, not 3 humans
  vouching. Human guardians remain mechanically possible (any
  identity can be a guardian) but are not the story.
- Completion is an EXPLICIT trigger (POST /recover/complete),
  not an automatic timer. There is no background job.
- Objection is an EXPLICIT endpoint (POST /recover/object),
  UNSIGNED in phase 1 (Brad's decision Oct 26). Signed objection
  is phase 1b.
- Notification in phase 1 is a PANEL alert + audit record only.
  Email is phase 1b (no email transport exists in the codebase).
- Rate limit is max 3 (open PENDING + trailing-24h attempts).
  There is NO exponential backoff — v1's backoff claim was never
  implemented and is removed.

---

## Purpose

Lose a device — or everything — and 2 of your 3 devices bring
your identity back on new keys. Same identity, new keys. The
standard case is self-guardianship across your own devices (phone
identity, laptop identity, paper/hardware backup identity), not
coordinating with other people. Human guardians work the same way
mechanically, but the story is devices.

## Roles

- **Owner**: the human whose identity is being recovered. Holds a
  UCII identity, has lost key material on one device (or all of
  it).
- **Guardian**: a UCII identity registered before any loss. In
  the standard case, the owner's own other devices. Registered
  *before* any loss.
- **Server**: the UCII operator's box. Verifies attestations,
  enforces the delay, revokes old keys, issues the new
  credential.

## Step 1 — Guardian registration (before loss)

The owner registers exactly 3 guardians:

```
POST /v1/identity/guardians
{
  "identity_id": "<uuid>",
  "guardians": ["<guardian-uuid>", "<guardian-uuid>", "<guardian-uuid>"],
  "nonce": "<random>",
  "signature": "<owner's ML-DSA-65 signature over canonical JSON>"
}
```

Rules:

- Must be signed by the identity's **current** key. Only the owner
  sets guardians.
- Exactly 3 guardians, all distinct, none equal to the owner.
- Every guardian must hold a valid, ACTIVE UCII identity.
- The guardian list can only be changed by the owner signing a
  new registration. It **cannot** be changed while a recovery is
  pending — that's the attack this rule kills.
- There is no threshold parameter. The threshold is always 2.

## Step 2 — Recovery request

The owner generates a fresh keypair locally, then collects
attestations from 2 guardians. Each guardian signs this exact JSON
(canonical form: keys sorted, no whitespace):

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

Signature: the guardian's ML-DSA-65 signature over the canonical
JSON, base64-encoded.

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

The server checks, in enforced order:

1. The identity exists, is ACTIVE, and a guardian set is on
   record.
2. No recovery is already PENDING for this identity.
3. Rate limit: open (PENDING) + trailing-24h attempts < 3.
4. New keys carry both halves (ed25519 + ml_dsa_65), base64.
5. At least 2 attestations, each from a **registered** guardian,
   no duplicates.
6. Per attestation: shape, type `ucii-recovery-attestation`,
   identity match, guardian match, same new keys as the request,
   freshness (within 7 days, +5 min skew), unseen nonce,
   signature verifies against that guardian's ACTIVE ML-DSA
   credential.

Then: the attempt opens PENDING_DELAY, completing 24 hours after
request, and a panel notification row is written (channel
`panel`, unacknowledged). The delay is the last line of defense
against a compromised guardian set — the real owner gets a day to
shout, by checking the panel (phase 1 has no email).

## Step 4 — Objection and completion

Objection (unsigned, phase 1):

```
POST /v1/identity/recover/object
{ "attempt_id": "<uuid>", "reason": "<optional>" }
```

Sets the attempt REJECTED. Anyone knowing the identity ID and
attempt ID can object — the bound is documented, not hidden:
the attack is targeted, not opportunistic; damage is bounded by
resubmission and the 3-attempts/day cap; the authenticated kill
(control secret) remains the hard backstop. Signed objection is
phase 1b.

Completion (explicit trigger, no background job):

```
POST /v1/identity/recover/complete
{ "attempt_id": "<uuid>" }
```

Requires PENDING_DELAY + now >= completes_at + identity ACTIVE.
On completion:

- ALL ACTIVE credentials of the identity are REVOKED (reason
  `guardian_recovery`). If the "loss" was actually theft, the
  stolen keys are dead on arrival.
- A new keypair is issued for the same `identity_id`: one ML-DSA
  signing row + one DEVICE_KEY row (ed25519), both ACTIVE, with
  lineage to the corresponding old rows.
- Note the deliberate divergence from the operator control-secret
  recovery path, which marks old ACTIVE credentials REPLACED:
  guardian completion marks them REVOKED, per this spec.

Status (panel read):

```
GET /v1/identity/{identity_id}/recovery
```

Returns attempts (newest first) + notifications. This is the
phase-1 notification surface: the panel shows it, nothing pushes
it.

## Threat model (plain language)

| Attack | Defense |
|---|---|
| Attacker adds themselves as guardian, then "recovers" your identity | Guardians can only be set by the owner's own signature, before loss |
| 2 guardians collude to steal the identity | 24-hour delay + panel notification gives the real owner time to object |
| Stolen old keys used after recovery | Old keys REVOKED the moment recovery completes |
| Replay of an old attestation | Nonces tracked server-side across attempts, 7-day freshness window |
| Brute-forcing recovery attempts | Max 3 open/trailing-24h attempts per identity |
| Griefing via unsigned objection | Targeted only (needs identity ID + attempt ID); owner resubmits; kill backstop |

## Deliberately out of v2

- Signed objection (phase 1b).
- Email notification transport (phase 1b).
- Solo long-delay no-guardian recovery path (phase 2).
- Automated rotation + expiry (phase 2).
- Hardware binding, TPM / Secure Enclave / StrongBox (phase 3,
  gated on a real customer).
- Guardian signing UX beyond the vault client (the client build
  is vault/recover.py).
- Dead-man's switch / inactivity-triggered recovery. Out on
  purpose: too easy to get wrong, too catastrophic when wrong.
