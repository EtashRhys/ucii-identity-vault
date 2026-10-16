# Portable credential format

Version: 1

## Purpose

A UCII identity as a file the owner holds. Moving to a new device = importing this file. No old device involved. This is the answer to the "new phone anomaly": the phone was never the identity.

## Format

JSON, UTF-8. All key material is base64-encoded raw bytes.

```json
{
  "format": "ucii-portable-credential",
  "format_version": 1,
  "identity_id": "782ccfdc-b6db-4680-a9ab-b9448e3b9030",
  "public_keys": {
    "ed25519": "<base64>",
    "ml_dsa_65": "<base64>"
  },
  "private_keys": {
    "ed25519": "<base64>",
    "ml_dsa_65": "<base64>"
  },
  "issued_at": "2026-10-16T19:44:00+00:00"
}
```

## Field rules

- `format` must be exactly `ucii-portable-credential`. Anything else: reject the file.
- `format_version`: readers must reject versions they don't understand. Never silently accept a newer version.
- `identity_id`: the permanent UCII identity. Never changes — not across devices, not across recovery. This is the whole point.
- Key sizes (validated on import):
  - ed25519: public 32 bytes, private 64 bytes
  - ML-DSA-65: public 1952 bytes, private 4032 bytes

## Security notes

- This file **is** the identity. Copying it copies you.
- Never email it unencrypted. Never commit it to git. The encrypted backup format (`backup-format.md`) exists for a reason.
- Import must write private key files with mode 0600.
