# Encrypted backup format

Version: 1

## Purpose

The portable credential, locked with a passphrase only the owner knows. Safe to store anywhere — printed QR codes, a USB stick, a cloud drive. Without the passphrase it's a brick.

## Crypto choices (v1)

- **KDF: scrypt** — N=2^15, r=8, p=1, 16-byte random salt, 32-byte output. Chosen because it's in Python's standard library: zero extra dependencies. Argon2id is the documented upgrade path.
- **Cipher: AES-256-GCM** — 12-byte random nonce, no associated data.

Deliberate v1 call: the post-quantum story lives in the identity signatures, not the backup envelope. A passphrase-encrypted backup is auditable today; hybrid wrapping can come later without changing the format version contract.

## Format

JSON, UTF-8. Ciphertext and binary fields are base64-encoded.

```json
{
  "format": "ucii-encrypted-backup",
  "format_version": 1,
  "kdf": "scrypt",
  "kdf_params": {
    "n": 32768,
    "r": 8,
    "p": 1,
    "salt": "<base64, 16 bytes>"
  },
  "cipher": "aes-256-gcm",
  "nonce": "<base64, 12 bytes>",
  "ciphertext": "<base64>"
}
```

The `ciphertext` decrypts to the exact bytes of the portable credential JSON file.

## Rules

- Passphrase minimum: 12 characters. Enforced by the tool, not just documented.
- Wrong passphrase: AES-GCM authentication fails. The tool reports "wrong passphrase or corrupted backup" — it must never distinguish the two (don't leak which one it was).
- Readers must verify `format` and `format_version` before running the KDF.
