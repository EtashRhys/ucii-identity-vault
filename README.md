# ucii-identity-vault

Your UCII identity, owned by you — portable credentials, encrypted backup, M-of-N social recovery. Lose the phone, keep the identity.

## The problem

Actor Corin Nemec got a new phone and got locked out of Instagram and Facebook. The new device couldn't prove it was him without the old device. He called it the "new phone anomaly."

He's not alone. Right now everyone's identity lives inside Apple/Google/Meta's device graph. Lose the phone, lose the proof you're you.

## What this is

Three tools that make your UCII identity survive your phone:

1. **Portable credential** — your identity as a file you own. New phone? Import the file. Done. The phone was never the identity.
2. **Encrypted backup** — that file, locked with a passphrase only you know. Print it, USB-stick it, cloud it. Without the passphrase it's a brick.
3. **Social recovery** — lose everything and your trusted circle vouches you back in. M-of-N guardians sign attestations, the server issues a fresh credential for the same identity. Same identity, new keys.

## What this isn't

This doesn't unlock your Instagram. Meta's a walled garden — they decide what counts as proof, and today UCII isn't on their list. What it does: you never get locked out of anything that accepts UCII, and your identity belongs to you, not your phone.

## Quick start

One dependency:

    pip install cryptography

Export your identity to a portable file:

    python3 vault/export.py --identity-id <your-id> \
        --ed25519-pub  ~/.ucii/keys/ed25519.pub \
        --ed25519-priv ~/.ucii/keys/ed25519.priv \
        --ml-dsa-65-pub  ~/.ucii/keys/ml-dsa-65.pub \
        --ml-dsa-65-priv ~/.ucii/keys/ml-dsa-65.priv \
        -o my-identity.json

Lock it with a passphrase:

    python3 vault/backup.py my-identity.json -o my-identity.backup

New phone? Restore, then import:

    python3 vault/restore.py my-identity.backup -o my-identity.json
    python3 vault/import.py my-identity.json -d ~/.ucii/keys

## The identity

The vault holds a UCII Citizenship identity — $10 CAD one-time for a production human UCII identity. The vault tools are free and open source. The identity is what you buy.

## Layout

- `spec/` — the file formats and the recovery protocol. Read these first.
- `vault/` — the client tools. They only touch files you hand them. They never talk to the UCII server and never touch its database.
- `server/` — reference implementation of the recovery endpoints. The protocol, not the deployment — production runs on the operator's box.

## Security rules

- The portable credential file **is** your identity. Anyone holding it is you. Guard it like a passport.
- The encrypted backup is useless without your passphrase. Lose the passphrase and the backup is a brick. There is no "forgot passphrase" — that's the point.
- Guardians must be registered **before** you lose everything. You can't add guardians during recovery — that's the attack.
- Recovery has a 24-hour delay with notification to your old contact methods. Old keys are revoked the moment recovery completes.
