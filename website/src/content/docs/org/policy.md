---
title: Policy
description: The rules member devices follow, platform attestation, and the audit log.
---

The policy is part of the signed governance, so the server cannot weaken it.
Only owners change it:

```sh
printf '%s\n' "$PIN" | symbolon device org policy ~/.symbolon KEY VALUE
```

| Key | Value | Devices then |
|---|---|---|
| `min_pin_len` | 4 to 32 (default 4) | refuse to join, and refuse every change, with a shorter PIN until it is changed (`device pin`) |
| `password_rules` | e.g. `min=12,upper,digit,symbol`, or `none` | refuse to save a password or secret into a shared folder that breaks the rules |
| `allow_offline_copy` | `yes` / `no` | keep, or forget, their copies of group folders |
| `max_offline_days` | 0 (no limit) to 3650 | read a shared folder from their copy for at most that many days after last reaching the relay |
| `allow_duress` | `yes` / `no` | offer, or not, the duress choice for group folders |
| `allow_biometric` | `yes` / `no` | recorded in the policy |
| `require_attestation` | `tpm` / `none` | see below |

Policy reaches the organization's folders and the PIN. It never reaches a
person's own vault or passkeys.

## Attestation

With `require_attestation tpm`, the relay serves group folders, the audit
log and the administrators' objects only to devices whose key is proven to
live in a TPM:

1. The device sends its evidence (`symbolon device org attest`): its TPM's
   endorsement-key certificate, the chain above it and the revocation lists,
   fetched from the addresses in the certificates, and its attestation key.
2. An administrator's sync answers with a credential challenge for that TPM.
3. The device runs `org attest` again: its TPM activates the credential and
   certifies the device key.
4. The next sync verifies it all with Resid's TPM verifier, against the TPM
   makers' roots pinned in Resid, and adds the device to the attested list.

The check is strict: every certificate in the chain needs a current
revocation list, and a chain without one is refused, never accepted. A TPM
whose maker publishes no list for its intermediate cannot be attested until
it does. An owner's device cannot turn the requirement on before it is
attested itself.

## Audit

Every member device signs the events it causes, chained in order per device:
people and groups changed, policy, invites, shared-folder changes (a folder's
version and item count; item names stay sealed), recovery steps, console
approvals. A gap or a fork in a device's chain shows that events were
dropped or altered.

```sh
symbolon device org audit ~/.symbolon      # TIME LOG SEQ ACTION OBJECT DETAIL-HEX ok|broken
```

### Export to a SIEM

```sh
symbolon device org export ~/.symbolon                                   # JSON lines to stdout
symbolon device org export ~/.symbolon --https https://siem.example/ingest --token TOKEN
symbolon device org export ~/.symbolon --syslog siem.example:6514 --ca ca.pem   # RFC 5425
```

Each line is verified on the exporting device first and says so:
`{"time", "org", "log", "seq", "action", "object", "detail", "verified", "problem"}`.
