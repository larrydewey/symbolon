# Symbolon: A Credential Agent

**Draft 0 -- 2026-10-12. Confidential (see NOTICE.md).**

## Abstract

This document specifies Symbolon, a credential agent. The agent replaces the
password manager's model -- a store of replayable shared secrets -- with a
set of keys held in hardware where possible, governed by an append-only,
self-certifying identity log. It specifies the identity log, device
enrollment, origin-bound authentication, hardware-bound sessions, minimal
disclosure of attributes, a legacy password vault built against a malicious
server, sharing, recovery without key escrow, and the agent's attestation of
itself. It closes with implementation requirements for the reference
implementation in Resid, where several of the security goals become
compile-time obligations.

## Table of contents

1. Introduction
2. Conventions and terminology
3. Threat model
4. Security goals
5. Architecture
6. Cryptographic suite
7. Data model
8. The identity log
9. Local unlock
10. Device enrollment and removal
11. Origin authentication
12. Session binding
13. Attribute presentation
14. The legacy vault
15. Sharing
16. Synchronization
17. Recovery
18. Agent attestation
19. Browser and application integration
20. Implementation requirements (Resid)
21. Security considerations
22. Privacy considerations
23. Open issues

---

## 1. Introduction

### 1.1 What is being replaced

A password is a shared secret that the holder presents and the verifier
compares. Anyone who learns it can replay it: a phishing page, a breached
verifier, malware on the endpoint. A password manager makes many such
secrets bearable but concentrates them, and the published record shows the
concentration failing in three places:

- **The server.** Under a malicious-server model, 12 attacks were shown
  against Bitwarden, 7 against LastPass, 6 against Dashlane and (in the
  ePrint version) 6 against 1Password, most of them recovering passwords.
  The root causes named were unauthenticated public keys, key escrow for
  recovery and SSO, integrity per field rather than per vault, insufficient
  key separation, missing binding between data and metadata, and
  downgrades through backwards compatibility.
- **The page.** DOM-based extension clickjacking made 10 of 11 password
  manager extensions fill credentials into invisible forms on a click.
- **The process.** KeePass 2.x before 2.54 left the master password
  recoverable from memory dumps, swap and hibernation files (CVE-2023-32784).

Beyond the password itself, the session token that a login produces is now
the asset most often stolen (infostealers), and account recovery is the
path that reintroduces phishable secrets after a phishing-resistant login.

### 1.2 Approach

Symbolon makes five changes:

1. **Keys, not secrets.** Every credential the agent holds is a private key
   that signs a challenge bound to the relying party's origin. Nothing the
   agent sends can be replayed elsewhere.
2. **Identity as a log.** The principal's identity is an append-only,
   hash-chained, signed log of key events with pre-committed rotation keys.
   Every key the agent or any peer relies on is reached from a verified log
   head, never from a server's say-so.
3. **Sessions bound to hardware.** Tokens the agent obtains are
   sender-constrained to non-exportable keys.
4. **Facts, not identities.** Where a service needs an attribute, the agent
   presents that attribute and no more.
5. **Recovery without escrow.** Lost devices are replaced by devices,
   recovery keys or guardians acting through the log, under a delay that
   any surviving device can veto. No party holds a key that decrypts the
   principal's data unless the principal opted into it.

### 1.3 Scope

In scope: the agent, its identity log, its storage format, its protocols
with relying parties, peers and an untrusted synchronization service, and
its integration with browsers and applications.

Out of scope: relying-party account recovery, issuance of attribute
credentials, the design of WebAuthn, DBSC or DPoP themselves (the agent
uses them), and defense against an adversary who controls the operating
system kernel at the moment of use (Section 3.3 bounds what such an
adversary gains).

---

## 2. Conventions and terminology

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD
NOT, RECOMMENDED, MAY and OPTIONAL are to be interpreted as described in
BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in capitals.

Data structures are given in CDDL (RFC 8610) and encoded in deterministic
CBOR (RFC 8949 §4.2.1). Signatures are COSE (RFC 9052). `H` is SHA-256.
`||` is concatenation. `HKDF(ikm, salt, info, L)` is HKDF-SHA256 (RFC 5869).

| Term | Meaning |
|---|---|
| Principal | The person whose credentials the agent holds. |
| Agent | A Symbolon instance on one device. |
| Device key (DK) | A per-device signing key, non-exportable where the platform allows. |
| Device encryption key (DEK) | A per-device HPKE key pair, sealed to the device. |
| Identity log (IL) | The principal's append-only sequence of signed key events (Section 8). |
| Log head | The latest verified event of an IL and its digest. |
| Roster | The set of device keys the current log head authorizes. |
| Relying party (RP) | A service the principal authenticates to. |
| Origin credential | A WebAuthn credential scoped to one RP ID. |
| Vault | Encrypted storage for legacy passwords, synced passkeys and notes (Section 14). |
| Vault head | The signed commitment to a vault's entire contents at one version. |
| Guardian | Another principal, identified by their IL, who may approve recovery. |
| Recovery kit | An offline recovery key whose digest the IL pre-commits. |
| Witness | An independent service that co-signs log heads it has seen. |
| Sync service | Untrusted storage and relay for logs, vaults and messages. |

---

## 3. Threat model

### 3.1 Adversaries

- **A1 Malicious sync service.** Reads, drops, reorders, replays, forks
  and fabricates anything it stores or relays; substitutes keys; serves
  different views to different devices and principals.
- **A2 Phisher.** Controls web origins and content the principal visits,
  including invisible elements, overlays and cross-origin frames.
- **A3 Network adversary.** Full control of the network outside TLS sessions
  the agent verifies.
- **A4 Endpoint malware without kernel control.** Runs as the principal's
  user or another user; reads files, other processes' memory where
  permitted, the clipboard and swap; exfiltrates cookies and tokens.
- **A5 Device thief.** Holds a powered-off or locked device.
- **A6 Malicious guardian minority.** Fewer than the guardian threshold.
- **A7 Malicious relying party or verifier.** Tries to link the principal
  across services or learn more attributes than requested.

### 3.2 Trust assumptions

- The device's hardware root (TPM 2.0, Secure Enclave, StrongBox or
  equivalent) keeps non-exportable keys non-exportable.
- The agent binary is the one its provenance record names (Section 18).
- At least one of: a surviving enrolled device, the recovery kit, or a
  guardian threshold remains available to the principal.

### 3.3 Explicit non-goals

- An adversary with kernel control on an unlocked device can use any key
  the agent can use while it controls the device. Symbolon limits this to
  *use during control*: non-exportable keys cannot be taken away, sessions
  bound to them die with the control, and the log records what was done.
- Denial of service by the sync service is detected (Section 16.4) but not
  prevented.

---

## 4. Security goals

Each goal names the attack class it answers. Section 21 maps goals to
mechanisms.

- **G1 Origin binding.** No credential the agent emits verifies at an
  origin other than the one it was created for. (A2)
- **G2 No replayable secret leaves the agent.** Nothing transmitted to an
  RP or the sync service suffices, alone, to authenticate again. (A2, A3, A4)
- **G3 Authenticated keys.** Every public key the agent encrypts to or
  trusts is reached from a verified log head through a chain of
  signatures, never accepted from the sync service directly. (A1:
  "lack of key authentication")
- **G4 Whole-vault integrity.** A device accepts a vault state only if the
  whole state matches a vault head signed by a rostered device, at a
  version no lower than the highest it has seen. Moving, swapping,
  deleting, injecting or reverting any item or field is detected. (A1:
  "integrity per field", cut-and-paste, rollback)
- **G5 Key separation.** Every ciphertext is under a key derived for
  exactly one (vault, item, field, version), with all of them in the
  associated data. (A1: "lack of key separation", data/metadata binding)
- **G6 No downgrade.** Cryptographic parameters (suite, KDF parameters) are
  fixed by the format version and covered by signatures; the agent has no
  code path that accepts a weaker setting from storage. (A1: backwards
  compatibility)
- **G7 No escrow.** No party other than the principal's own devices, its
  recovery kit and (only if the principal opts in) a guardian threshold
  can obtain any key that decrypts the principal's data. (A1: key escrow)
- **G8 Bound sessions.** Tokens the agent obtains are sender-constrained to
  non-exportable keys where the platform allows. (A4)
- **G9 Consent outside the page.** No credential is released into a web
  page without a user gesture in agent-owned interface that displays the
  origin as the browser reports it. (A2: clickjacking)
- **G10 Secret hygiene.** Secrets are never written to disk unencrypted,
  are kept out of swap and core dumps, are wiped on release, and are
  processed without secret-dependent branches or memory addresses. (A4, A5)
- **G11 Recoverable without escrow, resistant to takeover.** Recovery
  succeeds through any of Section 17's paths and cannot complete while any
  rostered device objects within the delay. (A1, A6)
- **G12 Minimal disclosure.** A presentation reveals only the requested
  attributes; where the credential format allows, presentations are
  unlinkable across verifiers. (A7)
- **G13 Fork detection.** Two devices that ever compare log or vault heads,
  directly or through a witness, detect a forked view. (A1)

---

## 5. Architecture

### 5.1 Components

```
 +-----------------------------  device  ------------------------------+
 |                                                                     |
 |  browser ── extension (no secrets) ──┐                              |
 |                                      │ native messaging             |
 |  apps / CLI ─────────────────────────┤                              |
 |                                      ▼                              |
 |   +-------------------------- agent ----------------------------+   |
 |   | bridge     | consent UI | core (pure)  | hw     | store | net |   |
 |   | (streams)  | (display)  | log, vault,  | (TPM)  | (fs)  |(TLS)|   |
 |   |            |            | policy, keys |        |       |     |   |
 |   +-----------------------------------------------------------+   |
 +---------------------------------------------------------------------+
                │                                   │
                ▼                                   ▼
        relying parties                  sync service (untrusted),
                                         witnesses, peers' logs
```

### 5.2 Component authority

Each component MUST be confined to the authority listed; Section 20 makes
this a compile-time obligation in the reference implementation.

| Component | Authority | Holds secrets |
|---|---|---|
| core | none (pure) | yes, as typed secrets |
| hw | device (TPM / secure element) | non-exportable keys stay in hardware |
| store | filesystem, agent directory only | ciphertext only |
| net | network | ciphertext and public data only |
| consent UI | display / terminal | the single item being released |
| bridge | its standard streams | the single item being released |
| extension | browser APIs | the single item being released, transiently |

### 5.3 Credential profiles

Each origin credential is created in one of two profiles, chosen per RP:

- **Bound** (default). The key is generated in the device's hardware and
  never leaves it. Each rostered device registers its own credential with
  the RP. Loss of all devices loses the credential; RP-level recovery
  applies.
- **Synced.** The key is generated by the agent and stored in the vault,
  encrypted (Section 14). Restorable by vault recovery. Weaker: the key
  exists in agent memory during use.

---

## 6. Cryptographic suite

Format version 1 defines exactly one suite. There is no negotiation and
no fallback (G6). A future suite is a new format version, and migration
is an explicit, signed log event (Section 8.4).

| Function | Suite 1 |
|---|---|
| Signatures (DK, recovery, events) | ECDSA P-256 with SHA-256 (COSE ES256), deterministic nonces (RFC 6979) for software keys |
| Hash | SHA-256 |
| KDF | HKDF-SHA256 |
| AEAD | AES-256-GCM, 96-bit nonce from the per-field derivation (Section 14.3) |
| Public-key encryption | HPKE (RFC 9180) DHKEM(P-256, HKDF-SHA256), HKDF-SHA256, AES-256-GCM, **mode_auth** |
| Password stretching (local only) | Argon2id (RFC 9106), m = 256 MiB, t = 3, p = 1, 16-byte salt |
| Random | the kernel's CSPRNG (getrandom), optionally mixed with the hardware RNG |

P-256 is chosen because TPM 2.0 and mobile secure elements support it for
non-exportable keys.

---

## 7. Data model

```cddl
digest      = bstr .size 32
pubkey      = COSE_Key                     ; EC2, P-256
suite       = 1
log-id      = digest                       ; H(inception event bytes)
device-id   = digest                       ; H(device public key)

roster-entry = {
  1 => device-id,
  2 => pubkey,                             ; DK
  3 => pubkey,                             ; DEK (HPKE)
  4 => tstr,                               ; human label
  5 => attestation-ref / null,             ; Section 18
}

policy = {
  1 => uint,                               ; threshold of DKs for authority events
  2 => uint,                               ; recovery delay, seconds (>= 86400)
  3 => [* log-id],                         ; guardians
  4 => uint,                               ; guardian threshold
  5 => [* witness-ref],                    ; witnesses
}

witness-ref    = { 1 => tstr, 2 => pubkey } ; URL, key
attestation-ref = { 1 => tstr, 2 => digest } ; media type, H(evidence)
```

---

## 8. The identity log

### 8.1 Structure

The identity log is a sequence of events `E0, E1, ...`. `E0` is the
inception event; the log's identifier is `H(E0)`.

```cddl
event = COSE_Sign                          ; one signature per signer
event-payload = {
  1 => log-id / null,                      ; null only in E0
  2 => uint,                               ; sequence number n
  3 => digest / null,                      ; H(E(n-1)), null only in E0
  4 => suite,
  5 => event-body,
  6 => [+ digest],                         ; next recovery-key digests (pre-rotation)
  7 => uint,                               ; advisory time, seconds
}

event-body = inception / add-device / remove-device / set-policy /
             rotate-recovery / recover / veto / migrate / revoke-credential

inception        = [0, roster: [+ roster-entry], policy]
add-device       = [1, roster-entry, enroll-transcript: digest]
remove-device    = [2, device-id]
set-policy       = [3, policy]
rotate-recovery  = [4]                     ; reveals nothing; field 6 carries the new digests
recover          = [5, path: uint, new-roster: [+ roster-entry],
                       revealed-recovery-key: pubkey / null,
                       guardian-approvals: [* COSE_Sign1]]
veto             = [6, target-seq: uint]
migrate          = [7, new-suite: uint]
revoke-credential = [8, rp-id: tstr, credential-id: bstr]
```

### 8.2 Signing rules

- **Routine events** (`add-device`, `remove-device`, `revoke-credential`)
  MUST carry signatures from `policy.threshold` distinct rostered DKs, or
  from one DK when the threshold is 1.
- **Authority events** (`set-policy`, `rotate-recovery`, `migrate`) MUST
  carry signatures from `policy.threshold` distinct rostered DKs.
- **Recovery events** (`recover`) follow Section 17; they do not take
  effect until the delay elapses without a `veto`.
- **Veto** MUST be signed by one DK rostered at the recovery event's
  predecessor.
- Field 6 MUST list the digests `H(pubkey)` of the recovery keys that a
  future `recover` may reveal (pre-rotation). A `recover` whose
  `revealed-recovery-key` digest is not in the predecessor's field 6 is
  invalid.

### 8.3 Verification

A verifier holding a log identifier `L` and a sequence of events MUST:

1. Check `H(E0) = L`, `E0.seq = 0`, `E0.prev = null`, `E0` signed by every
   DK in its roster.
2. For each `En`, n > 0: `En.log = L`, `En.seq = n`, `En.prev = H(E(n-1))`,
   `En.suite` equals the suite in force, and the signing rule for its body
   holds against the roster and policy in force at `E(n-1)`.
3. Apply pending `recover` events whose delay has elapsed with no valid
   `veto`; discard vetoed ones.
4. Output the log head: `(L, n, H(En), roster, policy)`.

The verifier MUST refuse, never repair, any log that fails a check.

### 8.4 Monotonicity

Each agent stores the highest log head it has verified for its own and
each peer's log. A log presented with a lower sequence number, or with the
same sequence number and a different digest, is a fork (Section 16.4).

---

## 9. Local unlock

### 9.1 Unlock key

```
pin_stretch = Argon2id(pin, salt_local, m, t, p)                ; Section 6
hw_secret   = TPM2_Unseal(sealed_blob, policy = PolicyAuthValue(pin_stretch)
                                                 [ & PolicyPCR(boot PCRs) ])
unlock_key  = HKDF(hw_secret, salt_local, "symbolon v1 unlock", 32)
```

The TPM's dictionary-attack lockout limits guesses at the PIN. `unlock_key`
decrypts the device's local key store (DEK private part, software DKs,
vault keys).

### 9.2 Without hardware

A device without a TPM or secure element MAY run the agent in the
**unprotected-device profile**: `unlock_key = HKDF(pin_stretch, ...)`.
The agent MUST show this profile in its interface and MUST NOT create
Bound credentials there; RPs requesting hardware-backed attestation learn
of it through Section 18.

### 9.3 The PIN never leaves the device

The PIN, `pin_stretch` and `unlock_key` MUST NOT be sent to any party. No
server-side password exists in Symbolon. (Section 17.5's optional remote
backup uses an oblivious protocol that reveals nothing about the PIN to
the service.)

### 9.4 Locking

On lock, the agent MUST wipe `unlock_key` and every derived key and
plaintext from memory. Auto-lock after inactivity (RECOMMENDED: 15
minutes) and on session lock or suspend.

---

## 10. Device enrollment and removal

### 10.1 Enrollment

A new device N joins through an existing rostered device X:

1. N generates DK_N in hardware and DEK_N, and produces attestation
   evidence binding DK_N to its hardware and its agent build (Section 18),
   with challenge `c` chosen by X.
2. X and N establish a channel through the sync service or locally, and
   authenticate it with a short authentication string (SAS) of at least
   40 bits, displayed on both and compared by the principal, or with a QR
   code carrying `H(DK_N)` scanned by X.
3. X verifies N's evidence against the principal's policy (accepted
   platforms and agent builds).
4. X appends `add-device(N, H(transcript))`, with the signatures the policy
   requires (other devices may need to approve).
5. X wraps the vault keys and the device-shared secrets to DEK_N with HPKE
   mode_auth (sender: DEK_X) and sends them.
6. For each Bound origin credential, N registers its own credential with
   the RP at the next sign-in (Section 11.3).

### 10.2 Removal

`remove-device(D)` removes D from the roster. The agents MUST then rotate
every vault key and shared-collection key D could read (Section 14.6) and
SHOULD revoke D's origin credentials at the RPs that support it.

---

## 11. Origin authentication

### 11.1 Protocol

The agent acts as a WebAuthn authenticator (platform or roaming) and
CTAP 2 authenticator. Origin binding (G1) is WebAuthn's: the client data
the agent signs includes the origin the *browser* reports, and the agent
MUST take the origin only from the browser or operating system, never from
page content.

### 11.2 Bound credentials

For a Bound credential the agent MUST generate the key in hardware (TPM
`TPM2_Create` under the agent's storage key, or the platform's secure
element) and MUST NOT be able to export it.

### 11.3 Multi-device by registration

A Bound credential is per device. On a device's first sign-in to an RP
where another rostered device holds a credential, the agent signs in with
any available factor and registers its own credential. The agent SHOULD
record `(rp-id, credential-id, device-id)` in the vault so the principal
can see and revoke every credential.

### 11.4 Legacy authentication

For RPs without WebAuthn, the agent uses the legacy vault (Section 14)
and the release rules of Section 19.

---

## 12. Session binding

### 12.1 Browser sessions

For browser sessions the agent relies on Device Bound Session Credentials
where the browser implements them, and adds nothing.

### 12.2 Agent-obtained tokens

For OAuth tokens and API sessions the agent obtains on behalf of
applications and command-line tools, the agent MUST use DPoP (RFC 9449)
with a per-RP key generated in hardware, and MUST NOT hand the DPoP
private key to the application. The application asks the agent for a DPoP
proof for each request, over the bridge (Section 19).

### 12.3 Long-lived secrets of other tools

SSH keys and signing keys the agent manages SHOULD be generated in
hardware and used through the agent (an SSH agent protocol endpoint), never
written to disk in the clear.

---

## 13. Attribute presentation

### 13.1 Holding credentials

The agent stores attribute credentials (identity documents, memberships,
age, employment) issued in SD-JWT VC, ISO mdoc, or BBS formats, in the
vault.

### 13.2 Presentation

On a presentation request the agent MUST:

1. Show the verifier's identity as authenticated by its certificate or
   registration, the attributes requested, and the attributes it will
   reveal.
2. Reveal only attributes the principal approves; prefer predicates
   (`age_over_18 = true`) to values when the credential supports them.
3. Bind the presentation to the verifier's nonce and audience.

### 13.3 Unlinkability

With BBS credentials the agent MUST derive a fresh zero-knowledge proof
for each presentation. With SD-JWT or mdoc, whose issuer signature is
constant and therefore linking, the agent SHOULD request single-use
credentials in batches from the issuer and MUST NOT present the same
single-use credential twice. The interface MUST say when a presentation is
linkable.

---

## 14. The legacy vault

The vault holds what cannot be a key: passwords for RPs without WebAuthn,
TOTP seeds, Synced-profile passkeys, attribute credentials and notes.

### 14.1 Keys

```
vault_key  : 32 random bytes per vault, held wrapped to each rostered DEK
item_key   = HKDF(vault_key, vault_id, "symbolon v1 item" || item_id, 32)
field_key  = HKDF(item_key, nil, "symbolon v1 field" || field_name || u64(item_version), 32)
nonce      = HKDF(item_key, nil, "symbolon v1 nonce" || field_name || u64(item_version), 12)
```

Each (item, field, version) has its own key and nonce (G5). An item update
MUST increment `item_version`; a key/nonce pair is therefore never reused.

### 14.2 Items

```cddl
item = {
  1 => bstr .size 16,                      ; item_id, random
  2 => uint,                               ; item_version
  3 => tstr,                               ; kind: "login", "totp", "passkey", "credential", "note"
  4 => { + tstr => bstr },                 ; field_name => ciphertext
}
```

### 14.3 Encryption

```
aad = CBOR([1, vault_id, item_id, item_version, kind, field_name])
ct  = AES-256-GCM(field_key, nonce, plaintext, aad)
```

Field names, kind, item and vault identity and version are all in the
associated data (G5), so a ciphertext moved to another field, item, kind,
version or vault fails to decrypt.

### 14.4 The vault head

```cddl
vault-head = COSE_Sign1 over {
  1 => digest,                             ; vault_id
  2 => uint,                               ; vault_version, strictly increasing
  3 => digest,                             ; Merkle root (below)
  4 => log-id,                             ; owner log
  5 => uint,                               ; owner log sequence the signer was rostered at
  6 => suite,
  7 => argon2-params,                      ; recorded, compared to the suite; never applied from here
}
```

The Merkle root is computed over the items sorted by `item_id`, each leaf
`H(0x00 || item_id || u64(item_version) || H(CBOR(item)))`, interior nodes
`H(0x01 || left || right)` (RFC 9162 style, with domain separation).

A device MUST accept a vault state only if (G4):

1. the head is signed by a DK in the owner's roster at the stated log
   sequence, and that sequence is no later than the device's verified head;
2. `vault_version` is at least the highest it has accepted for this vault;
3. the Merkle root recomputed from the delivered items equals the head's;
4. the suite and the recorded parameters equal format version 1's.

Any failure is a refusal, never a partial load.

### 14.5 Partial sync

A device MAY fetch a subset of items with Merkle inclusion proofs against
an accepted head. It MUST NOT treat absence of an item as deletion without
a head that proves it.

### 14.6 Key rotation

On device removal, membership change or suspected compromise, the agent
MUST generate a new `vault_key`, re-encrypt every item (incrementing
versions), publish a new head and wrap the new key to the current roster
only.

### 14.7 TOTP

TOTP codes (RFC 6238, HMAC-SHA1 by default) are computed inside the core
and released under Section 19's rules; the seed never leaves the core.

---

## 15. Sharing

### 15.1 Shared collections

A shared collection is a vault with its own `vault_id` and `vault_key`,
whose members are principals. Its head's field 4 names the collection's
administering log; membership is a signed list in the head.

### 15.2 Recipient keys (G3)

To add a member P, the agent MUST obtain P's DEKs from P's verified log
head, and MUST additionally either

- check P's log head against the policy's witnesses (Section 16.3), or
- compare a log-head fingerprint with P out of band (displayed as words
  or a QR code).

It MUST NOT accept a recipient key from the sync service on its own.

### 15.3 Wrapping

`vault_key` is wrapped to each member device's DEK with HPKE mode_auth,
sender key the adding device's DEK, `info = "symbolon v1 share" || vault_id
|| member log-id || u64(vault_version)`. Mode_auth authenticates the
sender, so a substituted wrapped key from the server fails to open
(answering the key-substitution class in which an origin-authenticated
ciphertext was wrongly assumed).

### 15.4 Removal

Removing a member MUST rotate the collection key (Section 14.6).

---

## 16. Synchronization

### 16.1 The service is untrusted

The sync service stores and relays: identity logs, vault heads and items,
wrapped keys, enrollment messages and recovery notifications. Every object
it returns is verified as Sections 8, 14 and 15 require. The service
authenticates devices by DK signatures over a fresh challenge; it holds no
password and no verifier derived from one.

### 16.2 Transport

TLS 1.3 with server authentication. Transport security protects metadata
from A3; it carries no weight for G3-G7.

### 16.3 Witnesses

Each agent SHOULD submit its own log head and vault heads to the policy's
witnesses, which co-sign `(log-id, seq, digest)` they have seen and refuse
to co-sign a second digest for the same `(log-id, seq)`. An agent verifying
a peer's log SHOULD require witness co-signatures on the head it uses.

### 16.4 Fork and freeze detection (G13)

- Devices of the same principal MUST exchange their highest verified heads
  whenever they communicate, directly or through the service, and MUST
  alarm on any fork.
- A device that has not seen a newer head from any witness within a
  configured interval SHOULD warn that it may be frozen.

---

## 17. Recovery

### 17.1 Paths

| Path | Who acts | Restores identity | Restores vault |
|---|---|---|---|
| R1 Surviving device | any rostered device | yes (Section 10) | yes |
| R2 Recovery kit | the principal, with the kit | yes | yes |
| R3 Guardians | guardian threshold | yes | only with R3-backup opted in |
| R4 Remote backup | principal's PIN + service | no | yes (optional profile) |

### 17.2 R2: Recovery kit

The recovery kit is a P-256 key pair generated offline at inception and
printed (as words and QR), whose public key digest is in the log's field 6,
and to which the vault keys are wrapped (HPKE base mode; the kit has no
sender). To recover, a new device reveals the kit's public key in a
`recover` event signed by the kit's private key, with a new roster and new
field-6 digests (the kit is single-use). The event takes effect after the
policy's delay unless vetoed.

### 17.3 R3: Guardians

Guardians hold approvals, not secrets. A `recover` event by path R3 MUST
carry COSE_Sign1 approvals over `H(event payload)` from `guardian
threshold` distinct guardians, each verified against that guardian's own
log head. Before approving, a guardian's agent MUST show the requesting
device's attestation summary and require the guardian to confirm out of
band with the principal.

Identity recovery by R3 restores authority over the log and therefore the
ability to re-register Bound credentials. It does not restore the vault
unless the principal opted into **R3-backup**: the vault key split with
Shamir secret sharing at the guardian threshold, each share wrapped to a
guardian's DEK, released by the guardian's agent only after the `recover`
event takes effect. R3-backup reconstructs the key on the new device only.

### 17.4 Delay and veto (G11)

Every `recover` event takes effect only after `policy.delay` (at least 24
hours, RECOMMENDED 72 hours). During the delay every rostered device MUST
notify the principal and MAY append a `veto`. The sync service MUST relay
recovery events to all devices, and witnesses SHOULD co-sign them so a
service that suppresses the notification is detectable.

### 17.5 R4: Remote backup (optional profile)

For principals who accept trusting a service's guess limit, the vault key
may be backed up under the PIN with an oblivious PRF evaluated by
attested enclaves (in the manner of Signal's SVR3), so the service learns
nothing about the PIN and can enforce a guess limit. Before every
request the agent MUST verify the enclaves' attestation evidence against
pinned measurements (Section 18.3). This profile MUST be off by default.

---

## 18. Agent attestation

### 18.1 Evidence

An agent produces evidence consisting of:

- the platform's attestation of the DK (TPM2_Certify by an AK whose EK
  chains to the manufacturer, or the platform's equivalent), and
- the agent build's provenance: the signed record naming the source,
  compiler and runtime hashes of the binary that is running, and a quote
  or measurement that binds the running binary to it where the platform
  measures it.

### 18.2 Uses

- **Within the principal's roster (REQUIRED):** enrollment (Section 10.1)
  and guardian approval (Section 17.3) check the evidence.
- **To relying parties (OPTIONAL, off by default):** in WebAuthn
  attestation for enterprise RPs that require it. Because attestation can
  identify the device, the agent MUST NOT send it to an RP without the
  principal's consent per RP.

### 18.3 Verifying others

When the agent relies on a remote enclave (Section 17.5) or a witness that
claims to run in one, it MUST verify that service's evidence before
sending anything.

---

## 19. Browser and application integration

### 19.1 The extension holds nothing

The browser extension MUST NOT store credentials or keys. It forwards to
the agent over native messaging: the request kind, the top-level origin
and the frame origin as the browser API reports them, and the field
descriptors. It receives at most one item for one fill.

### 19.2 Consent outside the page (G9)

Release of any credential, TOTP code or attribute into a page MUST follow a
user gesture in agent-owned interface outside the page's DOM: a native
window, the browser's own extension popup, or an operating-system prompt,
which displays the origin and, for a frame, the frame origin. The agent
MUST NOT fill on a click inside the page, and MUST NOT fill into a frame
whose origin differs from the credential's origin.

### 19.3 Clipboard

The agent SHOULD avoid the clipboard. Where it uses it, it MUST mark the
content sensitive to the platform where possible and clear it after at most
30 seconds.

### 19.4 Applications

Applications reach the agent through a local socket readable only by the
principal's user, authenticated by the peer's process credentials; the
agent shows which executable asks before releasing anything.

---

## 20. Implementation requirements (Resid)

This section binds the reference implementation. Facts about Resid are as
of the Resid repository on 2026-10-12.

### 20.1 Components as capability partitions

Each component of Section 5.2 MUST be a set of modules whose functions'
`@requires` declarations are exactly the authority listed:

- core: no `@requires`, except `declassify` at the named publication points
  (ciphertext out, signatures out);
- hw: `device`;
- store: `filesystem`;
- net: `network(readonly)`;
- consent UI: `display` or `terminal`;
- bridge: what its standard streams need.

The compiler's E0219 check then proves that the core cannot open a file
or socket and that the network component cannot touch the TPM.

### 20.2 Verified-only types (G3-G6 at compile time)

The following types MUST be opaque outside the module that verifies them,
in the manner of Resid's `Trust`, `Binding` and `Verified(Claims)`:

| Type | Built only by | Required by |
|---|---|---|
| `LogHead` | `il_verify` (Section 8.3) | everything that reads a roster |
| `RecipientKey` | `share_recipient(LogHead, Witnessed \| Fingerprinted)` | `share_wrap` |
| `VaultState` | `vault_accept` (Section 14.4) | every read of an item |
| `FieldKey` | `field_key(VaultKey, item_id, field, version)` | `field_seal`, `field_open` |

A function that encrypts to a key not reached from a `LogHead`, or reads an
item outside an accepted `VaultState`, MUST fail to compile. Each of
Section 4's anti-patterns is thereby a type error rather than a review
finding.

### 20.3 Secrets

- Every key, PIN, plaintext field and TOTP seed MUST be typed
  `Secret(...)` (Resid spec §48) from the moment it enters the core.
- Every core function on secrets MUST have a constant-time case in the
  repository's equivalent of Resid's `tests/ct`, and the coverage gate MUST
  pass.
- The agent runs in Resid's secret mode (wipe on free, no core dumps, no
  same-user ptrace).

### 20.4 What Resid lacks today

Checked against the Resid repository on 2026-10-12. Each is REQUIRED
before the named section can be implemented:

| Missing | Needed by |
|---|---|
| Argon2id (and BLAKE2b) | Section 9 |
| HMAC-SHA1 (SHA-1 exists) | Section 14.7 |
| `mlock` of secret memory | G10 (swap) |
| CTAP 2 over HID (`hidraw`/`uhid` descriptors in `lib/dev/`) | Section 11 roaming |
| TPM key creation and signing with non-exportable keys for DKs | Sections 10, 11.2, 12.2 |
| Oblivious PRF and hash-to-curve | Section 17.5 |
| Pairing-friendly curves and BBS | Section 13.3 |
| A GUI library (planned, not started) | Section 19.2 |
| Targets beyond Linux and Android | platform coverage |

Present and usable: ECDSA P-256 with RFC 6979, HPKE, AES-GCM,
ChaCha20-Poly1305, HKDF, SHA-256, COSE, CBOR, X.509, TLS 1.3 client and
server, the TPM wire format and quote, the attestation verifier, and the
`display` and `terminal` capability families.

---

## 21. Security considerations

### 21.1 Goal-to-mechanism map

| Goal | Mechanism | Section |
|---|---|---|
| G1 | WebAuthn origin in signed client data; origin from browser only | 11 |
| G2 | Keys, not secrets; DPoP; no server-side password | 11, 12, 9.3 |
| G3 | Log-head-reached keys, witnesses or fingerprints, `RecipientKey` type | 8, 15.2, 20.2 |
| G4 | Signed vault head, Merkle root, monotonic version | 14.4 |
| G5 | Per-(item, field, version) keys; full AAD | 14.1, 14.3 |
| G6 | One suite per format version; parameters never read from storage | 6, 14.4 |
| G7 | Wrapping only to rostered DEKs, kit, opt-in guardian shares | 10, 14, 17 |
| G8 | Hardware DPoP keys; DBSC | 12 |
| G9 | Consent outside the DOM | 19.2 |
| G10 | Secret types, ct gate, secret mode, mlock | 20.3 |
| G11 | Pre-rotation, delay, veto, multiple paths | 8.2, 17 |
| G12 | Predicate preference, BBS, single-use batches | 13 |
| G13 | Head exchange, witnesses | 16.3, 16.4 |

### 21.2 Residual risks

- A principal who loses every device and the recovery kit, and has no
  guardians, loses the vault and all Bound credentials. This is the cost of
  G7, and the interface MUST say so at setup.
- Witness collusion with the sync service defeats fork detection for
  peers who never meet.
- The unprotected-device profile depends on PIN strength alone.
- Synced-profile keys exist in agent memory while used.
- R4 trusts the enclaves' vendors and the guess-limit implementation.
- A guardian threshold acting together, and undetected for the whole delay
  by every device, can take over the identity.

---

## 22. Privacy considerations

- The sync service learns the number and sizes of items and when devices
  sync; padding of items to size classes is RECOMMENDED.
- Attestation to RPs is off by default (Section 18.2).
- Log identifiers are stable; RPs never see them (WebAuthn credentials are
  per RP). Guardians and sharing peers do.

---

## 23. Open issues

1. A threshold of DKs as authority vs. any single DK: usability against
   takeover by one stolen, unlocked device.
2. Witness ecosystem: who runs them; whether the IETF key transparency
   work (draft-ietf-keytrans-*) should replace Section 16.3.
3. Whether Bound credentials should be default for consumer RPs, given that
   NIST SP 800-63-4 reportedly accepts synced passkeys at AAL2.
4. Passkey import/export with FIDO CXP/CXF once those specifications are
   final.
5. Formal verification of Sections 8, 14 and 15 (e.g. Tamarin or
   ProVerif models) before any implementation is called secure.
6. Interaction of Section 19.2 with platform autofill services on Android.
