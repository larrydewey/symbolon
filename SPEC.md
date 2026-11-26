# Symbolon: A Credential Agent for Continuity of Control

**Draft 2 -- 2026-10-12 (red-team revision, see Appendix A).**

## Abstract

Symbolon is a credential agent. It holds a person's keys, not their
passwords, and it is built around one idea: identity on the internet is
*continuity of control* -- the ability to show, over time, that the party
acting now is the party that acted before -- and the hard part of
authentication is not the moment of login but the life of a credential:
holding it without a single point of failure, revoking it everywhere,
recovering it without escrow, resisting coercion, and controlling what a
verifier does with what it receives.

The agent speaks ordinary passkeys (WebAuthn/CTAP 2) to relying parties.
Behind each passkey is a **threshold key**: the private key never exists in
one place; any quorum of the principal's devices, recovery kit and an
optional cosigner signs together, producing a standard signature. Losing a
device loses nothing; a stolen device signs nothing alone; re-sharing
without a device revokes it at every relying party at once, with no change
on their side. A self-certifying **identity log** governs the quorum, and
the parties to it enforce the log's policy: revocation, recovery delays
with veto, and a duress mode that cannot be turned into lasting control.
Around this core the specification defines continuity proofs for relying
parties that want them, minimal and verifier-constrained disclosure of
attributes, hardware-bound sessions, a legacy password vault built
against a malicious server, and automatic rotation of every credential,
inside the agent and at relying parties, by a two-phase protocol that
never leaves the principal locked out.

## Table of contents

1. Introduction
2. Conventions and terminology
3. Threat model
4. Security goals
5. Architecture
6. Cryptographic suite
7. Data model
8. The identity log
9. Local unlock and duress
10. Threshold passkeys
11. Quorum membership: enrollment, revocation, refresh
12. The cosigner
13. Recovery
14. Duress
15. Continuity proofs
16. Session binding
17. Attribute presentation and verifier-constrained release
18. The legacy vault
19. Sharing
20. Synchronization
21. Agent attestation
22. Platform integration
23. Implementation requirements (Resid)
24. Security considerations
25. Privacy considerations
26. Credential rotation
27. Formal verification
28. Open issues
29. Organizations

---

## 1. Introduction

### 1.1 What passkeys solved and what they left

Passkeys (WebAuthn) replace the replayable shared secret with an
origin-bound key pair, which ends phishing and verifier breaches as ways
to steal a credential. They standardize the moment of login. They leave
the credential's life to the provider, and the two kinds of provider each
keep a single point of failure:

- **Device-bound passkeys**: the device. Lose it and the credential is gone.
- **Synced passkeys** (platform keychains, password managers): the
  provider account. The private key becomes copyable software under the
  provider's encryption; losing the account loses every passkey, and
  compromising it exposes every one. Published work names synced-passkey
  providers as a single point of failure, and the 2026 "Pass-ta-key"
  research obtained, from malware on one machine, the master key for all
  passkeys synced through one provider.

Relying parties bind an account to individual keys and have no notion of
"the same principal, another key"; a W3C proposal to attach device keys to
synced credentials (`devicePubKey`, then `supplementalPubKeys`, 2023) did
not, as far as we found, ship. Revoking a lost device's passkeys still
means visiting every relying party. Account recovery, studied in under 3%
of authentication research since 2012 (PoPETs 2025), remains the path that
reintroduces phishable secrets.

Passwords persist in a long tail of relying parties, and their managers
have their own record: twelve attacks on Bitwarden, seven on LastPass, six
on Dashlane and six on 1Password under a malicious server (USENIX Security
2026); DOM-based clickjacking of 10 of 11 autofill extensions (DEF CON 33);
master passwords recoverable from memory dumps (CVE-2023-32784).

### 1.2 Approach

1. **No single point of failure.** Every passkey is a threshold key over a
   quorum of independent parties (Section 10).
2. **Identity as a log.** An append-only, self-certifying log of key
   events with pre-committed recovery keys defines who the quorum is and
   what policy it enforces (Section 8).
3. **Revocation is re-sharing.** Removing a party re-randomizes every
   share; the removed party's share stops working at every relying party,
   with no relying-party involvement (Section 11).
4. **Recovery through the quorum, under delay and veto**, never through a
   party that can act alone (Section 13).
5. **Duress cannot become durable control** (Section 14).
6. **Release only to verifiers that are proven unable to keep or forward
   the data**, where the verifier can prove it (Section 17.4).
7. **Every key reached from a verified log; every vault state verified as
   a whole; no downgrade; no escrow** (Sections 18-20).

### 1.3 Scope

In scope: the agent, its identity log, the threshold passkey protocol
between quorum parties, the cosigner, recovery, duress, continuity proofs,
storage formats, synchronization through an untrusted service, and
integration with browsers and operating systems.

Out of scope: changes to WebAuthn itself (relying parties need none for
Sections 10-14), issuance of attribute credentials, and defense against an
adversary who controls a device's kernel *and* enough other parties to
meet the threshold.

---

## 2. Conventions and terminology

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD
NOT, RECOMMENDED, MAY and OPTIONAL are to be interpreted as described in
BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in capitals.

Data structures are CDDL (RFC 8610) encoded as deterministic CBOR
(RFC 8949 §4.2.1); signatures are COSE (RFC 9052). `H` is SHA-256, `||`
concatenation, `HKDF(ikm, salt, info, L)` HKDF-SHA256 (RFC 5869), `G` the
P-256 base point, `q` its order.

| Term | Meaning |
|---|---|
| Principal | The person whose credentials the agent holds. |
| Agent | A Symbolon instance on one device. |
| Party | A holder of a share of the principal's threshold key: a device, the recovery kit, the cosigner, or (opt-in) a guardian. |
| Quorum | The set of parties and the threshold `t` the log defines. |
| Device key (DK) | A per-device signing key, non-exportable where the platform allows; authenticates a device to other parties. Never a passkey share. |
| Device encryption key (DEK) | A per-device HPKE key pair, sealed to the device. |
| Root key | The principal's threshold ECDSA key `x` with public key `X = xG`; never assembled. |
| Share | A party's Shamir share `x_i` of `x` at the current epoch. |
| Epoch | A version of the shares; each refresh or re-share starts a new epoch. |
| Chain code | A 32-byte secret known to device parties and the kit, used to derive per-credential tweaks. |
| Credential | A passkey registered with one relying party; public key `X + τG` for a per-credential tweak `τ`. |
| Identity log (IL) | The principal's append-only sequence of signed key events (Section 8). |
| Log head | The latest verified event of an IL and its digest. |
| Cosigner | A party that holds a share, is always reachable, enforces the log's policy, and never learns which relying party a signature is for (Section 12). |
| Recovery kit | An offline party: a share, the chain code and a recovery signing key, printed or on a hardware token. |
| Guardian | Another principal, identified by their IL, who approves recovery and may hold a share (opt-in). |
| Witness | An independent service that co-signs log heads it has seen. |
| Sync service | Untrusted storage and relay. |
| Relying party (RP) | A service the principal authenticates to. |

---

## 3. Threat model

### 3.1 Adversaries

- **A1 Malicious sync service.** Reads, drops, reorders, replays, forks
  and fabricates what it stores or relays; substitutes keys; equivocates.
- **A2 Phisher.** Controls origins and page content the principal visits.
- **A3 Network adversary.** Outside the TLS sessions the agent verifies.
- **A4 Endpoint malware without kernel control** on one or more devices.
- **A5 Endpoint malware with kernel control** on fewer than `t` parties.
- **A6 Device thief** holding a locked or powered-off device.
- **A7 Malicious cosigner.** Holds one share and sees every signing
  request's timing and digest.
- **A8 Malicious guardian minority.**
- **A9 Coercer.** Physically compels the principal to unlock a device and
  act, for a bounded time.
- **A10 Malicious relying party or verifier.** Tries to link the principal
  across services, learn more than requested, or keep what it receives.

### 3.2 Trust assumptions

- Fewer than `t` parties are compromised at once, counting the cosigner.
- Device hardware (TPM 2.0, Secure Enclave, StrongBox) keeps
  non-exportable keys non-exportable and enforces its dictionary-attack
  lockout.
- The agent binary is the one its provenance record names (Section 21).
- The threshold ECDSA protocol (Section 6.2) is secure as proven, and its
  implementation is correct.

### 3.3 Non-goals

- An adversary controlling `t` parties controls the principal's
  credentials. The default quorum makes that require two independent
  compromises.
- An adversary with kernel control on an unlocked device can request
  signatures through that device while it has control; with the cosigner,
  each request is logged and subject to policy (Section 12.3), and the
  device's share is revoked by the next re-share.
- Denial of service by the sync service or the cosigner is detected, not
  prevented; the quorum is sized so that one unavailable party does not
  block signing (Section 10.2).

---

## 4. Security goals

- **G1 Origin binding.** No assertion verifies at an origin other than the
  credential's. (A2)
- **G2 No replayable secret leaves the agent.** (A2, A3, A4)
- **G3 No single point of failure.** No single party, device, account or
  service can sign alone, and the loss of any single party loses no
  credential. (A4, A6, A7)
- **G4 Revocation everywhere.** Removing a party makes its share useless
  for every credential at every RP, with no RP action, within one re-share.
- **G5 Authenticated keys.** Every key the agent trusts or encrypts to is
  reached from a verified log head; none is accepted from a service on its
  own. (A1)
- **G6 Whole-vault integrity** for the legacy vault: moving, swapping,
  deleting, injecting or rolling back anything is detected. (A1)
- **G7 Key separation and data/metadata binding.** (A1)
- **G8 No downgrade.** Parameters are fixed by format version and signed.
  (A1)
- **G9 No escrow.** No party can obtain the root key or any data key on
  its own; guardian shares are opt-in and below threshold individually.
  One exception, opt-in per organization and visible to its members: k
  administrators together may open a member's work folder after a delay
  (Section 29.8), never their own vault.
- **G10 Recovery resistant to takeover.** Every recovery completes only
  after a delay during which any surviving device can veto. (A1, A8)
- **G11 Duress containment.** Under A9, the coercer cannot enroll a party,
  export a credential, change the quorum or recovery, or prevent the
  duress record, during the coercion or after it. (A9)
- **G12 Cosigner blindness.** The cosigner learns no RP identity, no
  credential public key and no message content. (A7)
- **G13 Bound sessions.** Tokens the agent obtains are sender-constrained.
  (A4)
- **G14 Consent outside the page.** (A2)
- **G15 Secret hygiene.** Shares and secrets are typed secret, processed
  in constant time, wiped on release, kept out of dumps and swap. (A4, A6)
- **G16 Minimal, verifier-constrained disclosure.** Presentations reveal
  only requested attributes, are unlinkable where the format allows, and
  are released only to verifiers meeting the principal's handling policy.
  (A10)
- **G17 Fork detection.** (A1)
- **G18 Rotation without the principal.** Every secret the agent holds,
  inside the agent and at relying parties, is rotated by the agent when
  rotation is due, without the principal's involvement except where a
  relying party demands a factor the agent cannot supply; no rotation can
  leave the principal without a working credential. (A1, A4, A6)
- **G19 Per-item containment.** An item the principal marks protected is
  opened only with `t` parties of the quorum, as a passkey signs: no single
  device, unlocked or not, opens protected items faster than the
  cosigner's limit, and an opening is recorded where the other devices see
  it. (A4, A6)

---

## 5. Architecture

### 5.1 Parties and components

```
            relying parties (unchanged WebAuthn)
                     ▲ standard ECDSA assertion
                     │
 phone (share) ◀────▶ laptop (share) ◀────▶ cosigner (share, blind)
      ▲                    ▲                      ▲
      └──── sync service (untrusted relay) ───────┘
                     ▲
            recovery kit (share, offline)      witnesses (log heads)
```

On each device:

| Component | Authority | Holds secrets |
|---|---|---|
| core | none (pure) | shares, chain code, vault keys, as typed secrets |
| hw | device (TPM / secure element) | DK, DEK, sealing key; never released |
| store | filesystem, agent directory only | ciphertext only |
| net | network | ciphertext, protocol messages, public data |
| consent UI | display / terminal | the single item being released |
| bridge | its standard streams / OS credential-provider IPC | the single item being released |

### 5.2 Credential profiles

| Profile | Key | Use |
|---|---|---|
| **Threshold** (default) | Tweaked threshold key (Section 10) | All RPs. AAL2-class. |
| **Bound** | Non-exportable hardware key on one device, one credential per device | RPs requiring hardware attestation of a non-exportable key (AAL3-class). |
| **Synced** | Software key in the vault | Only for import (Section 22.3) and RPs that refuse the other two. Discouraged. |

---

## 6. Cryptographic suite

Format version 1 fixes one suite. There is no negotiation (G8); a new
suite is a new format version adopted by a signed `migrate` event.

### 6.1 Primitives

| Function | Suite 1 |
|---|---|
| Passkey signatures | ECDSA P-256 / SHA-256 (COSE ES256), produced by the threshold protocol |
| Device and log signatures | ECDSA P-256 (ES256); RFC 6979 nonces for software keys |
| Hash, KDF | SHA-256, HKDF-SHA256 |
| AEAD | AES-256-GCM |
| Public-key encryption | HPKE (RFC 9180) DHKEM(P-256), HKDF-SHA256, AES-256-GCM; mode_auth between parties |
| Local stretching | Argon2id (RFC 9106), m = 256 MiB, t = 3, p = 1 (the reference agent currently uses m = 19 MiB, t = 2, OWASP's minimum, until its Argon2id is fast enough; each device records its parameters) |
| Continuity tokens | Publicly verifiable blind RSA tokens (Privacy Pass, RFC 9578 type 2) |
| Random | getrandom, optionally mixed with the hardware RNG |

### 6.2 Threshold ECDSA

The threshold protocol MUST:

- support any `t`-of-`n` with `n <= 8`, distributed key generation with
  no trusted dealer, signing by any `t` parties, proactive refresh, and
  re-sharing to a new set of parties and threshold with the same public
  key;
- be proven secure against a malicious, adaptive minority with abort,
  and identify a misbehaving party on abort;
- accept an additive public tweak applied by one designated party
  (Section 10.3) without the other parties learning it;
- carry every zero-knowledge proof its security proof requires; omitting
  or weakening a proof for speed is forbidden;
- deliver the final signature only to the initiating device. No other
  party may receive `s`, or values from which it can complete `(m, r, s)`:
  ECDSA public-key recovery from a complete signature would give the
  cosigner the credential's public key and let it link every use of that
  credential (Section 12.2);
- on an abort that identifies a party, the honest parties MUST NOT run
  another session with it until a refresh that excludes it; on repeated
  aborts that identify no one, they MUST stop and alert, since selective
  aborts can leak share material in some protocols.

**Decision (2026-10-14): the CGGMP21 line** (Canetti, Gennaro, Goldfeder,
Makriyannis, Peled, ePrint 2021/060): Paillier-based, with identifiable
abort and proactive refresh, run over P-256. The oblivious-transfer-based
DKLs line was the alternative; CGGMP was chosen by the maintainer. The
protocol needs, per party, a Paillier key whose modulus is a product of two
safe primes and Pedersen parameters, and every proof of the paper:
Paillier-Blum modulus (mod), Pedersen parameters (prm), no small factors
(fac), Paillier encryption in range (enc), affine operation with group
commitment (aff-g), discrete-log consistency (log*), and decryption (dec).
The implementation plan and its verification are in `PLAN-CGGMP.md`.
Published attacks on
deployed threshold ECDSA libraries came from omitted or weakened proofs and
parameter checks; the implementation requirements in Section 23 exist
because of them.

---

## 7. Data model

```cddl
digest       = bstr .size 32
pubkey       = COSE_Key                      ; EC2 P-256
suite        = 1
log-id       = digest
party-id     = digest                        ; H(party's authentication key)

party = {
  1 => party-id,
  2 => uint,                                 ; kind: 0 device, 1 kit, 2 cosigner, 3 guardian
  3 => pubkey,                               ; authentication key (DK, kit key, cosigner key, guardian's DK)
  4 => pubkey,                               ; HPKE key for share transport
  5 => tstr,                                 ; label
  6 => attestation-ref / null,
}

quorum = {
  1 => [+ party],
  2 => uint,                                 ; t
  3 => pubkey,                               ; root public key X
  4 => uint,                                 ; epoch
  5 => digest,                               ; H(epoch transcript)
  ? 6 => [+ pubkey],                         ; Feldman commitments C_0..C_{t-1} of the vault OPRF key (18.10.1)
}

policy = {
  1 => uint,                                 ; device signatures needed for authority events
  2 => uint,                                 ; recovery delay, seconds (>= 86400)
  3 => [* log-id], 4 => uint,                ; guardians, guardian approval threshold
  5 => [* witness-ref],
  6 => uint,                                 ; duress window, seconds
  7 => cosigner-policy / null,
}

cosigner-policy = {
  1 => uint,                                 ; max signatures per device per hour
  2 => bool,                                 ; reserved (draft 1; kit rule now unconditional, 10.6)
  ? 3 => uint,                               ; max protected-item evaluations per device per hour (18.10.4; default 60)
}

witness-ref     = { 1 => tstr, 2 => pubkey }
attestation-ref = { 1 => tstr, 2 => digest }
```

---

## 8. The identity log

### 8.1 Structure

```cddl
event = COSE_Sign
event-payload = {
  1 => log-id / null,                        ; null only in E0
  2 => uint,                                 ; sequence n
  3 => digest / null,                        ; H(E(n-1))
  4 => suite,
  5 => event-body,
  6 => [+ digest],                           ; next recovery-key digests (pre-rotation)
  7 => uint,                                 ; advisory time
}

event-body =
    [0, quorum, policy]                      ; inception
  / [1, party, enroll-transcript: digest]    ; propose-party (effective at reshare)
  / [2, party-id]                            ; remove-party (effective at reshare)
  / [3, quorum]                              ; reshare: new parties, t, epoch; same X
  / [4, policy]                              ; set-policy
  / [5]                                      ; rotate-recovery (field 6 changes)
  / [6, recover-body]                        ; recover
  / [7, target-seq: uint]                    ; veto
  / [8] / [9]                               ; reserved (draft 1 duress events; never used, A-05)
  / [10, new-suite: uint]                    ; migrate
  / [11, party-id, hpke-key: pubkey]         ; party-key: a device's new share-transport key

recover-body = [
  path: uint,                                ; 1 kit, 2 guardians
  new-parties: [+ party],
  revealed-recovery-key: pubkey / null,
  guardian-approvals: [* COSE_Sign1],
]
```

### 8.2 Signing rules

- `propose-party`, `remove-party`, `set-policy`, `rotate-recovery`,
  `migrate`: signatures from `policy[1]` distinct devices of the current
  quorum. `policy[1]` MUST be at least 2 whenever the quorum holds two or
  more devices. An event signed by fewer devices than that (for example by
  the only device a principal still has) is **delayed**: it takes effect
  only after the recovery delay, during which every other device is
  notified and may veto, exactly as for `recover` (A-04).
- A `set-policy` that weakens recovery protection (shorter delay, fewer
  guardians, lower guardian threshold, fewer witnesses) is always delayed.
- `reshare`: signatures from every party that took part in the re-share
  (Section 11.3), at least `t` of the old quorum.
- `recover`: Section 13. `veto`: Section 13.4.
- `party-key`: a signature by the authentication key (DK) of the party it
  names, which MUST be a device of the current quorum that is not
  removed; the key MUST be a P-256 point other than the party's current
  `hpke_key`. It takes effect at once (no delay, no other device's
  signature) and replaces that party's field 4 in the quorum; the epoch
  does not change. It moves where others wrap to the device, not who
  signs, recovers or holds a share, and whoever holds the device's DK and
  profile already reads what the old key opened; another device cannot
  move it (that would redirect the device's wraps). A device uses it to
  retire a transport key someone else may hold (Section 9.2).
- Field 6 MUST hold the digests of the recovery keys a future `recover`
  may reveal; a revealed key whose digest is not in the predecessor's field
  6 is invalid.

### 8.3 Verification

Given `L` and events, a verifier MUST check `H(E0) = L`; sequence,
predecessor digest, suite and signing rule of every event against the
state in force before it; apply `recover` events whose delay has passed
without a valid `veto`; and output `(L, n, H(En), quorum, policy)`. Any
failure is a refusal; the verifier never repairs a log.

Delays are measured from an event's **witness time**: the median of the
times in the co-signatures of the policy's witnesses, which MUST number at
least a majority of them. Field 7 is advisory and never used for a delay
(A-07).

Signatures and co-signatures are not covered by an event's digest, so
anyone can add entries to a stored event. A verifier therefore refuses an
event that carries more signature entries than parties that could sign it
(the quorum's parties, plus those of the quorum a `reshare` or `recover`
names, plus one for a kit's recovery key; for `E0`, its quorum's parties
plus one), or more co-signatures than the policy names witnesses, and it
tries only the first entry naming each party and the first co-signature
under each witness key. A party marked removed (`remove-party`, until the
next `reshare` or `recover`) no longer counts as a signer of an event's
signing rule, and a party already removed cannot be removed again.

### 8.4 Monotonicity

Each agent and the cosigner store the highest head they have verified per
log. A lower sequence, or the same sequence with another digest, is a fork
(Section 20.4).

An agent also keeps the events it has verified (`logcache/`). To verify a
log again it asks the relay only for the events after those it keeps, and
verifies the whole log, kept and new events alike, as above: the copy
saves round trips, never checks. A relay that serves fewer events than the
copy holds cannot roll the log back. If the kept and new events do not
verify together, the agent fetches the whole log again and keeps that copy
only if it holds every kept event, the same signed bytes at the same
sequence, and verifies; a log that is shorter than the copy or differs
from it is a fork or a rollback and is refused. The cosigner acts on a log
(a kit release, a signature, a re-share, a duress beacon or end) only when
its head is not below the highest head it has recorded. While the rest of
the log is fetched, the agent asks
the witnesses that the kept log names for the current witness time, all at
once. It uses their answer only if the verified log still names exactly
those witnesses; otherwise it asks the log's witnesses again.

---

## 9. Local unlock and duress

### 9.1 Unlock

```
pin_stretch = Argon2id(pin, salt_local, m, t, p)
hw_secret   = TPM2_Unseal(blob, PolicyAuthValue(pin_stretch) [& PolicyPCR(boot PCRs)])
unlock_key  = HKDF(hw_secret, salt_local, "symbolon v1 unlock", 32)
```

`unlock_key` decrypts the device's share, chain code, vault keys and DEK.
The TPM's lockout limits PIN guesses. A TPM holds one Symbolon device: its
device key and unlock keys sit at fixed persistent handles, so a second
`device new` on the same TPM is refused rather than replacing them, and
`device forget` removes only keys whose device key is the one its
configuration names. The DK MUST be usable only after
local unlock (a TPM policy bound to `pin_stretch`, or the platform's
user-verification gate), so that a thief holding a locked device can
neither sign log events, veto, nor request co-signatures (A-04). The
optional PCR term MUST use `PolicyAuthorize` over signed policies, never
raw PCR values: a firmware or kernel update must not make the blob
unsealable. A blob that does fail to unseal is recovered through another
device or the kit (Section 13), never by weakening the seal (A-11). The PIN and everything derived from
it MUST NOT leave the device. A device without a TPM or secure element MAY
run the **unprotected-device profile** (`unlock_key` from `pin_stretch`
alone), which the interface MUST show.

On Android the hardware is the Keystore, which the app reaches and the
agent (a separate process) does not; the app serves it to the agent on
loopback behind a per-start token (the **Keystore profile**). Two
non-exportable HMAC-SHA256 keys, in StrongBox where present and the TEE
otherwise, take the TPM's place: `hw_secret = HMAC(K_a, pin_stretch ||
salt_local)` (`K_b` for the duress blob), and the DK is a Keystore P-256
key. On a phone with a secure lock screen (Android 11+) all three are
usable only within 30 seconds of a biometric or lock-screen check of the
person (the platform's user-verification gate A-04 allows); when a key
refuses for want of one, the app asks for it and retries, so long
operations (an inception) ask again rather than fail. Code running as
the app on an unlocked phone therefore cannot try PINs, or use the DK,
without the person. Without a secure lock screen the keys are usable
whenever the phone is unlocked, and the interface says so. The Keystore
keeps no count of wrong PINs itself; the per-use check stands in for the
TPM's lockout.

The PIN MAY be kept on the phone for biometric unlock: encrypted under a
Keystore AES key that the same check opens and that a new biometric
enrollment destroys (the PIN is then typed again). It never leaves the
phone (Section 9.1).

### 9.2 Duress PIN

The principal MAY set a duress PIN at setup. It is sealed exactly like the
real PIN, to a second blob, and unlocks the **duress profile** (Section 14).
The two blobs MUST be indistinguishable in size, location pattern and
unseal cost, so that inspection of the device does not reveal that a
duress PIN exists. A device without a duress PIN stores a second blob of
random content, so the pair is always present.

The duress blob holds the device's share, the duress DK sub-key, the duress
vault key, and the per-credential tweaks `τ` of the duress subset only --
**never the chain code**. Without `cc` the duress profile cannot derive the
tweak of any other credential, and so cannot sign for it even with the
cosigner's help (A-06). The real profile keeps the duress blob current
(new shares at each epoch, new subset tweaks) by encrypting updates to a
duress HPKE public key whose private half is sealed under the duress PIN:
it can write the duress blob without being able to read it. A device
without a duress PIN rewrites its random second blob on the same schedule,
so the pattern of writes does not reveal whether a duress profile exists
(A-21).

The duress profile has a share-transport (HPKE) key of its own: a random
32-byte seed in the profile (the field the device's share would take),
whose public key the real profile registers with the cosigner beside the
duress sub-key (`duress.pub`, 65 + 65 bytes; a device without a duress
PIN registers keys no one holds). It MUST NOT hold the device's own
transport key, nor anything it can be derived from: that key opens every
folder-key wrap (Section 19), kit half (Section 10.6) and enrolment or
re-share envelope addressed to the device, so whoever is given the duress
PIN would read every shared folder (D-4).

The device's transport key is `HPKE-DeriveKeyPair(HKDF(DEK, "symbolon v2
device hpke", 32))` (suite 16,1,2), from a label the duress profile never
had. Devices made before 2026-11 used `"symbolon v1 device hpke"` and put
that same seed in the duress profile. On such a device every command
reminds the principal, on standard error (and `device status` with a
`security-update due` line), to run `device security-update DIR` (the
PIN, then the duress PIN or an empty line), which under the PIN only:

1. re-seals the duress profile with a fresh transport seed (everything
   else in it unchanged; same blob size) and registers its key with the
   cosigner first, so the old profile works until the new one is in
   place; without a duress PIN, the second blob, the slot, `dshare` and
   the registered keys become decoys as on a device made without one;
2. publishes a `party-key` event (Section 8.1) naming the v2 key, signed
   by the DK, and records it in the device's configuration;
3. makes every collection's wraps again (Section 19.2).

The reminder depends only on whether the device directory holds the file
`security-update` (written by `device new` and at the end of the update),
never on the PIN entered, so it reads the same under the PIN, the duress
PIN or none: it tells a coercer only that the device predates the update,
which every such device shows, with or without a duress PIN. Under the
duress PIN `device security-update` fails as any change does under duress
(Section 14.3). Residual risk: a copy of the old duress blob taken before
the update still opens with the duress PIN and holds the v1 key, which
opens what was addressed to v1 before it was replaced (wraps not yet made
again, envelopes the relay still keeps); nothing made after the update.

### 9.3 Lock

On lock, auto-lock (RECOMMENDED 15 minutes idle), session lock or suspend,
the agent MUST wipe `unlock_key`, the share and every derived secret.

### 9.4 Security keys as a second factor

A principal can require a FIDO2 security key (a YubiKey or any CTAP 2.1
key with `hmac-secret` and PIN/UV auth protocol 2) to be present and
touched, besides the PIN, before a device opens its profiles
(`device key add|list|remove`).

- **Enrollment.** The key makes a non-resident ES256 credential for the
  relying-party label `symbolon.unlock` (one touch), then gives its
  `hmac-secret` output O for a 32-byte salt the device chose (a second
  touch). The salt is the same for every key of a device; O differs per
  credential.
- **Sealing.** With the first key, the device draws a random 32-byte wrap
  key W and seals `blob_a` and `blob_b` (Section 9.1) again under W with
  AES-256-GCM (`blob_a.k`, `blob_b.k`); the plain files are emptied. Each
  enrolled key keeps W sealed under HKDF(O) with AES-256-GCM in
  `security-keys`, beside its credential ID and public key, so a backup
  key is a second entry. The list is written before the profiles are
  sealed, so an interruption cannot leave profiles no entry opens.
- **Opening.** The device asks the present key for its `hmac-secret`
  output (getAssertion with user presence, the salt encrypted under the
  protocol-2 shared secret) for each enrolled credential until one is
  held. It checks the assertion's signature with that credential's public
  key and the relying party, and unseals W. Without a key, without a touch,
  or with a wrong signature, nothing opens; the PIN still goes through
  Section 9.1 as before, and the TPM's or Keystore's limits on PIN
  attempts are unchanged. Both profiles are under W, so the duress PIN
  needs the key too: a coerced principal hands over the key with the PIN,
  and the duress profile behaves as in Section 9.2.
- **Removal** needs the PIN and any enrolled key. Removing the last key
  unseals the profiles and returns the device to the PIN alone.
- **Transport.** USB keys over CTAPHID, through Resid's isolated device
  host (`lib/dev/fido.resid`): the host writes only to a hidraw node whose
  report descriptor declares the FIDO usage page, and waits up to 45 s for
  a touch. `SYMBOLON_FIDO_SOCKET` names a Unix socket speaking
  length-prefixed CTAP2 messages instead (tests, bridges).

A security key adds a factor to one device; it does not hold a share and
is not a quorum party (Section 10). It cannot run the threshold protocol,
and its own credentials cannot be exported.

---

## 10. Threshold passkeys

### 10.1 The root key

At inception the initial parties run distributed key generation for the
root key `x`, obtaining shares `x_i` and the public key `X`. The device
parties and the kit also generate, jointly, the 32-byte chain code `cc`
(each contributes randomness; `cc = H(contributions)`), transported to
each between parties with HPKE mode_auth. The cosigner never receives `cc`.

### 10.2 Default quorum

| Parties | `t` | Properties |
|---|---|---|
| phone, laptop, cosigner, recovery kit | 2 | Two devices, or a device and the cosigner, sign. One lost device: the rest sign. One stolen device: needs the cosigner, which applies policy. The kit cannot sign with a device or with the cosigner until a recovery takes effect (Section 10.6). All devices lost: kit, then cosigner, after the recovery delay (Section 13). |

Principals without a cosigner use `t = 2` over their devices and kit and
accept that signing needs two of their own devices; in that configuration
the kit and any one device can sign without delay, and the interface MUST
say so and recommend a kit passphrase (Section 10.6).

### 10.3 Per-credential keys

For each credential the agent draws a random 16-byte `nonce` and computes

```
τ   = HKDF(cc, nil, "symbolon v1 tweak" || rp_id || nonce, 48) mod q
P   = X + τG                                  ; the credential's public key
tag = HMAC-SHA256(k_cid, "symbolon v1 cid" || rp_id || nonce)[0..16]   ; k_cid = HKDF(cc, nil, "symbolon v1 cid", 32)
cid = nonce || tag                            ; credential ID, 32 bytes
```

On every assertion the device recomputes `tag` from the **request's** RP
ID (as the browser or OS reports it) and refuses the credential ID if it
does not match, so a relying party cannot replay another relying party's
credential ID to obtain a signature under that party's key (A-12). The
credential ID is opaque to everyone but the device parties. Registration
returns `P` with attestation format `none`.

The tweak `τ` MUST stay unpredictable to every party without `cc`.
ECDSA under additively related keys has known related-key pitfalls when an
adversary can predict or choose the tweak; the construction relies on `τ`
being a pseudorandom function output under `cc`, and its proof is an open
item (Sections 27.3 C-01 and 28, A-10).

In signing, the designated device party (the initiator) applies `τ`
inside the protocol; no other party learns `τ`, `τG` or `P`. Moving the
designated party's public share by `τG`, the obvious construction, would
hand every co-signer `τG` and so `P`, a per-credential linking handle
(Section 12.2). Instead (2026-10-29), every share and public share stays
untweaked, and in presigning the designated party sends a Paillier
encryption `T = Enc(τ)` and runs one more MtA with each other signer on
that signer's `K_j`, proven with the aff-p proof against `T` (no group
element). Each signer adds its MtA output to its `χ` share, so the `χ`
shares sum to `k(x + τ)`. The `S` points, whose sum is `P`, the signature
shares, and the abort-2 openings (which would let a co-signer solve for
`τG`) go to the designated party only, and only it checks `Σ S = P` and
names a culprit. This is Symbolon's addition to CGGMP21, not part of the
paper; it needs its own review (C-01). Because the tweak
is additive and unhardened, **a credential's private key, if ever
assembled, together with `cc`, would reveal `x`.** Therefore:

- a Threshold credential's private key MUST NOT be assembled, exported or
  transferred, including by credential exchange (Section 22.3);
- `cc` is a secret of the same rank as a share.

### 10.4 Signing an assertion

1. The browser or OS passes the request to the agent; the agent shows the
   origin (Section 22.2) and obtains the principal's gesture.
2. The agent forms `authenticatorData` and computes
   `m = SHA-256(authenticatorData || clientDataHash)`.
3. The agent opens a signing session with `t - 1` other available parties,
   preferring the principal's other devices when they are reachable and
   the cosigner otherwise, sending each only `m`, the epoch, a fresh
   32-byte session identifier and a request over all three signed by its
   DK. Parties refuse a session identifier they have seen (A-16).
4. The parties run the threshold protocol; the designated party applies
   `τ`. The result is an ordinary ECDSA signature under `P`.
5. The agent verifies the signature under `P` before returning it.

Relying parties see a standard ES256 assertion. The sign count is 0
(permitted for authenticators without counters). Flags are truthful:
BE = 1 and BS = 1 (the credential survives the loss of a device); UV = 1
only if the PIN or biometric was verified in this ceremony; UP = 1 only
after the gesture of step 1 (A-08).

### 10.5 Availability

If fewer than `t` parties are reachable, signing fails with a clear
message. It never falls back to a weaker credential or to a single party.

### 10.6 Offline parties: the kit and guardians

An offline party cannot take part in refreshes, which would otherwise
leave its share in a dead epoch within 30 days (A-03). It therefore holds
only static keys: a recovery signing key and an HPKE key. Its
current-epoch material is computed by the online parties at every DKG,
refresh and re-share, encrypted to its HPKE key (base mode, `info` binding
log-id, epoch and party-id), committed in the `reshare` transcript, and
stored by the sync service. The offline party decrypts the latest copy
when it acts.

**With a cosigner in the quorum,** the kit's material is split so that
the kit can never act without a recovery having taken effect (A-02):

- the kit's share is `x_K = a + b`; the chain code and the vault recovery
  key are encrypted under `k_K = k_a XOR k_b`;
- `a` and `k_a` are wrapped to the kit's HPKE key; `b` and `k_b` are wrapped
  to the cosigner's key;
- the cosigner releases `b` and `k_b` only after a path-1 `recover` has
  taken effect (Section 13.4), and only to the new device named in that
  event, encrypted to that device's HPKE key. The new device combines them
  with the kit's `a`, `k_a` to obtain `x_K`, `cc` and the vault recovery key,
  then signs and re-shares with the cosigner. The cosigner never holds `a`,
  so it never holds two shares.

Consequences: kit + device = a device share and half of another, which
cannot sign; kit + cosigner before recovery = the same; cosigner alone =
its share and `b`, which cannot sign. A stolen kit gives nothing without a
recovery that every surviving device is told about and can veto.

**Without a cosigner,** the kit's material is wrapped to the kit alone,
and the kit with any one device can sign. The kit's HPKE private key
SHOULD then be encrypted under `Argon2id(kit passphrase)`.

Guardian shares (Section 13.3) are offline material of the same kind.

---

## 11. Quorum membership: enrollment, revocation, refresh

### 11.1 Enrollment of a device

1. The new device N generates DK_N in hardware and DEK_N, and produces
   attestation evidence (Section 21) over a challenge from an existing
   device X.
2. X and N authenticate their channel with a short authentication string
   of at least 40 bits compared by the principal, or a QR code carrying
   `H(DK_N)` scanned by X.
3. X verifies N's evidence against the policy and appends
   `propose-party(N)` with the signatures the policy requires.
4. The quorum re-shares to include N (Section 11.3). N receives `cc`, the
   vault keys, X's highest verified log head and X's accepted vault heads
   by HPKE mode_auth from X, so N's first vault state is anchored to X's
   and not to the sync service (A-14).

### 11.2 Removal

`remove-party(D)` followed by a re-share without D. D's share belongs to
an old epoch and is useless for every credential at every RP (G4). The
chain code is not secret from D, so after removing a *device* the quorum
MUST also rotate the chain code for *new* credentials and SHOULD mark
existing credentials for re-registration at the next sign-in (Section
26.5, Section 28), since D could link them. Vault keys are rotated (Section 18.6).

### 11.3 Re-share and refresh

Re-share runs between at least `t` parties of the old epoch and all
parties of the new one, producing new shares of the same `x` under a new
polynomial (and optionally a new `t`). The transcript digest goes into the
`reshare` event. Parties MUST delete old-epoch shares on completion and
MUST refuse to sign with an epoch older than the log's.

Proactive refresh (same parties, new shares) MUST run at least every 30
days and after any suspected exposure.

### 11.4 Lost party

A lost device is removed by any `policy[1]` other devices; the remaining
parties re-share. If fewer than `t` parties remain, the principal is in
recovery (Section 13).

### 11.5 Adding a device by code

The new device N shows a QR code; a device X of the identity scans it.
Nothing is typed or copied, and N needs no setting beforehand:

1. N listens on every interface on a free port, draws a 32-byte secret
   `s`, and shows `symbolon://link?a=ADDRESSES&p=PORT&s=BASE64URL(s)`, its
   network addresses as its platform reports them.
2. X, with the PIN given (a wrong one stops here, before N acts), connects
   to one of the addresses and sends an *offer*: its relay's host and port,
   the relay's CA certificate and X's party keys, with
   `HMAC-SHA256(s, "symbolon v1 link offer\n" || offer)`.
3. N accepts the first connection whose offer's mac checks; any other is
   closed and N keeps waiting (at most ten minutes and twenty refusals).
   N makes its keys against the relay the offer names (as `device new`,
   with the PIN chosen on N), and answers with its party keys and
   `HMAC-SHA256(s, "symbolon v1 link accept\n" || offer mac || accept)`.
4. X checks the answer's mac and enrolls N (Section 11.1, steps 3-4) as
   `device enroll` would; N joins as `device join` would.

The secret travels only in the QR code, seen by the principal; it
authenticates the exchange, which carries nothing secret (a relay address,
a certificate, public keys). This is step 2 of Section 11.1 with a code
that carries a key for the whole exchange rather than `H(DK_N)` alone. N
and X must reach each other on a local network; otherwise
`device enroll` and `device join` with the keys exchanged by hand remain.
A device N made by an earlier attempt that never joined is used again,
with its PIN.

---

## 12. The cosigner

### 12.1 Role

The cosigner is a party that is always reachable, so that a single
device suffices for everyday signing without being able to sign alone. It
MAY be the principal's own always-on machine, a service, or a service in a
trusted execution environment whose evidence the agent verifies
(Section 21.3).

### 12.2 Blindness (G12)

The cosigner receives `m`, the epoch, a session identifier and a
DK-signed request. It does not receive `rp_id`, `P`, `τ`, `cc`, the
credential ID, client data, or the final signature (Section 6.2). It
cannot tell which RP a signature is for, nor link two signatures to the
same credential. A cosigner that colludes with a relying party can still
correlate by timing; running the cosigner on the principal's own machine
removes that.

For protected vault items (18.10) the cosigner receives only blinded
points, uniformly random to it, with the epoch, a purpose and a DK-signed
request. It cannot tell which item is opened, or whether two openings are
of one item.

### 12.3 Policy enforcement

Before each signing session the cosigner MUST verify that:

- the request is signed by a DK of a device in the current quorum, per
  the highest log head it has verified (it fetches newer heads from the
  sync service and witnesses);
- the epoch is current;
- the device is under its rate limit (`cosigner-policy[1]`);
- the log is not in a duress window in which this request kind is
  refused (Section 14);
- the request does not come from the kit or a device named only in a
  pending `recover` (Section 13.4).

The cosigner MUST append a record of each session (time, requesting
device, `H(m)`) to a log the principal's devices can read, so that misuse
from a compromised device is visible (as in accountable-login systems).

### 12.4 A malicious cosigner

A cosigner that refuses service is replaced: `t` other parties re-share
without it (two devices, or a device and the kit after a recovery). A
cosigner outage stops single-device signing until then; principals who
need availability SHOULD keep two devices, or run their own cosigner as a
second, independently operated party with `t` raised accordingly. A cosigner that colludes with one compromised device
reaches `t = 2` in the default quorum; this is the residual risk the
default accepts, mitigated by running the cosigner on the principal's own
machine or in an attested enclave, or by raising `t`.

---

## 13. Recovery

### 13.1 Paths

| Path | Who acts | Restores |
|---|---|---|
| R1 Surviving devices | `t` parties without the kit | everything, by enrollment |
| R2 Recovery kit | kit + cosigner (cosigner releases its half of the kit's material to the new device after the delay); without a cosigner, kit + one device | everything, after delay |
| R3 Guardians | guardian approvals + guardian shares (opt-in) | everything if guardian shares reach `t`; otherwise authority over the log only |

No path lets a single party recover. No relying party is involved:
because passkeys are threshold keys, recovering the quorum recovers every
credential.

### 13.2 R2: Recovery kit

The kit holds static keys only (Section 10.6): a recovery signing key
whose digest (SHA-256 of its SEC1 encoding) is in the log's field 6, and
an HPKE key. Both derive from a 32-byte kit seed, the only thing printed or
stored on the token: the signing scalar is
`HKDF(seed, nil, "symbolon v1 kit sign", 48) mod (n - 1) + 1`, the HPKE key
pair `DeriveKeyPair(HKDF(seed, nil, "symbolon v1 kit hpke", 32))`. The chain
code and vault recovery key are sealed under `k_K` with AES-256-GCM (nonce
`HKDF(k_K, nil, "symbolon v1 kit nonce" || epoch, 12)`, aad
`["symbolon v1 kit secrets", log-id, epoch]`). To recover, a new
device:

1. reads the kit (printed words, QR, or hardware token) and fetches the
   kit's wrapped current-epoch material from the sync service;
2. appends `recover(path 1, new parties, revealed kit key)`, signed by the
   kit key, and submits it to the witnesses;
3. waits the policy's delay (at least 24 hours, RECOMMENDED 72, measured
   by witness time) with every surviving device notified and able to veto;
4. after the delay, receives the cosigner's half (Section 10.6), assembles
   the kit's share, and re-shares with the cosigner to the new quorum. The
   recovery key is spent; the new device prints a new kit, and its field-6
   digest replaces the old one.

### 13.3 R3: Guardians

A `recover` by path 2 carries COSE_Sign1 (ES256) approvals from
`policy[4]` distinct guardians named in `policy[3]`, each by a device of
that guardian's own verified log head. An approval's payload is
`["symbolon v1 guardian approval", H(p)]`, where `p` is the event payload
with its guardian-approvals list empty; `p` binds the log id, sequence and
predecessor, so an approval cannot be replayed into another log or
another position. A guardian's agent MUST show the requester's attestation summary and
require out-of-band confirmation with the principal before approving.
Guardians that are also parties contribute their shares to the re-share
after the delay.

### 13.4 Delay and veto (G10)

Every `recover` (and every delayed event, Section 8.2) takes effect only
after the delay, measured by witness time, without a valid `veto`.

- **Notification.** The sync service relays the event; in addition, every
  device MUST poll at least two of the policy's witnesses directly, not
  through the sync service, at an interval no longer than a quarter of the
  delay, so a sync service that suppresses the event cannot hide it (A-05).
  Guardians are notified through their own agents.
- **Witness time.** "Now", for every delay, is the median of the times a
  majority of the policy's witnesses sign for a fresh nonce (`["symbolon
  v1 witness time", nonce, time]`), never a party's local clock, so a
  tampered clock on the cosigner's host cannot shorten a delay.
- **Release.** The cosigner MUST NOT release its half of the kit's
  material, or take part in any session with the recovering device, until
  the event carries co-signatures from a majority of the policy's witnesses
  whose witness time is at least the delay in the past.
- **Fresh head.** The relay could serve the log cut before a veto. Before
  it releases the kit's half or deals in a re-share, the cosigner asks
  every witness of the policy, for one fresh nonce, how far it co-signed
  the log (`POST /head`, Section 20.3), and proceeds only if a majority of
  them answer, every answer verifies, none reports a sequence past the
  head it acts on, and none reports another digest at that head. A veto
  co-signed by a majority cannot then be hidden from it while a majority
  answers. The check fails closed: with fewer than a majority answering,
  or with a witness that co-signed past the head an event that never
  reached a majority (an abandoned or contested publish), the cosigner
  refuses until the log's next event takes that sequence.
- **Veto.** A veto is signed by the DK of a device in the quorum preceding
  the event, which requires that device to be unlocked (Section 9.1). A
  thief with a locked device therefore cannot veto.
- **One at a time.** A `recover` filed while another `recover` is pending
  is invalid. Otherwise whoever holds the kit could take every next
  sequence with another `recover` as soon as the last was witnessed, and
  no veto would ever be witnessed.
- **Contest.** A veto pauses a recovery; it does not end the right to
  recover, since otherwise anyone holding one unlocked device could block
  the owner forever (A-04). A recovery vetoed twice is *contested*: with
  guardians, a guardian threshold decides; without guardians, it may be
  filed again with four times the delay, and a veto of that filing needs
  the signatures of two devices. A principal who still has two devices
  keeps a veto; a thief with one device does not keep one forever.
- **Undecidable contests.** One device against the kit, with no guardians,
  cannot be decided cryptographically: each side holds a genuine factor.
  The rule above resolves it for the kit after four times the delay, so a
  principal left with one device whose kit is stolen loses the contest
  (A-20). Setup MUST therefore recommend guardians or a second device,
  and SHOULD recommend a kit passphrase in every configuration.

---

## 14. Duress

### 14.1 Goal

A coercer present for a bounded time can make the principal unlock and
act. Symbolon cannot prevent what is done in that time with the
credentials shown; it prevents the coercer from turning it into durable
control (G11), and records it.

### 14.2 The duress profile

Unlocking with the duress PIN:

1. opens a **real subset** of the principal's credentials and vault items,
   chosen in advance by the principal. Because the subset is genuine data,
   not generated decoys, it is not open to the distinguishing attacks
   published against decoy ("honey") vaults;
2. signals duress to the cosigner only: its signing requests are signed
   by the duress DK sub-key, which the cosigner recognizes and no one else
   can tell from the DK. Nothing is written to the identity log or the
   sync service that would differ from a normal unlock, because a visible
   duress record could be seen by the coercer and endanger the principal
   (A-05). Its envelopes carry the device's party id but are sealed
   (HPKE mode_auth) with the duress profile's own transport key (Section
   9.2), which the cosigner tries after the device's: the relay sees the
   same sender, recipient and sizes. The cosigner answers every request
   under the key it came under (the signing session's rounds, a refusal,
   alert settings), so the duress profile reads its answers and the real
   profile's key is never needed. Under a duress transport key the
   cosigner takes only signing sessions, beacons, alert-setting requests
   and end-duress messages, never a duress-key registration (which it
   takes under the device's own key only), a kit release, an event
   signature or a re-share;
3. otherwise behaves like a normal unlock, with identical timing,
   interface and network pattern.

### 14.3 Containment

From the first duress request until the cosigner receives an end-duress
message signed by `policy[1]` devices other than the duress device, or
`policy[6]` elapses:

- the cosigner refuses re-shares, enrollments, recovery, kit sessions and
  policy changes requested from any device, and the other devices refuse to
  co-sign them;
- signing for credentials outside the subset is impossible, not merely
  refused: the duress profile holds the subset's tweaks but not the chain
  code (Section 9.2);
- the principal's chosen contacts are alerted (Section 14.4).
- the duress profile cannot change what the cosigner knows it by: the
  cosigner takes a duress-key registration only under the device's own
  transport key, which the duress profile does not hold (Section 9.2).

Refusals during duress MUST look like ordinary transient failures (the
same errors and timing as an unreachable cosigner), so the coercer cannot
tell a refusal from a network fault. This cannot be made perfect: a
coercer who demands a new device enrollment and watches it fail
repeatedly may infer duress.

Without a cosigner, containment is enforced by the other devices alone:
they refuse to co-sign authority events with the duress device's sub-key
(which they learn at setup), and the duress profile still cannot sign
outside the subset.

An end-duress message names the window (its start time) and carries
signatures over `["symbolon v1 end-duress", log_id, started_at]` from
`min(policy[1], other devices)` devices other than the duress device, at
least one: an identity with two devices ends a window from the second
alone. The agent sends it as `device duress end DIR` (the app's "I'm
safe" button), from any device but the one that opened the window.

### 14.4 Duress alerts

A duress unlock alerts people the principal chose, through their Symbolon
Home box (the cosigner), never from the phone under duress.

**The unlock beacon.** After every unlock, under either PIN, the app sends
the cosigner one beacon: `{session_id, log_id, epoch, time, location,
requester, sig}` in the usual envelope, as cosign request kind 7 (the
signature is over the request bytes of Section 13 with
`m = SHA-256("symbolon v1 beacon" || log_id || be64(time) || location)`).
The real profile signs it with the DK, the duress profile with the duress
sub-key: the same size, the same timing, and no answer is awaited. The
location is 32 bytes (latitude, longitude in 1e-7 degrees, accuracy in
meters, age in seconds, each a big-endian signed 64-bit integer; zeros
when there is none), the phone's last known location: no new fix is
asked for, so no location indicator shows.

The cosigner drops a DK-signed beacon at once, location included. A beacon
signed by a duress sub-key opens the duress window (as a duress signing
request does) and queues an alert; a second one within the window queues
nothing. A beacon more than ten minutes from the cosigner's time, or with
a session identifier already seen, is ignored. When the window runs out,
or an end-duress message ends it, an "ended" alert is queued.

**The contacts.** Kept by the cosigner (`cos/alerts.cbor`), read and
replaced with an alert-settings message (request kind 8) signed by a DK
of the quorum. A duress sub-key's signature is refused, so the duress
profile sees no contacts and cannot change them; a change while a window
is open is refused too, so a coercer cannot switch alerts off. Each
contact has a name and any of: an ntfy notification (the box makes a
random topic per contact), an email address, a phone number for text
messages, a household member's name on the same box, and a Threnody
fingerprint.

**Sending.** Queued alerts are files in `cos/alerts/`, tried on every
channel each turn of the cosigner until each channel takes it, given up
after a day. The box's settings (`home alerts BOX set KEY VALUE`, in
`BOX/alerts.conf`) say how:

| Channel | Settings | How |
|---|---|---|
| ntfy | `ntfy_url`, `ntfy_token` | HTTPS POST to the topic, priority urgent |
| Email | `smtp_host`, `smtp_port` (465), `smtp_user`, `smtp_pass`, `smtp_from` | SMTP over TLS: EHLO, AUTH PLAIN, MAIL, RCPT, DATA |
| Text message | `sms_url`, `sms_auth`, `sms_body` (`{to}`, `{text}`), `sms_type` (`form` or `json`) | HTTPS POST to a gateway |
| Threnody | `threnody` (the binary) | `threnody ctl /to FP`, then the text |
| Household | none | sealed to the member's devices' alert keys (below) |

`ca` names a PEM file of trust anchors for the HTTPS and SMTP servers
(the system's by default); `tz` and `tz_minutes` the time zone the alert
is written in.

**Household members.** A device registers an alert key with its own
cosigner (`device alerts register DIR`): 32 random bytes kept in
`DIR/alert-key` without the PIN, so a background job can read alerts;
the cosigner keeps the HPKE public keys of at most eight devices. An
alert for a household member is left in their cosigner's inbox on the
box; their cosigner seals it with HPKE (the envelope suite, mode auth
from the cosigner's key, info "symbolon v1 duress alert"), one line per
alert key, to the relay blob `alrt-<log id>-<n>`. Their devices read it
with `device alerts inbox DIR` (no PIN): the Android app every 15 minutes
and at every start, as a notification; elsewhere when the app opens.

**The message.** "DURESS: NAME unlocked Symbolon with the duress PIN at
TIME. Last known location: LAT, LON (within ACC m, AGE old): an
OpenStreetMap link", or "Location unknown"; then "NAME's duress alert
ended at TIME (the duress window ran out / ended from another of their
devices)".

The alert can be seen by a coercer near a contact, and a contact's
response may be seen by the coercer; the principal chooses who is told.

### 14.5 Limits

A coercer who knows Symbolon's design may demand the real PIN. The design
offers no deniability about whether a duress PIN exists beyond Section
9.2's indistinguishability of the sealed blobs. Duress mode MUST be
opt-in, and setup MUST explain that it may be detected and that detection
can escalate danger; the principal decides. The legal status of duress
mechanisms varies by jurisdiction and has not been researched for this
draft.

---

## 15. Continuity proofs (OPTIONAL, relying-party opt-in)

Threshold credentials need no RP change for revocation. Continuity
proofs are for RPs that want more: proof, at login, that the signing
principal's quorum is current and not in a duress window, without learning
anything that links logins across RPs.

1. Each device obtains continuity tokens from an issuer (the cosigner, or
   a federation of witnesses) with Privacy Pass issuance (RFC 9578, type 2,
   blind RSA). The issuer issues only to a device whose DK is in the current
   quorum of a log it has verified. Issuance MUST NOT depend on duress
   state: a token that stopped during duress would reveal it to a coercer
   watching a login (A-05).
2. Tokens expire within an epoch of at most 15 minutes.
3. At login, the agent redeems one token with challenge
   `H("symbolon continuity" || clientDataHash)`, carried in a WebAuthn
   client extension `symbolonContinuity` or an HTTP header.
4. The RP verifies the token against the issuer's public key.
5. The issuer MUST use one public key per epoch for all principals and
   publish it in a transparency log; agents MUST check that the key they
   are issued under is the logged one, since a per-principal key would
   deanonymize every redemption (A-18).

The anonymity set is all principals served by the issuer. An RP that
refuses logins without a token gives the principal's revocations and
duress windows effect even for Bound credentials.

---

## 16. Session binding

- Browser sessions: Device Bound Session Credentials where the browser
  implements them.
- Tokens the agent obtains for applications and tools: DPoP (RFC 9449)
  with a per-RP hardware key; the application receives proofs, never the
  key.
- SSH and code-signing keys: Threshold or Bound profile, used through the
  agent's SSH-agent endpoint; never written to disk in the clear.

### 16.1 SSH agent

`symbolon ssh-agent DIR` serves the SSH agent protocol
(draft-ietf-sshm-ssh-agent) on a Unix socket, by default
`$XDG_RUNTIME_DIR/symbolon/ssh-agent.sock`. The runtime makes the socket
0600 in a 0700 directory owned by the principal, refuses another user's
connections by `SO_PEERCRED`, and opens it close-on-exec (Resid
`resid_unix_*`). The principal points `SSH_AUTH_SOCK` at the socket.

**Keys.** Two kinds, both kept as `ssh` items in the vault:

- *Threshold* (`device ssh new`): an `ecdsa-sha2-nistp256` key made by
  the quorum like a passkey (Section 10), under the relying-party label
  `ssh:NAME`. No party holds the private key. Each signature is a
  threshold signature with the cosigner over SHA-256 of the data, so
  revoking a device (Section 11) revokes its part of every SSH key, with
  no change at any server.
- *Imported* (`device ssh import`): an existing OpenSSH private key
  (`ssh-ed25519`, `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`, or RSA of
  2048 to 4096 bits signing `rsa-sha2-256`/`rsa-sha2-512`; a request for a
  SHA-1 `ssh-rsa` signature is refused), unencrypted or protected by a
  passphrase (bcrypt-pbkdf with
  aes128/192/256-ctr, ssh-keygen's default; bcrypt is not constant time,
  and runs once, at import). Its private part is sealed in the vault like
  any secret field and is opened only inside the process that signs
  (`device ssh sign`), as `Secret` bytes. The file is not removed; the
  principal is told to delete it. RSA signing is constant time in the
  private key (Resid `lib/rsasign.resid`: CRT without a secret division, a
  Montgomery ladder, the signature checked with the public key before it
  is released).

The public keys, with their names, are also written to `DIR/ssh-keys`, so
`REQUEST_IDENTITIES` is answered without the PIN. `device ssh refresh`
(PIN) rebuilds that list, and those of 16.1.2, from the vault's `ssh`
items, for a key made on another device.

A server lets a key in once the key's line is in the user's
`~/.ssh/authorized_keys` there, once per server and key. Symbolon's
certificate authority (16.1.2) needs one setup per server for every key.
Either way the keys and the authority are the quorum's, so one setup
covers every device of the identity.

**Signing.** A `SIGN_REQUEST` opens the consent window (the app run with
`--ssh-consent REQUEST`) for each signature. The window shows:

- the key's name;
- the program asking: the executable and command line of the peer
  process, from `SO_PEERCRED` and `/proc`;
- what is being signed. The data is parsed as an SSH user-authentication
  request (the user name and the key algorithm), or as an `SSHSIG`
  signature with its namespace (`git` for commits and tags, `file`, ...),
  or else marked unrecognized;
- the server, when the client bound the session with
  `session-bind@openssh.com`. The agent checks the host key's signature
  over the session identifier before it shows the host key's fingerprint
  and the names `~/.ssh/known_hosts` gives it (hashed entries are matched
  against the host names in the caller's command line). A
  user-authentication request whose session identifier, or whose server
  host key (`publickey-hostbound-v00@openssh.com`), differs from the bound
  session's is refused. A forwarded agent request is marked and warned
  about. As in OpenSSH's agent, a connection binds again only along a
  forwarding chain: a bind after a non-forwarding one is refused, the
  forwarding mark stays once any hop forwarded, the first host is the one
  shown and requests are checked against the latest hop.

The window takes the PIN and runs `symbolon device ssh sign`, which opens
the item and signs. Only the signature, which is public, goes back to the
agent, on a per-request Unix socket that requires the request's one-time
token; the agent checks the signature against the key before the client
gets it. Each signature takes the PIN. The agent refuses `ADD_IDENTITY`, `REMOVE_IDENTITY`, `LOCK` and the smartcard
messages: keys are managed in Symbolon, not added through `ssh-add`.
Connections are served one at a time, each with a 30-second idle limit
outside a pending consent.

#### 16.1.1 The agent for other apps on Android

On Android there are no Unix-socket agents between apps. Symbolon serves
the same protocol to apps it lists by signing certificate
(`res/values/ssh_agent_callers.xml`; Pylon's release certificates) over
Binder: an exported `SshAgentService`, action
`dev.symbolon.action.SSH_AGENT`, behind the permission
`dev.symbolon.permission.SSH_SIGN` (`signature|knownSigner` with the same
list, so on Android 12+ other apps cannot bind at all). Every call checks
the caller again: the calling uid's package must have a single signer
whose SHA-256 is listed; the agent then names it to the principal as its
label and package.

Each (calling app, connection number) gets its own
`symbolon ssh-agent-stdio DIR RUNDIR PEER` process, which serves the
agent protocol on its standard input and output with the rules above
(binds, refusals, the PIN on every signature); `PEER` is the verified
caller. A consent request is announced on standard error as
`consent PATH`, the request file, which carries `peer`.

| Transaction (`dev.symbolon.ISshAgent`) | Data | Reply |
|---|---|---|
| `CALL` (`FIRST_CALL_TRANSACTION`) | `long` conn, `byte[]` request | `int 0`, `byte[]` reply; or `int 1`, `PendingIntent`; or `int -1` |
| `WAIT` (`+1`) | conn | `int 0`, `byte[]` reply (up to 6 minutes); or `int -1` |
| `CLOSE` (`+2`) | conn | nothing |

A background service may not start an activity, and should not: a
signature's `CALL` returns an immutable, one-shot `PendingIntent` for
`SshConsentActivity`, which the calling app, in front because the
principal is using it, starts before it `WAIT`s. The activity is not
exported, sets `FLAG_SECURE` and hides overlay windows
(`setHideOverlayWindows`), and refuses a request file whose `peer`
differs from the one the service verified. With no `known_hosts` on the
phone, it shows the server's host key fingerprint and leaves the
server's identity to the calling app's own host trust. Connections idle
for 30 seconds outside a pending consent end.

#### 16.1.2 The certificate authority

`device ssh ca-new DIR NAME` makes an SSH certificate authority: an
`ecdsa-sha2-nistp256` key made by the quorum like a threshold key, under
the relying-party label `ssh-ca:NAME`, kept as an `ssh` item with role
`ca`. Its public line goes to `DIR/ssh-cas` (`device ssh cas`), not to
`DIR/ssh-keys`: the agent never offers it, and `device ssh sign` refuses
it, so it signs nothing but the certificates below. A key and an
authority cannot share a name.

**Certificates.** `device ssh certify DIR KEY CA --principal USER ...
[--days N]` issues an OpenSSH user certificate (PROTOCOL.certkeys) for
the vault key KEY: `ecdsa-sha2-nistp256-cert-v01@openssh.com`,
`ecdsa-sha2-nistp384-cert-v01@openssh.com`,
`ssh-ed25519-cert-v01@openssh.com` or `ssh-rsa-cert-v01@openssh.com` by
the key's type. It has a random 32-byte nonce and a random serial, type
1 (user), key id `symbolon:KEY`, the principals (user names on the
servers, 1 to 32 of them, each letters, digits and `. _ - @ +`), valid
from five minutes before it is made (clocks differ) for N days (30 by
default, at most 366), no critical options, and exactly the extensions
`permit-port-forwarding` and `permit-pty` (no agent or X11 forwarding,
no `~/.ssh/rc`). The quorum signs SHA-256 of everything up to the
signature with the authority's key, a threshold signature like any
other; the certificate is parsed back and its signature checked before it
is kept. It goes to `DIR/ssh-certs` (`device ssh certs`: key, authority,
days, principals, validity and the certificate's line), and into the
key's item with what renews it (`cert_ca`, `cert_principals`,
`cert_days`, `cert`), which carries it to the other devices. A key has one
certificate; certifying again replaces it.

**The agent.** For each key with a certificate valid by the clock, the
identities answer offers the certificate first (comment
`NAME (certificate)`) and then the key, as OpenSSH's agent does; an
expired or not yet valid certificate is not offered. A sign request
naming the certificate is signed by the certified key, with every rule
of 16.1: the signed user authentication must name the certificate, the
session binding applies, the consent window opens and takes the PIN. A
client that loaded the certificate from a file asks for the signature
with the key itself while the authentication names the certificate
(OpenSSH does); that is accepted only for the key's current certificate,
and any other certificate is "another key" and refused. The window shows
that a certificate is used: its authority, its principals and its end.

**Renewal.** After a signature the principal approved, `device ssh sign`
checks the key's certificate as the vault holds it. With less than a
third of its lifetime left, or expired, it is renewed in the same run,
with the same unlocked profiles: a second threshold signature, by the
authority, with the authority, principals and days the vault remembers.
The settings come from the sealed item, not from `DIR/ssh-certs`, which
any program of the principal's can write, so a renewal never names
anything the principal did not certify. The signature is printed first:
the window sends it at once and stays open until the renewal ends. A
failed renewal is reported and changes nothing else. A certificate not
yet due that another device renewed is copied from the vault to
`DIR/ssh-certs`. `device ssh renew DIR KEY` renews by hand.

Deleting an authority (`device ssh delete`) drops the certificates it
issued from this device's list; neither a signature nor `device ssh
refresh` lists or renews them again. Servers that trust it accept those
until they expire; its line is to be removed from them.

**Server setup**, once per server:

- *One user, no root*: in the user's `~/.ssh/authorized_keys`, the line
  `cert-authority,principals="USER" CA-LINE`. Pylon writes it from a
  device that can already log in: `pylon authorize --ca USER@HOST
  'CA-LINE'` (and `pylon authorize USER@HOST 'KEY-LINE'` for one key);
  it appends to the file without changing what is there and fixes its
  permissions.
- *The whole server, as root*: the authority's line in
  `/etc/ssh/symbolon_user_ca.pub`, `TrustedUserCAKeys
  /etc/ssh/symbolon_user_ca.pub` in `/etc/ssh/sshd_config` (above any
  `Match` block), then `sshd -t` and a reload of sshd. Each user logs in
  with a certificate that names their user name.

The app's SSH page shows both, with each line and command ready to copy.

---

## 17. Attribute presentation and verifier-constrained release

### 17.1 Holding

Attribute credentials (SD-JWT VC, ISO mdoc, BBS) are vault items.

### 17.2 Presentation

The agent shows the verifier's authenticated identity, the attributes
requested and those it will reveal; reveals only what the principal
approves, preferring predicates; and binds the presentation to the
verifier's nonce and audience.

### 17.3 Unlinkability

BBS: a fresh proof per presentation (MUST). SD-JWT and mdoc: single-use
credentials from batches, never presented twice (SHOULD); the interface
MUST say when a presentation is linkable.

### 17.4 Verifier-constrained release

The principal MAY attach a **handling policy** to an attribute or vault
item: the capability set any code that receives it may hold. For such
items the agent releases only to a verifier that presents:

1. attestation evidence from a trusted execution environment, bound to
   the TLS channel the presentation will use;
2. a signed provenance record for the measured binary, naming its source,
   compiler and runtime, and the **capability set of the receiving entry
   point as checked by the compiler** (Resid's `@requires` closure:
   families and modes);
3. a compiler identity the agent's policy trusts (for Resid, a compiler
   reproduced by diverse double-compiling).

The agent verifies the evidence, that the measurement matches the record,
that the record is signed by a trusted builder, and that the capability
set is within the policy (for example: no `filesystem` write, no `network`
beyond the reply). Only then does it release.

The capability set MUST be that of the **whole program** the measurement
covers, not of one entry point: data received by one function can reach
any other through shared state (A-13). The record MUST also list the
program's declassification points, and the received value MUST be typed
secret in the receiving code, so the flows out of it are the listed ones.
This profile is experimental: until its semantics are formalized (Section
27), an agent MUST NOT present it to the principal as a guarantee. It
exists only where verifiers build with a compiler that records capability
sets; it is a Resid-specific capability.

---

## 18. The legacy vault

Holds what cannot be a key: passwords for RPs without WebAuthn, TOTP
seeds, Synced-profile keys, attribute credentials and notes.

### 18.1 Keys

```
vault_key : 32 random bytes per vault, wrapped to each device party's DEK and,
            for recovery, under the kit's split key k_K (Section 10.6), never to the kit alone
            while a cosigner exists
item_key  = HKDF(vault_key, vault_id, "symbolon v1 item" || item_id, 32)   ; standard tier; protected items: 18.10
salt      = 16 random bytes, drawn for every field each time it is sealed
field_key = HKDF(item_key, salt, "symbolon v2 field" || field_name || u64(item_version), 32)
nonce     = HKDF(item_key, salt, "symbolon v2 nonce" || field_name || u64(item_version), 12)
```

Format 1, which agents wrote before, had no salt (`HKDF(item_key, nil,
"symbolon v1 field" || ...)`, likewise `"symbolon v1 nonce"`). Neither the
item id (from the name) nor the version is unique over time -- an item
deleted and written again restarts at version 1, imports and shared-folder
copies seal at version 1, a relay that rolls a vault back makes a device
reuse a version -- so format 1 could seal two plaintexts under one key and
nonce. Agents seal only format 2 and still open format 1.

### 18.2 Items

```cddl
item = {
  1 => bstr .size 16,                        ; item_id
  2 => uint,                                 ; item_version, incremented on every update
  3 => tstr,                                 ; kind
  4 => { + tstr => bstr },                   ; field_name => ciphertext
  5 => bool,                                 ; in duress subset
  6 => handling-policy / null,               ; Section 17.4
}
```

The agent writes kind `"password"` for every item, so the relay learns
nothing about what an item is. The item's type -- `login`, `card`,
`identity`, `note`, `bank`, `wifi` or `secret` -- is a sealed field
`type`, next to the sealed `name`; other field names are `[a-z0-9_]{1,32}`,
at most 40 per item, each value at most 64 KiB. A login has at least one
of `origin` (scheme://host[:port]), `username` and `current` (the password
rotation reads; rotation needs `origin` and `current`), and may have
`totp`; a card has `number`, a secret `secret`, a note `text`. An item
without `type` predates it: a secret if it has `secret`, else a login.
Fields the user adds are `custom_N`, the value being label, 0x1F, `1`
(hidden) or `0`, 0x1F, text; the agent stores them like any other field.
An item's folder is the sealed field `folder`, its levels joined by `/`
("Work/Clients"); like the type, the relay never sees it.

### 18.3 Encryption

`aad = CBOR([2, vault_id, item_id, item_version, kind, field_name])`;
`ct = salt || AES-256-GCM(field_key, nonce, plaintext, aad)`. A reader
tries format 2 (the first 16 bytes as the salt) and, when that does not
authenticate, format 1 (`aad` led by 1, `ct` the AEAD output alone); the
two use different labels and `aad`, so bytes of one never open as the
other.

### 18.4 The vault head

```cddl
vault-head = COSE_Sign1 over {
  1 => digest,                               ; vault_id
  2 => uint,                                 ; vault_version, strictly increasing
  3 => digest,                               ; Merkle root
  4 => log-id,
  5 => uint,                                 ; log sequence at which the signer was a party
  6 => suite,
}
```

Merkle leaves `H(0x00 || item_id || u64(item_version) || H(CBOR(item)))`
over items sorted by `item_id`, interior nodes `H(0x01 || l || r)`. A
device accepts a vault state only if the head is signed by the DK of a
device in the quorum **of the device's own highest verified log head** --
a device removed since cannot sign an acceptable head, whatever sequence
it states (A-14) -- the
version is no lower than any it has accepted, the recomputed root matches,
and the suite is format version 1's (G6-G8). A device records the root
with the version it accepts; a state at that version with another root is
a fork (the relay served two writers' states at one version, dropping one
change) and is refused with an error that says so, until a higher version
arrives. KDF parameters are never read
from storage.

After a kit recovery (Section 13.2) every device of the recovered quorum is
new, so no current device signed the head. The recovered device accepts,
once, the head under the quorum in force before the `recover` event,
provided the head's field 5 is a sequence before that event (a head a
removed device signs afterwards stays unacceptable), and re-signs it at
the next version; later accepts follow the rule above. Residual risk: an
older pre-recovery head cannot be told from the latest, since the new
device has no history (Section 24.2). Partial fetches carry inclusion proofs; absence is never
deletion without a head proving it.

### 18.5 Duress

The duress profile holds its own vault key covering only items with
field 5 set, re-encrypted under it, so the duress device cannot decrypt
anything else. It holds no key that opens what is addressed to the
device (Section 9.2): shared collections open under the duress PIN only
from the `.dkey` records the real profile sealed to it (Section 19.2).

### 18.6 Rotation

After removing a device or a member, suspected compromise, or ending
duress: new `vault_key`, re-encrypt everything with incremented versions,
new head, wrap to current parties only.

### 18.7 TOTP

Computed in the core (RFC 6238); the seed never leaves it.

### 18.8 Offline reading

After every state it accepts or publishes, a device keeps that state in
its directory (`vault.cache`) with `HMAC-SHA256(HKDF(vault_key, "symbolon
v1 vault cache", 32), cbor)` beside it (`vault.tag`). When the relay, the
log or the witnesses cannot be had, or the relay's state does not verify,
reading -- list, get, show -- falls back to that copy and says why; the
copy is used only if its tag verifies. A change always needs the relay and
the verified log, so it is refused offline. Signing never works offline:
it needs the cosigner (Section 7). Residual risk: someone who can write
the device's directory can put back an older copy with its tag; it is
read-only and only as old as one this device itself accepted.

### 18.9 Importing

`device vault import DIR FILE` reads another password manager's export
and adds every entry to the vault as one new vault version (one head
signature, however many items); nothing already in the vault is replaced:
a name in use, in the vault or earlier in the same import, becomes "Name
(2)", "Name (3)" and so on. With `--dry-run` it reads and checks the file
without the PIN, for the app to show what will come across.

Sources: Bitwarden and Vaultwarden JSON (logins, cards, identities, notes,
SSH keys; folders, and an organization's collections where an item has no
folder; custom fields, hidden ones kept hidden), and any CSV whose header
names its columns -- Bitwarden, LastPass, 1Password, Chrome, Edge,
Firefox, Safari, KeePassXC, Proton Pass and Dashlane all write one. LastPass
secure notes are read by their `NoteType`: credit cards, bank accounts,
addresses, Wi-Fi, passports, licences and social security numbers become
the matching types; others become notes that keep every field. The first
web address of a login gives its `origin`; the others, and app addresses,
become custom fields. Parsing uses the resid-json and resid-csv packages.

Signing in instead of exporting (Bitwarden and Vaultwarden): `device vault
signin-bitwarden DIR SERVER [--dry-run] [--share ID]` signs in as
Bitwarden's own apps do (prelogin; the master key by PBKDF2-SHA256 or
Argon2id over the email; the login hash; `/identity/connect/token` with a
random device identifier kept in DIR; a two-step code from an
authenticator app, email, a YubiKey OTP or a recovery code, and the
new-device email code, asked for through a line conversation with the
app), downloads `/api/sync` and decrypts it on the device: the stretched
master key (HKDF-Expand "enc"/"mac") opens the user key (EncString type 2,
AES-256-CBC with HMAC-SHA-256, the MAC checked first), the user key the
RSA private key, that each organization's key (RSA-OAEP-SHA-1, type 4; or
SHA-256, type 3), and an item with its own key is opened with it. Items in
the trash are left behind. The account's key derivation must be at least
100,000 PBKDF2 iterations, or Argon2id with at least 2 passes and 16 MiB:
a server that lowered it would be asking for a login hash cheap to guess
(a malicious-server downgrade), so a weaker account is refused with a way
to raise it. Every value except what Symbolon lists in the clear anyway (an
item's name, its folder, its site, a custom field's label, a passkey's
site and credential ID) is decrypted into secret bytes and stays secret
until the vault seals it; a passkey's key is read with the standard
library's constant-time base64 and secret PKCS#8 reader. The master
password, master key, session and decrypted vault are never written down.
Accounts on Bitwarden's newer key format ("user crypto v2", COSE keys)
and two-step login by Duo or a security key are refused for now, with the
export file as the way in.

Signing in to LastPass (experimental): `device vault signin-lastpass DIR
[--dry-run] [--share ID]` speaks the protocol of LastPass's own command-line
client, as LastPass offers no supported one for other apps: the iteration
count, the key PBKDF2-SHA256(password, email, n) and the login hash, the
login with an authenticator code or a push approval (polled), the account
blob, and its fields in AES-256-CBC, -GCM or (old accounts) -ECB; a shared
folder's key is RSA-OAEP-SHA-1 to the account's private key. The same
floor on the key derivation, and the same rule for secrets, as for
Bitwarden; a typed secure note's framing (line breaks and "Key:" labels) is
published, its values are not.

1Password: on Linux, through its command-line tool `op` (with the desktop
app's CLI integration): the app reads `op item get --reveal --format json`
and hands it to `device vault import DIR - --format 1password-op` on
standard input (one line, then the PIN; never a file). On Android, and
for any other app that supports it (Google Password Manager, Bitwarden,
Dashlane), through Android's Credential Exchange: the person picks the app
and confirms there, and the FIDO CXF 1.0 it hands over goes to `--format
cxf` the same way (logins, one-time-code seeds, passkeys as Synced
passkeys, cards, Wi-Fi, keys, addresses, identity documents; an item's
folder is the first collection that lists it). As with an export file,
these arrive as text and are classified as they are read.

A Bitwarden export's passkeys (`fido2Credentials`) are imported as Synced
passkeys (Section 5.2, 22.3): a Symbolon passkey's key is split between the
device and the cosigner, and a whole private key is never split after the
fact, so each is kept as a software key in a vault item of type `passkey`
(`rp_id`, `credential_id`, `key`, `public_key`, `user_handle`, `username`,
`display_name`, `rp_name`, `counter`, `profile` "synced", `migrate` "1",
`source`, `imported`), and the import says how many came across and that
each should be replaced by a Threshold passkey. A passkey that is not ES256
(ECDSA on P-256), or whose PKCS#8 key does not read or does not match the
public key it states, is left out with the reason. `device webauthn assert`
serves a credential ID that is not a Threshold credential of the identity
from the Synced passkey with that ID and RP ID, signing on the device alone
(UP, BE and BS set; UV with `--uv`; the counter 0 when the source's was 0,
else the larger of the source's next value and the time in seconds, so it
does not go backwards while no device writes it back); a Synced passkey is
not available under the duress PIN. `device webauthn synced` lists them.
Replacing one (Section 22.3 step 4, 26.5 method 3): `device webauthn
register ... --replaces CID`, during the site's own registration ceremony,
checks that CID is a Synced passkey of the same RP ID, makes the Threshold
credential and records it in the Synced item (`migrate` "registered",
`replaced_by`, `replaced_at`); the Synced passkey keeps signing (its
assertions add `replaced-by`) until `device webauthn retire DIR CID` deletes
it, which is refused while nothing replaces it unless `--force`. The app
replaces an account's imported passkey when the site excludes its
credential ID or names its user handle, lists imported passkeys apart with
their next step, and does not offer a replaced one where the site accepts
its replacement.

Not imported, and said so: a password-protected Bitwarden export (it is
exported again unencrypted). An entry that cannot be stored (a field over 64 KiB, a card
without a number) is left out with the reason; a card without a number
comes across as a note.

The export file holds every secret in clear. The agent reads it and
writes nothing of it outside the sealed vault; the app removes the copy the
platform's file picker made and tells the person to delete the original.

### 18.10 Protected items: a second tier under the quorum

Status: built (2026-11-22), with the deviations listed in 18.10.8. The
evaluation core (`src/vault/toprf.resid`) is tested against RFC 9497's
vectors and an independent reference; the sharing of `k_v`
(`src/vault/kvshare.resid`) against independent P-256 arithmetic; the whole
tier end to end in `tests/protected_e2e.sh`.

The keys of 18.1 separate items from each other cryptographically, but every
device holds `vault_key`, and anyone with `vault_key` derives every item key.
One unlocked device, or malware in it, therefore opens the whole vault. A
passkey cannot be taken this way, because no party holds `x` (Section 10).
This section gives individual items the same property. An item marked
**protected** can only be opened when `t` parties of the quorum take part,
as a passkey can only sign when they do. The cosigner, which takes part
without learning which item it is (G12), limits how fast any one device can
open protected items and records every opening.

The vault therefore has two tiers:

| | Standard | Protected |
|---|---|---|
| Key | `item_key` (18.1), from `vault_key` alone | `pitem_key`, from `vault_key` **and** a threshold OPRF output that needs `t` parties |
| One unlocked device can open | everything | only the fields that stay standard (below), and protected items only at the cosigner's rate |
| Offline | readable from the cache (18.8) | the list only; protected fields need the quorum |
| Fill latency | none | one round trip to the cosigner (or a second device) |
| Duress subset | allowed | not allowed (below) |
| Default for | every item | none: the principal marks items. The app SHOULD suggest it for kinds `bank`, `card` and `secret`, for logins whose origin is an email or identity provider, and for Synced passkeys (18.9) |

#### 18.10.1 The vault OPRF key

The quorum shares a second secret, the vault OPRF key `k_v`, a scalar
modulo the P-256 order `q`. `k_v` is independent of the root key `x`: the two
are never the same scalar and never derived from each other. `k_v` is
shared with Shamir's scheme at the quorum's threshold `t`, using each
party's share index from the epoch transcript (11.3), and is committed with
Feldman commitments `C_0 .. C_{t-1}` (`C_l = a_l G` for the sharing
polynomial `f(z) = Σ a_l z^l`, `f(0) = k_v`). The commitments are field 6
of the quorum (Section 7), so every device verifies them from its verified
log head and never from the relay (G5). Party `j`'s verification key is
`K_j = Σ_l j^l C_l`, and the vault OPRF public key is `K = C_0`.

- **Generation.** At inception, or the first time protected items are turned
  on, the online parties (devices and cosigner) run a joint Feldman key
  generation. Each draws a random polynomial of degree `t - 1`, sends each
  party its value by HPKE mode_auth (info `"symbolon v1 vault oprf"` ||
  log-id || u64(epoch) || party-id), and publishes its commitments. A party
  whose value does not match the sender's commitments complains with the
  opened value, and the sender is excluded and the run restarts. `k_v` is
  the sum of the constant terms and no party ever holds it. The result goes
  into the next `reshare` event (11.3), whose transcript digest covers the
  commitments.
- **Offline parties.** The kit's share is computed and split exactly as
  `x_K` is (10.6): `a_v` is wrapped to the kit and `b_v` to the cosigner,
  and `b_v` is released only after a path-1 `recover` takes effect.
  Guardians hold `k_v` shares only if they hold `x` shares.
- **Re-share and refresh.** Every re-share and proactive refresh (11.3)
  re-shares `k_v` together with `x`, to the same parties at the same `t`. A
  device MUST refuse an epoch whose `C_0` differs from the previous
  epoch's, because `k_v` never changes across epochs. Removing a party
  therefore kills its `k_v` share at the same moment as its `x` share (G4)
  and re-encrypts nothing.

#### 18.10.2 The protected item key

```
input     = "symbolon v1 protected" || vault_id || item_id
y         = OPRF(k_v, input)                    ; RFC 9497, VOPRF mode, P256-SHA256, 32 bytes
pitem_key = HKDF(vault_key || y, vault_id, "symbolon v1 protected item" || item_id, 32)
```

`y` is what RFC 9497's `Evaluate(k_v, input)` would return. It is computed
without any party holding `k_v`, as in 18.10.3. The field keys and nonces
of a protected field are derived from `pitem_key` exactly as 18.1 derives
them from `item_key`, and the AEAD and AAD are those of 18.3.

`pitem_key` needs `vault_key` **and** `y`. The OPRF alone does not open an
item: the cosigner and the kit together (`t = 2`), even after a recovery
has given them both their shares, still lack `vault_key`, so 18.1's rule
that the vault key is never released to the kit alone while a cosigner
exists still holds. `vault_key` alone does not open a protected item
either. That is the point of the tier.

A protected item keeps these fields standard, under `item_key`, so that the
vault can be listed, searched and matched for filling without the quorum:
`type`, `name`, `folder`, `origin` and the marker `protected` (value `"1"`,
the OPRF suite of this section). Every other field is sealed under
`pitem_key`. A device reads the marker before opening any other field, and
an item whose marker does not open, or names a suite other than `"1"`, is
refused (G8). A protected field moved into the standard tier, or the
reverse, does not open, because the two tiers' keys differ and the AAD
names the field.

#### 18.10.3 Evaluation

The requesting device `D` opens a protected item as follows:

1. `D` computes `P = HashToGroup(input)` and chooses a random nonzero
   `r`, then sends the blinded element `B = r P`. The DST and the
   `HashToScalar` hash are RFC 9497's for context string
   `"OPRFV1-" || 0x01 || "-P256-SHA256"`.
2. `D` chooses `t - 1` other parties of the current epoch: the cosigner
   if the quorum has one, otherwise another device (18.10.5). `D` sends
   each of them an evaluation request:
   ```cddl
   eval-request = COSE_Sign1 over {      ; signed by D's DK
     1 => log-id,
     2 => uint,                          ; epoch
     3 => bstr .size 16,                 ; session id, random
     4 => uint,                          ; purpose: 0 open, 1 re-key (18.6), 2 rotation (26)
     5 => [+ bstr .size 33],             ; blinded elements, compressed, at most 256
     6 => uint / null,                   ; for purpose 1: the log sequence of the event that requires the re-key
   }
   ```
3. Party `j` checks the request as the cosigner checks a signing request
   (12.3): signer in the quorum of its highest verified head, epoch
   current, not a kit or pending-recovery device, rate (18.10.4) and duress
   window. It then checks that every `B_i` decodes to a point other than
   the identity, and answers
   `Z_ij = k_j B_i` for each `i`, together with **one** batched DLEQ proof
   (RFC 9497 `GenerateProof(k_j, G, K_j, [B_i], [Z_ij])`) that the same
   `k_j` was used throughout.
4. `D` checks each proof against `K_j`, computed from the quorum's
   commitments. A failed proof names party `j` (an abort with a culprit,
   as in 10.4) and `D` retries with another party if it can. `D` computes
   its own `Z_iD = k_D B_i` locally, without a proof, and combines the
   answers for the evaluating set `S` (`|S| = t`, `D ∈ S`) with
   Lagrange coefficients at zero:
   `Z_i = Σ_{j∈S} λ_j Z_ij`.
5. `D` finishes as RFC 9497 does:
   `y = Finalize(input, r, Z_i)` = `Hash(I2OSP(len(input), 2) || input ||
   I2OSP(33, 2) || SerializeElement(r^{-1} Z_i) || "Finalize")`.

This is the 2HashTDH threshold OPRF (Jarecki, Kiayias, Krawczyk and Xu,
2017), using RFC 9497's encodings and proofs. `Σ λ_j k_j = k_v`, so `y`
equals the single-key evaluation, and that equality is what the
implementation's reference tests check. The blinding makes `B` a uniformly
random point to every party but `D`: an evaluating party learns neither
`input` nor `y` (G12), and two evaluations of the same item cannot be told
apart from evaluations of two items.

Each `Z_ij`, `r`, `y` and `pitem_key` is a secret value (23.3). A device
keeps `pitem_key` in memory for at most five minutes after its last use,
and drops it at lock (9.3) and when the item is closed, whichever comes
first. It never writes `y` or `pitem_key` to storage.

#### 18.10.4 The cosigner's limits

`cosigner-policy` gains field 3: the maximum number of blinded elements per
device per hour for purposes 0 and 2. The default is 60, and the principal
may lower it. Purpose 1 (a re-key) is exempt from the limit only when field
6 names an event in the cosigner's verified log head, at or after its
current epoch's `reshare`, that requires a vault rotation under 18.6
(`remove-party`, the end of a duress window, a completed `recover`, or a
`rotate-vault`), and only once per item per event. Re-keys therefore cost
one blinded element per protected item, at most once per event.

The cosigner appends to its session log (12.3) one record per evaluation:
time, requesting device, purpose, number of elements, and the session
id. It records no element. The app shows each device's protected openings
for the day from that log. An opening rate well above that device's usual
rate is shown as an alert on every other device, because the most likely
cause is malware in an unlocked device.

During a duress window the cosigner refuses every evaluation request, and
the refusal reads as a network failure (14.3).

#### 18.10.5 Without a cosigner

Without a cosigner, the other evaluator is one of the principal's other
devices. That device answers only after its user confirms on it, with a
consent screen outside the requesting page (22.2) that shows the requesting
device's label and the number of items. A device that is locked does not
answer. Every protected opening is then an approval on a second device, as a
security-key prompt is, and the interface says this before the first item is
marked protected. The kit never evaluates unless a recovery has taken
effect (10.6), so the kit with one device cannot open protected items while
the principal's other devices can still veto (13.4).

#### 18.10.6 Interaction with the rest of the vault

- **Duress (18.5).** The duress profile holds no `k_v` share. An item can be
  protected or in the duress subset, but not both. The device refuses to
  set both flags, and marking an item protected removes it from the subset,
  after saying so.
- **Rotation (18.6).** A new `vault_key` changes every `pitem_key` but not
  `y`. The rotating device obtains every protected item's `y` with one
  purpose-1 request of up to 256 elements per batch, then reseals.
- **Offline reading (18.8).** The cache keeps protected items as they are,
  sealed. Offline, a device lists and searches them and shows their
  standard fields, but opening one says that it needs the cosigner (or
  another device).
- **Sharing (19).** In this format version a collection has no OPRF key, so
  its items are all standard. Moving a protected item into a collection
  makes it standard there, and the device asks before doing so. Moving one
  back reseals it as protected.
- **Credential rotation (26).** A password change on a protected login
  makes purpose-2 evaluations, which count against the device's limit. A
  rotator device (24.2) holds `vault_key` but no unrequested `y`, so a
  stolen rotator yields protected items only at the cosigner's rate.
- **Filling (22.5-22.7).** Matching uses the standard `origin`. The value is
  filled only after the evaluation succeeds, and the fill prompt says
  "protected item". A device may evaluate ahead of time for the item the
  principal has selected, but never for items they have not selected.
- **Organizations (29).** Group folders are collections, so they are
  standard in this format version (Section 28).
- **Turning the tier off.** Unmarking an item reseals it under `item_key`
  as a new version. This is an ordinary change and needs one evaluation.

#### 18.10.7 What the tier does and does not give

- Against one unlocked, compromised device: at most the cosigner's limit
  of protected items per hour, each opening recorded in a log the other
  devices read. Without a cosigner, only the items the principal approves
  on a second device.
- Against a leaked `pitem_key`, field key or plaintext: nothing about
  other items, because each `y` is an independent PRF output and HKDF is
  one-way.
- Against the relay, the kit or the cosigner alone: nothing (they lack
  `vault_key`, a share, or both).
- Against the cosigner colluding with a compromised unlocked device:
  everything, as for signing (12.4). The defense is the same: a cosigner
  of the principal's own, an attested cosigner, or a larger `t`.

#### 18.10.8 As built

What the implementation does where this section leaves a choice, or does
less than it says:

- **Dealers.** `k_v` is generated and re-shared by the two parties that
  deal `x`: the requesting device and the cosigner (the kit's device at a
  recovery). Each dealing is one message per receiver (`WKvDeal`) in the
  receiver's HPKE mode_auth envelope (`src/net/envelope.resid`), next to the
  CGGMP rounds; there is no separate inner HPKE layer. A part that does not
  fit its dealer's commitments (or, re-sharing, a dealing whose `C_0` is not
  `lambda_d K_d`) ends the session naming the dealer; there is no
  complaint round.
- **Inception and later.** A new identity gets `k_v` at inception when its
  cosigner deals it; an older cosigner does not answer, and the identity is
  made without it. `device protection enable` adds `k_v` to a quorum with
  this device as its only device (a re-share to the same parties at the
  next epoch); a quorum with other devices would need them to join that
  re-share, which they cannot yet.
- **Evaluation.** The session id is 32 bytes (as for signing requests),
  and the request is signed with `request_tbs` (12.3) over its message
  `SHA-256(log-id || purpose || seq || each element)`, kind 6. Purpose 1
  (re-key) is counted like purpose 0: vault rotation (18.6) is not built,
  so no event exempts it yet.
- **The session log** for devices: `device openings` asks the cosigner for
  the past week's evaluation records (DK-signed request; nothing is
  recorded for it) and prints each device's openings for the hour, day and
  week. A day is unusual when it exceeds 20 openings and three times the
  device's daily average over the six days before; the app shows it on
  every device's home screen while unlocked.
- **Key lifetime.** The agent is one process per command, so `y` and
  `pitem_key` live only for that command, which is shorter than the five
  minutes of 18.10.3.
- **Not built.** The no-cosigner mode of 18.10.5 (opening is refused
  without a cosigner), and the purpose-1 re-key of 18.10.6.

---

## 19. Sharing

A shared collection is a vault with its own key whose members are
principals. A member's DEKs MUST come from the member's verified log head,
checked against the policy's witnesses or a fingerprint compared out of
band (G5); never from the sync service alone. The collection key is
wrapped with HPKE mode_auth, `info = "symbolon v1 share" || vault_id ||
member log-id || u64(roster_version)`. The recipient MUST verify that the
sender key used by mode_auth belongs to a device in the sender's verified
log head. Removing a member rotates the key.

### 19.1 Objects

```
coll_id    : 16 random bytes
vault_id   = SHA-256("symbolon v1 collection" || coll_id)
roster     = { coll_id, version, owner log-id, owner label,
               members: [ { log-id, label } ], name_ct, deleted,
               log_sequence, signer, sig }
wrap set   = { coll_id, roster_version, member log-id,
               wraps: [ { to party, from log-id, from party, enc, ct } ] }
card       = { log-id, name, log_sequence, signer, sig }
```

At the relay: `roster-<id>`, `wrap-<member log>-<id>` (one per member,
holding a wrap for each device of the member's verified quorum: devices
only, never the cosigner, the kit or a guardian), `coll-<id>` (the
collection's items: a vault state as in Section 18, under the collection
key) and `card-<log>`. The relay lists blob names by prefix, so a device
finds its collections (`wrap-<own log>-`) and the people with cards
(`card-`); a listing is a hint, every object is verified.

The roster and the card are signed by a device's DK over `"symbolon v1
roster"` (or `"symbolon v1 card"`) followed by the record's deterministic
CBOR without `sig`; the signer must be a device of the owner's (the
card's log's) verified quorum, at a sequence already verified. The
collection's name is a sealed field (`field_seal` with item id `coll_id`,
kind `"share"`, field `"name"`, version the roster version), so the relay
learns no names but the people's own.

### 19.2 Rules

- Only the owner's devices sign rosters. The version strictly increases
  with every change of members, name or key; a device keeps the highest
  version it saw and refuses a lower one.
- A wrap set is accepted only at the roster's current version. Any member's
  device that holds the key may add the wraps a member's newer devices
  lack (an enrolment, a recovery); wraps are authenticated by mode_auth
  and the sender check above, not by the roster.
- Wraps go to each device's transport key in its verified log head and
  are sent with the sender's current one. A device that moved to a new
  key (`party-key`, Section 9.2) opens wraps with the new key and then,
  under the PIN only, with its v1 key, until they are made again; its
  wraps made with v1 no longer authenticate (the sender check uses the
  key in the log), so it makes every collection's wraps again, to every
  member's devices, in the update and then each time it opens a
  collection still listed in `rewrap.todo`. Until then a member whose
  wrap it made reads that collection from their kept copy.
- The collection's vault head is signed by a device of anyone in the
  current roster; the device checks it against that person's verified log
  (Section 18.4, with that log in place of its own) and keeps the highest
  version it accepted.
- Removing a member: a new key, every item opened and sealed again under
  it (new item ids, which come from the key), a new head, a new roster
  without them, wraps for those remaining and an empty wrap set for the
  removed one. Deleting: an empty item list, a roster marked deleted, and
  empty wrap sets for everyone.
- Leaving: a member publishes `leave-<id>-<log>` = { coll_id, log-id,
  roster_version, log_sequence, signer, sig }, signed like a card over
  `"symbolon v1 leave"`. Their devices stop opening the collection and
  forget their copies at once. The owner's device, when it next lists its
  collections, removes every member with a valid record (as above: a new
  key) and clears the record; adding someone clears any old record of
  theirs. The owner cannot leave; they delete. Until the owner's device
  re-keys, the key the leaver held still opens what is there.
- Moving an item between the own vault and a collection (or between two
  collections) opens it under one key and seals it under the other (a new
  id), writes it at the destination first and then removes it from the
  source, so a failure in between leaves it in both, never in neither. An
  item with a password change under way does not move.
- Rotation (Section 26) works in a collection as in the own vault; the
  lease and the failed sign-ins live in the item, so they hold across
  every member's devices.
- Offline reading: after a collection loads, a device keeps
  `share-<id>.key`, the key with the collection's name, role and number of
  people, sealed (AES-GCM, random IV) under `HKDF(vault_key, "symbolon v1
  share record", 32)` with AAD `"symbolon v1 share record" || coll_id`,
  and a copy of the items with its tag as in Section 18.8
  (`share-<id>.cache`, `.tag`). Reading and listing fall back to these as
  the own vault does, and say why; a change needs the relay. A device
  forgets them when the collection is deleted, it is removed, or it left.
- Duress: beside each `.key` the device keeps `share-<id>.dkey`, the same
  record sealed by HPKE base mode (suite 16,1,2) to the duress profile's
  HPKE key when the person chose the collection for the duress PIN on
  this device, and otherwise random bytes of the same length, so the files
  do not tell whether a duress profile exists or what its subset holds.
  Under the duress PIN the device lists and reads only those collections,
  from `.dkey`, and changes nothing: a change fails as one the relay did
  not take (Section 14.3). The choice is per device and is kept when the
  key changes (the device re-seals `.dkey` the next time it loads the
  collection under the PIN).

### 19.3 Who is who

On Symbolon Home the relay and the witnesses are one box, so a verified
log proves only that the log is consistent, not whose it is: the box could
present a log of its own under a person's name. People therefore compare
fingerprints out of band before adding someone: six groups of five
decimal digits from `SHA-256("symbolon v1 fingerprint" || log-id)`, three
bytes per group modulo 100000. The app shows a person's own fingerprint
and, when adding someone, theirs, and asks whether they match. Residual
risks: someone removed keeps what they could read before; a member can
copy the key or the items out; the relay can withhold objects or serve
stale ones down to the versions a device last saw; and it can put back a
member's old leave record after they were added again, which removes
them again (a denial of service it could do by withholding anyway).

---

## 20. Synchronization

### 20.1 The service is untrusted

It stores and relays logs, heads, items, wrapped keys, protocol messages
between parties and recovery notifications. Every object is verified by
its recipient. Devices authenticate to it with DK signatures over fresh
challenges; it holds no password or password verifier.

### 20.2 Transport

TLS 1.3. Protocol messages between parties are additionally HPKE
mode_auth encrypted end to end between the parties' keys; the service
relays ciphertext.

The agent's configuration names one trust anchor (a CA certificate) for
the service and the policy's witnesses; with it, every call to them is
TLS 1.3 with the server's certificate checked against that anchor and the
host name or IP address. TLS adds no trust the protocol relies on: log
events are signed and witnessed, envelopes are authenticated end to end
and witness times are signed, so a service or witness that a network
attacker impersonates can only withhold. What TLS adds is confidentiality
of the traffic's metadata and of the request patterns against a passive
network observer. A deployment without the anchor (loopback tests) speaks
plain HTTP.

### 20.3 Witnesses

Witnesses co-sign `(log-id, seq, digest)` and refuse a second digest for
the same `(log-id, seq)`. A witness co-signs only an event that is valid
as the next event of the log it is shown with the request (the whole log
before it, with its co-signatures): the log verifies (Section 8.3), and
the event passes every check of the next step at the witness's own time
but its co-signatures, which do not exist yet; at sequence 0, an inception
whose digest is the log id, signed by every party of its quorum. So only
the holders of a log's keys can take its next sequence, and a device's
veto of a pending recovery is co-signable until the delay has run by the
witness's clock. The relay likewise stores an event only as the verified
next event of the log it holds. Agents and the cosigner MUST require a
majority of the policy's witnesses on `recover`, delayed and `reshare`
events and on heads they release material against, and SHOULD require
them on all heads. A policy MUST name at least three witnesses run by
independent operators.

A witness co-signs with the witness time at which it checked the event:
its own clock, but never earlier than the last event's witness time, so a
witness whose clock runs behind does not co-sign a time that every agent
would refuse ("witness time went backwards") while it holds the sequence.
It records what it co-signed whole or not at all (a temporary file renamed
into place). A co-sign request is bounded (2 MiB, 2048 events); with the
signature limits of Section 8.3 its cost grows only with its size.

A witness answers, for a 32-byte nonce and a log id (`POST /head`, body
`nonce || log`), CBOR `[seq, digest, time, sig]`: the highest sequence of
the log it co-signed and the digest it co-signed there (an empty byte
string, and `seq` 0, when it co-signed none), and its time, signed with
its key over `["symbolon v1 witness head", log, seq, digest, nonce,
time]`. The cosigner uses it before a release or a re-share (Section
13.4), a device for the freeze alarm (Section 20.4).

### 20.4 Fork and freeze detection (G17)

Parties exchange their highest verified heads at every contact and alarm
on a fork. A party that sees no newer witnessed head within a configured
interval warns that it may be frozen.

A witness co-signs one digest per `(log, seq)` and never another. Anyone
holding a key that can sign a valid next event (a device, a removed
device until the next re-share, the kit) can therefore show different
valid events to different witnesses, so that no event gets a majority at
that sequence and the log can never grow again. When the witnesses refuse
a device's event, the device asks each of them how far it co-signed the
log (`POST /head`); if no digest at that sequence can still reach a
majority, counting every witness that did not answer or co-signed nothing
there as free, it reports "log frozen at sequence n" as a possible attack
instead of a generic failure.

**Residual (open).** The alarm detects the freeze; nothing in this version
undoes it. A frozen log stays frozen, and recovering from it (for example
with the relay as a sequencer whose signed claim on `(log, seq, digest)`
the witnesses require) needs a protocol change not made here. Excluding
removed parties from signing rules (Section 8.3) narrows who can cause it.

### 20.5 Symbolon Home

A household MAY run every service on one box it owns (a NAS, a small
computer): the relay, a cosigner per principal, and pairing. The box
makes its own certificate authority (P-256, 20 years) and a server
certificate under it (10 years) for the names and addresses its devices
use; no public CA or domain is involved. A principal is invited with a
one-time code (128 bits, a week) that the box shows as a QR code:

```
symbolon://pair?h=HOST&p=PORT&c=CODE&f=BASE64URL(SHA-256(server certificate DER))
```

The device connects to `https://HOST:PORT` and MUST accept only a server
certificate whose SHA-256 is `f`, before sending the code, so a network
attacker can neither read the code nor pose as the box. `GET /setup?c=`
returns the relay, the principal's cosigner keys, the witnesses and the
box's CA certificate, which the agent then trusts for TLS (Section 20.2);
`POST /pair?c=` with the keys `device new` printed pins the device at the
principal's cosigner as the inception party (Section 11.1 step 2, the
out-of-band comparison being the QR code) and spends the code. The box
keeps each cosigner's key on its disk; whoever holds the box and one of a
principal's devices still needs the device's PIN (Section 9.1).

Interim deviation: the box runs the policy's three witnesses itself, so
they are not independent operators (Section 20.3): the box could present
a forked log to devices that have no other contact. Independent public
witnesses (an append-only public log for heads, signed public time for
delays) replace them; until then the interface states it.

---

## 21. Agent attestation

### 21.1 Evidence

The platform's attestation of the DK (TPM2_Certify by an AK whose EK
chains to the manufacturer, or the platform's equivalent), and the agent
build's signed provenance record with a measurement binding the running
binary to it where the platform measures it.

### 21.2 Uses

REQUIRED within the quorum: enrollment (Section 11.1), guardian approval
(Section 13.3), and the cosigner's acceptance of a new device. OPTIONAL
and off by default toward RPs, with per-RP consent.

### 21.3 Verifying services

Before relying on a cosigner, issuer or witness that claims to run in a
trusted execution environment, the agent MUST verify its evidence against
pinned measurements, bound to the channel.

### 21.4 Agent updates

An agent update is the most direct way to compromise every principal at
once (A-15). An agent MUST install an update only if:

- it is signed by a threshold of the project's release keys;
- it appears in a public transparency log, with an inclusion proof;
- its provenance record reproduces: independent rebuilders have published
  matching hashes (for Resid, from a compiler checked by diverse
  double-compiling).

Updates roll out in stages, and each device's enrollment policy (Section
11.1) and the cosigner's acceptance policy pin the builds they accept, so
a device running a build absent from the log is refused by its peers.

---

## 22. Platform integration

### 22.1 Credential provider

The agent registers as a passkey provider through each operating system's
credential-provider interface where one exists, and as a CTAP 2
authenticator (hybrid transport, USB/HID emulation where permitted)
elsewhere. The browser extension, where needed, holds nothing and forwards
requests over native messaging.

On Android 14+ the app is a Credential Manager provider. The system asks
it which passkeys it holds for an RP, answered from public data without
the PIN; choosing one opens the agent-owned passkey screen, which shows
the RP ID, the account and the requester's origin as Android reports it
(a browser's page only for browsers on the privileged-browser list, else
the app's `android:apk-key-hash`), takes the PIN (so UV is truthful), and
has the agent form the response (`device webauthn register | assert`,
Section 10.4). A browser supplies its own `clientDataHash`; for an app the
client data is formed by the provider. Cross-device sign-in (hybrid, the
QR code a computer shows) reaches the provider through the platform where
the platform routes it to third-party providers.

### 22.2 Consent outside the page (G14)

No credential, code or attribute is released into a page without a gesture
in agent-owned interface outside the page's DOM showing the origin (and
frame origin) as the browser or OS reports it. No fill on in-page clicks;
no fill into frames of another origin, except card fields into a pinned
payment processor's frame (22.2.1). The clipboard is avoided; where used,
content is marked sensitive and cleared within 30 seconds.

#### 22.2.1 Payment processor frames

Checkouts commonly put the card number, expiry and security code in a
cross-origin iframe served by the payment processor (hosted fields), so
that the merchant never handles the card. Refusing every cross-origin
frame would make card fill impossible on most checkouts and push the
principal to the clipboard, which is worse. The exception is narrow:

- Only card fields (`cc-number`, `cc-exp`, `cc-exp-month`, `cc-exp-year`,
  `cc-csc`, `cc-name`) may go into a frame of another origin, and only if
  that frame's origin, as the browser reports it, is exactly one of the
  pinned processor origins. No suffix or pattern matching. Login fields
  never go into another origin's frame.
- The pinned list ships with the agent and changes only with a release:
  `https://js.stripe.com`, `https://assets.braintreegateway.com`,
  `https://checkoutshopper-live.adyen.com` and its regional hosts (`-us`,
  `-au`, `-apse`, `-in`), `https://web.squarecdn.com`. Each entry is
  confirmed against the processor's documentation before a release.
- The consent window names the page's origin and, separately, every
  processor frame that will receive a field. The principal approves both
  in one gesture.
- The page's own frame may receive card fields too (a merchant that takes
  cards directly). A frame of any other origin receives nothing.

### 22.3 Migration and credential exchange

A principal arrives with credentials held elsewhere: a password manager,
a platform's passkey provider, a browser, hardware security keys, an
authenticator app. Symbolon MUST be adoptable without the principal
re-entering anything and without any relying party's involvement, and MUST
NOT lock the principal in.

**Sources.** In order of preference:

1. **FIDO Credential Exchange (CXP/CXF).** From any provider that
   implements it, the agent imports passwords, passkeys, TOTP seeds, notes
   and the other CXF item kinds over the CXP channel, without a plaintext
   file.
2. **The source's own export format.** Until CXP is widely available, the
   agent reads the documented export of each widely used manager (CSV and
   JSON exports, KeePass KDBX, browser password CSV). Each format has one
   importer in the core, with no `filesystem` or `network` authority of its
   own; the bridge hands it the file's bytes. The agent then offers to
   overwrite and delete the export file and says that a plaintext export
   may persist in backups or the source's download history.
3. **Re-registration.** Passkeys a provider will not export (platform
   providers without CXP, and every hardware-bound key) cannot be moved.
   The agent records the relying party as *to migrate* and registers a
   Threshold passkey there by recipe or at next sign-in (Section 26.5,
   methods 2 and 3). Hardware security keys are left registered as
   additional credentials unless the principal removes them.

**Import is untrusted input** (the file or provider may be compromised or
malformed):

- importers are fuzzed (Section 23.3), bound in size, and refuse rather
  than repair a malformed record;
- an imported item becomes an ordinary vault item only through a vault
  update the importing device signs (Section 18.4); nothing imported
  changes the identity log, the quorum or the policy;
- origins in imported items are **unconfirmed** until the principal
  consents to a fill at that origin (Section 22.2). An unconfirmed origin
  is not used to fill without consent and is not part of the intersection
  a recipe may visit (Section 26.4), so a crafted import cannot widen where
  a recipe or a fill may go;
- imported passkeys become Synced-profile keys (Section 5.2) and are
  marked for re-registration as Threshold; imported TOTP seeds, SSH keys
  and attribute credentials keep their kind; each item records its source
  and import time in the vault.

**Procedure.**

1. **Import** from the sources above into a new vault version.
2. **Assess.** Breached, weak and reused passwords are flagged (Section
   26.1); the principal is asked once to mark high-value items and,
   optionally, to choose the duress subset (Section 14.2).
3. **Coexist.** Until the principal retires the source, both stores may
   be in use. During coexistence the agent MUST NOT rotate an imported
   item at its relying party (rotation would leave the source holding a
   dead password the principal may still use), except with the principal's
   per-item or blanket consent. A repeated import merges by item: an
   incoming record that differs from the vault's is written as a new item
   version with the vault's previous value kept in history; nothing is
   silently overwritten or dropped.
4. **Upgrade.** In order of the value marks: register a Threshold passkey
   where the site supports passkeys and retire the password (Section 26.6),
   replace imported passkeys with Threshold ones (Section 26.5), and
   rotate passwords the source held (Section 26.3), each verified before
   the old credential is dropped.
5. **Retire the source.** The agent shows which items are still only in
   the source's form (not yet rotated or re-registered). Secrets the source
   held stay exposed to it, and to its sync service, until they are
   rotated; the agent says so and schedules their rotation once the
   principal confirms retirement.

**Organizational and shared vaults** (team or family plans) migrate into
shared collections (Section 19): one member imports and the collection's
key is wrapped to the members' log-verified keys. Membership is not
imported from the source; each member is added from their own log.

**Identity providers and credential services** (single sign-on, enterprise
identity providers, account-recovery services) need no special path: the
principal registers a Threshold passkey at the identity provider as at any
relying party, and removes the old factors as that provider's policy
allows. Accounts that sign in through an identity provider follow it.

**Export.** Leaving Symbolon is supported by the same mechanisms: Synced
keys, passwords, TOTP seeds, notes and attribute credentials export
through CXP/CXF. Threshold credentials are **not exportable** (Section
10.3); an export lists the relying parties at which to register the new
provider's credential, never a private key.

### 22.4 Applications

Local socket readable only by the principal's user, peer authenticated by
process credentials; the agent shows which executable asks.

### 22.5 Browser extension

The extension holds nothing (no vault data, no PIN, no keys, no cache of
values between fills) and runs no code in pages until the principal asks.
Its parts:

1. **Trigger.** The toolbar button or its shortcut (Ctrl+Shift+L). Both
   belong to the browser's own interface, so a page cannot synthesize
   them. Nothing is filled on page load or on a click inside the page.
2. **Scan.** The extension injects its field finder into every frame of
   the tab. Each frame reports the autocomplete kinds of its visible
   fields (`username`, `email`, `current-password`, `new-password`,
   `one-time-code`, the card kinds of 22.2.1). Fields without an autocomplete token are classified by name,
   label and position. Each frame is labelled with the origin the browser
   reports for it (`webNavigation`). A frame whose own report disagrees
   is dropped.
3. **Request.** The extension sends the agent `{type: "fill", id, top,
   frames: [{frame, origin, fields}]}` over native messaging (host
   `dev.symbolon.browser`). The browser starts the agent for the
   extension's ID only (`allowed_origins`, `allowed_extensions`). Messages
   are a 32-bit little-endian length and UTF-8 JSON, at most 1 MiB. Any
   program of the same user could run the host itself, so the host refuses
   to start unless its first argument is an extension origin (Chromium) or
   its second is the add-on ID (Firefox). Same-user code can fake those
   arguments, so the consent window's caller line (item 5) is the real
   check.
4. **G14 check (agent).** The top origin must be `https://host[:port]` in
   lower case, or `http://localhost` / `http://127.0.0.1`. Each frame is
   cut to the kinds 22.2 and 22.2.1 allow, and frames left with nothing
   are dropped. If no frame remains, the agent refuses without showing
   anything.
5. **Consent (agent-owned).** The agent opens the consent window, the
   app run as `--fill-consent REQUEST`. The request file is mode 0600 in
   `$XDG_RUNTIME_DIR` (the agent refuses if that is unset, rather than
   use a shared `/tmp`). It holds no vault data, only the origins, the
   field kinds, a loopback port the agent listens on for this one request,
   and a 256-bit one-time token, which is kept out of argv. As it opens,
   the window connects to the port and sends the token. The agent drops
   any connection that does not send the token within 2 seconds and keeps
   waiting, so a local process that connects first cannot block the
   window. The window shows the page's origin, every processor frame, and
   the program that started the host. It finds that program itself from
   `/proc` (the owner of the listening socket, then that process's parent
   executable), so a caller cannot choose what is shown, and it warns
   when the program is not a browser. It takes the PIN and offers only
   the matching items: logins whose stored site covers the page (step 6),
   or cards; the only match is chosen, and Enter fills it. The principal
   chooses one. The window opens the item with the agent (for a fill the
   agent gives only what a fill uses, and a login's current one-time code
   instead of its TOTP key) and sends its fields on the same connection.
   It sends only the fields its type fills: for a login the origin,
   username and password, and the current code when the page has a code
   field; for a card the holder, number, expiry and code. It never sends a
   card PIN, notes, custom fields or a TOTP seed. Where the page has a
   `new-password` field, the window also offers to create a login for the
   page's origin: a generated password, saved in the vault first and
   filled only once saved, so a password is never set at a site without
   being kept. Only such a just-created password goes into `new-password`
   fields; a stored one never does. The agent waits
   up to 5 minutes, then closes the connection. The window then marks the
   request expired and sends nothing, so nothing goes to a port the agent
   no longer holds.
6. **Item check (agent).** The item's type must be the one offered. A
   login's stored origin must cover the page's origin: the same origin,
   or a subdomain of the stored host with the same scheme and port, after
   a leading `www.` of the stored host is dropped. A login saved for
   `proton.me` fills at `account.proton.me`; one saved for
   `login.example.com` fills neither `example.com` nor `mail.example.com`.
   A stored host without a dot, or an IP address, covers only itself.
   Frames still follow 22.2: only frames of the page's own origin (or a
   pinned processor's, for cards) receive anything. The values
   are `Secret` in the agent from the moment the answer is parsed. The
   socket buffer and the answer's text lines before that are plain
   memory, not wiped. The values are declassified once, when the reply to
   the browser is written, and only for the kinds each frame asked for. The reply is `{type: "fill", id,
   fills: [{frame, values: {kind: value}}]}`, or `cancel`, or `error` with
   a reason the button's tooltip shows.
7. **Fill.** Before filling, the extension checks that the tab is still
   at the same top origin. It targets each frame by the document it
   scanned, where the browser reports document IDs (Chromium), so a frame
   that navigated is not filled. Elsewhere it targets the frame ID, and
   the origin check that follows still applies. Inside the frame it
   checks `location.origin` against the approved origin once more. Values
   are set the way typing sets them (native setter, `input` and `change`
   events). Selects for month and year are matched by value or text.
   Values are not kept after the call.

Where the browser is not involved (Android apps, and browsers on
Android), Android autofill (22.6) and the passkey provider (22.1) apply
instead. The extension is for desktop browsers. Every fill also follows
22.7. A page can still read values once they are in its fields: the
guarantees above are about which page gets them and whether the
principal approved it, not about what the page then does.

### 22.6 Android autofill

On Android 8 and later the app is also an autofill service
(`AutofillService`): logins, cards and one-time codes for apps and for
browsers that hand autofill to a third-party service. It follows 22.2:
nothing leaves the agent without the principal's gesture in agent-owned
interface that shows, as the platform reports it, where it goes.

1. **Locked offer.** A fill request is answered without opening the
   device and without vault data: one entry, "Fill with Symbolon", which
   the system presents (a dropdown, or an inline suggestion the keyboard
   shows). It names no item, account or site, so neither the requesting
   app nor the keyboard learns what the vault holds. Choosing it opens the
   fill screen (item 4) through the response's authentication intent; a
   tap on the system's entry cannot be made by the requesting app. The
   service answers only for fields it classifies as login, card or
   one-time-code fields (autofill hints, input type, then id and hint
   text), and never for a view the request reports as not visible.
2. **The requester.** It is the package of the activity holding the
   focused field, with its signing certificates as the package manager
   reports them. Its identity is `android:apk-key-hash:` and the base64url
   SHA-256 of the signing certificate, with the package name.
   - A browser on the privileged-browser list (22.1), matched by package
     and by a certificate the list marks as a release build (a debug or
     `userdebug` key, such as the platform test key, is one anyone can
     sign with, so it never counts and is not shipped), also reports a
     page: the origin is the scheme and web domain the request gives for
     the focused field, `https://host[:port]`, or `http://` only for
     `localhost` or `127.0.0.1`, as in 22.5 step 4. A page on any other
     scheme, or one whose scheme the request does not give, is refused:
     it names no site, so no login is offered there; `http` is never
     taken for `https`. The platform's compatibility mode is used only
     for browsers on that list.
   - For any other app, every web domain in the request is ignored. An
     app's WebView shows whatever page the app chooses, and the app can
     read what is filled into it (the AutoSpill attacks, Black Hat Europe
     2023), so a page inside an app is never treated as that page's site.
3. **What may fill where.** A login is offered
   - in a privileged browser, when its stored origin covers the page's
     origin (22.5 step 6);
   - in any other app, only when the login was saved for that app (its
     package and `android:apk-key-hash`, item 6), when the principal linked
     it to that app in Symbolon (item 8), or when its stored site names
     that app in Digital Asset Links: the site's
     `https://HOST/.well-known/assetlinks.json`, fetched by Symbolon
     directly from that host over TLS, without redirects and at most
     128 KiB, lists `delegate_permission/common.get_login_creds` for an
     `android_app` target with that package and certificate fingerprint.
     The file covers only a login saved for that very host (`https`, no
     port, a leading `www.` aside on either side): unlike a page in a
     browser, a subdomain's file never reaches the parent site's login,
     since a subdomain may be a hosting customer's or one team's.
     Only the sites the app itself claims (its manifest's
     `asset_statements`) are looked up, never every site in the vault,
     which would tell the network what the vault holds. The file is
     untrusted input; a fetch that fails or does not list the app means
     no link. A result is cached for at most 24 hours. No third-party
     lookup service is asked. The app, not the agent, does this: it is the
     app that learns the requester's package and certificate from the
     platform, so the agent could only repeat the app's word.

   No other login is offered: there is no search and no manual choice of
   an item for an app or page that matches none, since that choice is how
   a lookalike app obtains a password. The fill screen says that nothing
   is saved for this app or site, and offers only to save a new login
   there, or to link one later from the item in Symbolon (item 8). A card is offered in any app or privileged browser, for card
   fields, once the principal has seen the requester on the fill screen;
   its PIN never fills.
4. **The fill screen** is an activity of the app, outside the requesting
   app's process. It shows the requester (item 2) first, opens the device
   as 22.7 requires, then lists the items item 3 allows, the only match
   preselected. The answer is a dataset with the chosen item's values for
   the request's classified, visible fields only: a login's username and
   password, a card's kinds of 22.2.1, and for a one-time-code field the
   current code (22.7 item 5). The screen is `FLAG_SECURE`, hides other
   apps' overlay windows (Android 12 and later), and ignores touches while
   anything covers it; before Android 12, a touch made while it is
   obscured is refused.
5. **Duress.** Under the duress PIN, only the duress subset (14.2) is
   offered and saved to, with the same screens and timing.
6. **Saving.** After an app commits a form with a password, the system
   may ask the principal to save it, in the system's own prompt. Saving
   opens the fill screen with the requester (item 2) and writes only once
   the principal confirms and the device opens: a new login, or, when
   the principal chooses one, a new version of a matching login with its
   previous password kept as a hidden field (22.3, Coexist). No login is
   chosen for update by default, so another account's password is never
   replaced without a tap. A login saved in a privileged browser records the page's
   origin. One saved in any other app records the app's package and
   `android:apk-key-hash`, and fills only in that app. A save releases
   nothing, so it needs no match; an unconfirmed save is dropped.
7. **Security keys.** The app relays CTAP 2 between the agent's
   `SYMBOLON_FIDO_SOCKET` (9.4) and a security key over NFC or USB. The
   relay only passes messages: the agent checks every assertion as 9.4
   requires, so a relay that alters one opens nothing.
8. **Linking a login to an app.** Many apps are not named in their
   site's Digital Asset Links. The principal may link a login to an app
   from the login's page in Symbolon ("Use in an app"), never from a fill:
   the in-the-moment choice a requesting app prompts is what item 3
   forbids, while a link is made deliberately, away from the app.
   - The principal chooses an installed app from the list the package
     manager gives. The link screen shows the app's name and icon, its
     package, the SHA-256 fingerprint of its signing certificate, and
     where it was installed from, as the package manager reports the
     installer. It warns, before the principal confirms, when the app was
     not installed by an app store, and says that an app asking to be
     linked is a reason to stop: no genuine app needs that.
   - Confirming opens the device (22.7 item 1) and records the package and
     `android:apk-key-hash` on the login, as a vault change (18.4); a
     login may be linked to several apps. The link covers that signing
     certificate only: an update signed by another key no longer matches,
     and is linked again only the same way.
   - The login's page lists its links, each with its app's name and
     fingerprint, and removes one with a tap. Under the duress PIN no link
     is made or removed (14.3).

### 22.7 Every fill

These hold for the extension (22.5) and Android autofill (22.6).

1. **Opened for each fill.** A fill opens the device afresh (9.1): the PIN,
   or the platform biometric that releases it, and with a security key
   enrolled, that key's touch (9.4). No unlocked session is used for a
   fill: not the app's "stay unlocked", and not an earlier fill's.
2. **Keys for fills.** A principal MAY set a device to refuse every fill
   while no security key is enrolled, rather than fill on the PIN alone.
3. **One at a time.** The agent holds at most one pending fill per device.
   A request that arrives while one is pending is refused, not queued, so
   one gesture cannot approve two requests, the principal's and another
   raised beside it.
4. **The gesture names the request.** The requester (the page's origin and
   its frames' origins, or the app's identity) is shown before the PIN is
   asked and before the key is touched. The opening assertion's client
   data hash is SHA-256 over `"symbolon v1 fill"` and the request (the
   requester and the field kinds), and the device keeps the assertion with
   the request in its fill record, so each touch can be traced to the fill
   it approved.
5. **One-time codes.** A login's TOTP code is computed in the core (18.7)
   and released like a field, as the `one-time-code` kind, only where the
   login itself may fill. The seed is never released.
6. **Passkeys first.** A filled password stays a replayable secret. Where
   the relying party accepts passkeys, the fill screen offers to register
   a Threshold passkey and retire the password (26.6).

---

## 23. Implementation requirements (Resid)

### 23.1 Capability partitions

Each Section 5.1 component is a set of modules whose `@requires` are
exactly its authority: core none (plus `declassify` at named publication
points), hw `device`, store `filesystem`, net `network(readonly)`, UI
`display` or `terminal`. The compiler's E0219 check proves the partition.

### 23.2 Verified-only types

| Type | Built only by | Required by |
|---|---|---|
| `LogHead` | `il_verify` | everything reading a quorum or policy |
| `Quorum` | `LogHead` accessor | threshold sessions, re-share |
| `Share(E)` | DKG / re-share at epoch `E` | signing at epoch `E` only |
| `RecipientKey` | `share_recipient(LogHead, Witnessed \| Fingerprinted)` | HPKE wrapping |
| `VaultState` | `vault_accept` | every item read |
| `FieldKey` | `field_key(...)` | `field_seal`, `field_open` |
| `HandlingOk` | `release_check(evidence, record, policy)` | release of a policy-bearing item |

Encrypting to an unverified key, reading an unaccepted vault, signing with
a stale-epoch share, or releasing a policy-bearing item without a check
MUST be type errors.

### 23.3 Secrets and constant time

Shares, chain code, nonces of the threshold protocol, keys, PINs and
plaintexts are `Secret(...)` from entry. Every core function on secrets has
a constant-time case and the coverage gate passes. The agent runs in
secret mode. The threshold protocol's implementation MUST check every
proof and parameter its paper requires, with a negative test for each
check, and MUST be fuzzed on every message parser.

### 23.4 What Resid lacks (checked 2026-11-19, against Resid v0.10.1; still so in v0.12.0)

| Missing | Needed by |
|---|---|
| Constant-time, secret-typed threshold ECDSA. CGGMP21 runs, but shares, Paillier `p`/`q` and nonces are public `List(UInt(64))`, and the tweak crosses in at one named `declassify` (PLAN-CGGMP layer 8). This blocks a release. | Sections 10-13, G15 |
| RSA blind signatures and Privacy Pass issuance/redemption (RSA is verification and signing only) | Section 15 |
| A fast Argon2id. It exists (`argon2g.resid`) but works on byte lists, so new devices use m = 19 MiB, t = 2 rather than 6.1's 256 MiB, t = 3 | Sections 6.1, 9 |
| `mlock` of secret memory and exclusion from core dumps | G15 |
| CTAP 2 hybrid transport (caBLE), and credential-provider bindings beyond Android | Section 22 |
| Pairings and BBS | Section 17.3 |
| Capability sets in provenance records, per entry point, verifiable remotely | Section 17.4 |
| A GUI library (PLAN-gui: not started; the app is Flutter over the agent) | Section 22.2 |
| Targets beyond Linux and Android | platform coverage |

Present: threshold ECDSA (CGGMP21 key generation, refresh, re-share,
presigning, signing with the blind tweak and identifiable abort, in
`lib/cggmp*.resid`), Paillier, Shamir and Feldman, Argon2id and BLAKE2b,
HMAC-SHA1, ECDSA P-256 (RFC 6979), HPKE, AES-GCM, ChaCha20-Poly1305, HKDF,
PBKDF2, SHA-1/256/384/512, COSE, CBOR, X.509, TLS 1.3, TPM key creation,
PIN-policy sealing and signing, quotes and the attestation verifier,
provenance records, CTAP 2.1 over USB HID, and the `display`, `terminal`
and `device` capability families. In Symbolon itself: the threshold OPRF of
18.10 (`src/vault/toprf.resid`), the recipe interpreter and its CDP driver
(26.3), the Pwned Passwords range check (26.1, `src/rotation/breach.resid`),
and the Android credential provider and autofill service (22.1, 22.6).

---|---|
| Threshold ECDSA (DKG, signing, re-share, refresh) and its oblivious transfer or Paillier machinery | Sections 10-13 |
| RSA blind signatures and Privacy Pass issuance/redemption (RSA is verification-only today) | Section 15 |
| Argon2id, BLAKE2b | Section 9 |
| HMAC-SHA1 (SHA-1 exists) | Section 18.7 |
| `mlock` of secret memory | G15 |
| TPM key creation, sealing to a PIN policy, and signing with non-exportable keys | Sections 9, 11, 16 |
| CTAP 2 transports (HID, hybrid) and OS credential-provider bindings | Section 22 |
| Pairings and BBS | Section 17.3 |
| Capability sets in provenance records, per entry point, verifiable remotely | Section 17.4 |
| A GUI library (planned, not started) | Section 22.2 |
| A browser-automation driver for recipes (CDP or extension-driven) and a recipe interpreter | Section 26.3 |
| Pwned Passwords range client (SHA-1 exists; needs `network` module) | Section 26.1 |
| Targets beyond Linux and Android | platform coverage |

Present: ECDSA P-256 (RFC 6979), HPKE, AES-GCM, ChaCha20-Poly1305, HKDF,
PBKDF2, SHA-1/256/384/512, COSE, CBOR, X.509, TLS 1.3, TPM wire format and
quotes, the attestation verifier, provenance records, and the `display`,
`terminal` and `device` capability families.

---

## 24. Security considerations

### 24.1 Goal-to-mechanism map

| Goal | Mechanism | Section |
|---|---|---|
| G1 | WebAuthn origin, taken from browser/OS only | 10.4, 22.2 |
| G2 | Keys, not secrets; DPoP; no server password | 10, 16, 9 |
| G3 | Threshold keys over independent parties | 10 |
| G4 | Re-share as revocation; epoch checks | 11 |
| G5 | Log-reached keys; witnesses or fingerprints; `RecipientKey` | 8, 19, 23.2 |
| G6-G8 | Vault head, per-field keys, fixed suite | 18, 6 |
| G19 | Threshold OPRF per protected item; cosigner limit and log | 18.10 |
| G9 | No party holds `x`; guardian shares opt-in | 10, 13 |
| G10 | Delay and veto | 13.4 |
| G11 | Duress profile and containment | 14 |
| G12 | Cosigner receives only `m` and epoch | 12.2 |
| G13 | DBSC, DPoP | 16 |
| G14 | Consent outside the DOM | 22.2, 22.5-22.7 |
| G15 | Secret types, ct gate, secret mode, mlock | 23.3 |
| G16 | Selective disclosure; verifier-constrained release | 17 |
| G17 | Head exchange; witnesses | 20 |
| G18 | Rotation triggers, two-phase change, recipes, rollover | 26 |

Each row is a design argument until the lemmas of Section 27.3 that cover
it are verified; this table is not a claim of security.

### 24.2 Residual risks

- Cosigner plus one compromised, unlocked device meets `t = 2`.
- Threshold ECDSA is complex; an implementation flaw can leak shares.
- Shares live in software memory during signing; one share is useless
  alone, but several devices compromised over time between refreshes are
  not.
- A removed device knows the chain code and can link existing credentials
  until they are re-registered.
- Threshold credentials do not satisfy RPs that demand hardware
  attestation of a non-exportable key; those use Bound.
- Losing all devices, the kit and the cosigner (or guardian threshold)
  loses everything; the interface says so at setup.
- Duress protection is bounded (Section 14.5).
- Witness collusion with the sync service defeats fork detection for
  parties that never meet, and a witness majority colluding with a kit
  thief can shorten a recovery delay.
- The additive tweak's security under related-key attacks rests on `τ`
  being unpredictable; it needs a proof (A-10).
- Duress can be inferred by a coercer who probes for refusals (Section 14.3).
- Recipes are a supply chain: a malicious recipe within the rules can
  still click the wrong button. Transparency, holds and the destructive
  list reduce this; they do not remove it.
- A rotator device holds vault keys while locked.
- Without a cosigner, a stolen kit plus one device signs without delay.
- A stolen kit filed while the principal has no device left to veto, and
  no guardians, succeeds after the delay: that is what a recovery factor
  is. The kit passphrase is the defense.
- A principal talked into linking a login to a lookalike app (22.6 item
  8) gives that app the login. The link screen's publisher, installer and
  warning make this harder; they cannot make it impossible.
- Standard vault items open with `vault_key` alone, so one unlocked,
  compromised device reads all of them; only protected items (18.10)
  resist that, and only up to the cosigner's limit per hour, which is a
  rate, not a bar. The cosigner with one unlocked device opens every
  protected item.
- The threshold OPRF of 18.10 rests on the one-more gap Diffie-Hellman
  assumption in the random-oracle model (2HashTDH). Its joint Feldman key
  generation can bias the distribution of `K`; that this does not matter
  for an OPRF key is argued, not proven (C-05).
- A filled password is a replayable secret. The page or app that receives
  it can keep it, and malware with accessibility access can read filled
  fields. 22.5 to 22.7 decide who receives a value and whether the
  principal approved; passkeys (26.6) remove the secret.

---

## 25. Privacy considerations

- RPs see one unlinkable public key per credential; continuity tokens are
  unlinkable within the issuer's anonymity set.
- The cosigner sees request timing and the requesting device; it learns
  no RP. Running it on the principal's own machine removes even that.
- The sync service sees object sizes and timing; padding to size classes
  is RECOMMENDED.
- Attestation toward RPs is off by default.
- Guardians, sharing peers and witnesses see the log identifier.
- A cosigner colluding with a relying party can correlate by timing
  (Section 12.2).
- For protected items (18.10) the cosigner sees when each device opens
  one and how many, never which; the relay sees which items are protected
  (their field `protected`), as it already sees field names (18.2).

---

## 26. Credential rotation

The principal never has to change a credential. The agent rotates every
secret it holds -- inside the agent and at relying parties -- when
rotation is due, and no rotation may leave the principal without a
working credential (G18). Where a relying party demands a factor the agent
cannot supply (a code sent by SMS or email), the agent batches such
requests into one prompt; this is the only case in which the principal is
involved.

### 26.1 When rotation is due

Rotation is driven by evidence, not by calendar. Routine periodic changes
of passwords are not required by NIST SP 800-63B-4, which calls for a
change when compromise is evident, and they add risk (lockouts) without
benefit for unique random secrets. Triggers:

| Trigger | Rotates |
|---|---|
| A device is removed from the quorum (Section 11.2) | Shares (re-share), chain code for new credentials, vault keys, **every legacy password and TOTP seed the removed device could decrypt** |
| A party is suspected compromised | As above, plus re-registration of Threshold credentials (26.5) |
| A password appears in a breach corpus (k-anonymity range query, e.g. Pwned Passwords; only a 5-hex-digit SHA-1 prefix leaves the agent) | That password |
| A relying party is reported breached | Every credential for that relying party |
| A password is weak or reused (imported vaults) | That password, once |
| End of a duress window (Section 14) | Everything the duress profile exposed |
| The principal asks | The selection |
| Policy schedule (OPTIONAL, off by default) | High-value items the principal marks |

Proactive refresh of shares (every 30 days, Section 11.3) is scheduled,
since it is invisible to relying parties and cannot lock anyone out.

**The breach check** (`device vault breach DIR`, 2026-11-19). For each
login's `current` password the agent computes SHA-1 inside the core and
sends only the first five hex digits to the range service
(`GET /range/PREFIX` with `Add-Padding: true`), one query per distinct
prefix. The service answers with every suffix it holds under that prefix.
The agent compares its own suffix against every line in constant time with
respect to the hash, so the matching line is never a branch, and it makes
public only the resulting count. A login with a nonzero count is reported
and becomes due for rotation under this trigger. The service is Pwned
Passwords over TLS, trusting the platform's root bundle, or a mirror the
principal names. A service that cannot be reached, or whose certificate
does not verify, fails the check and does not report the logins clean, and
so does an item that does not open. The app runs the same check (More ›
Breached passwords) and keeps the names of the breached logins and their
counts on the device, never a password or a hash, so the vault list, the
item and the fill windows can warn; changing a login's password clears its
mark. On Android it hands the agent the system's roots as one PEM bundle and
the network's DNS servers (`RESID_RESOLV_CONF`), which Android does not
keep where the agent looks. Protected items (18.10) are skipped,
because their passwords need the quorum, and the check says how many it
skipped. The range service learns the prefixes and their timing, which is
the anonymity set the protocol is designed around (about 800 to 1,000
passwords per prefix).

After a device is removed, the attacker who holds it may already be
racing to change the same passwords. The agent MUST rotate in order of the
principal's value marks (financial, email and identity providers first)
and, for an email account that receives password resets, before anything
that resets through it.

**Who rotates.** Rotation needs vault keys, so it runs only on an unlocked
device, or on a device the principal designates as *rotator*, which keeps
the vault key available under a hardware-backed key while locked and is
listed as such in the log (a deliberate trade of exposure for automation,
off by default). Each item has at most one rotation in progress: the
rotating device takes a lease, a vault item field with an expiry, and
other devices do not start a rotation of a leased item (A-17).

### 26.2 Passkeys: rotation without relying parties

For Threshold credentials, all secret material is the shares. Refresh and
re-share (Section 11.3) replace every share while the public key, and so
every relying party's record, stays the same. This is complete rotation of
the secret for every passkey at once, with no relying-party involvement
and no possibility of lockout: the new shares are verified to produce a
signature under `X` before the old ones are deleted.

A relying party's record needs to change only if the root key itself may
be exposed (at least `t` parties compromised) or credentials must become
unlinkable to a removed device (Section 11.2). Then 26.5 applies.

### 26.3 Passwords: the two-phase change

A legacy password at a relying party is changed by the following
protocol, whose invariant is that **at every moment the vault holds a
password the site accepts**:

1. **Prepare.** Generate the new password under the site's rules (from
   the recipe, 26.4). Write a new item version holding both `current = old`
   and `pending = new` to the vault, with a new vault head, synchronized to
   at least one other device before step 2.
2. **Change.** Run the site's change procedure (26.4), filling the old and
   new passwords and any TOTP code from the vault.
3. **Verify.** In a fresh session, sign in with `pending`. Success:
   write `current = new`, keep `old` in the item's history (at least 3
   versions, encrypted like any field), new head. Failure: sign in with
   `old`; if that succeeds, the change did not happen -- drop `pending`,
   record the failure, retry later. If neither works, keep both, mark the
   item "unresolved", and notify the principal; never delete either.
4. **Clean up.** Close sessions opened by the procedure.

Sign-in attempts are rationed so verification cannot itself lock the
account (A-17): at most one attempt per candidate password per run, at
most three failed attempts per site per day across all devices (counted
in the vault), with exponential backoff; an "unresolved" item tries every
password in its history once per run before notifying.

A change interrupted at any step resumes at step 3 on the next run, so a
crash or lost network never strands the principal.

### 26.4 Recipes

There is no standard API for changing a password; the W3C "well-known URL
for changing passwords" (`/.well-known/change-password`, a Working Draft)
only locates the page. The agent therefore drives each site's own pages
with a **recipe**: a declarative, signed, versioned description of the
change procedure.

```cddl
recipe = COSE_Sign1 over {
  1 => tstr,                                 ; registrable domain
  2 => uint,                                 ; version
  3 => password-rules,                       ; length, classes, forbidden characters
  4 => [+ step],
  5 => [* tstr],                             ; origins the procedure may visit (same site only)
  ? 6 => [+ step],                           ; sign-in procedure for 26.3 step 3
}

step = [0, url: tstr]                        ; navigate (must be in field 5)
     / [1, selector: tstr, value: slot]      ; fill
     / [2, selector: tstr]                   ; click
     / [3, condition]                        ; expect: URL, element, or text present/absent
     / [4, passkey-register: true]           ; run the site's passkey registration (26.6)

slot = "username" / "old" / "new" / "totp" / "password"
```

Field 6 is the sign-in procedure that step 3 of 26.3 runs in a fresh
session, once per candidate; it fills the slot `password` (the candidate)
and never `old` or `new`, may not register a passkey, and must end in an
expectation like field 4. A recipe without field 6 cannot be verified, so
the agent does not run it. Field 6 is present only when not empty, so a
recipe without it keeps its five-entry canonical encoding.

Rules:

- Recipes come from a curated repository, are signed by a threshold of
  its keys, and appear in a public transparency log; the agent requires
  an inclusion proof. A new recipe version takes effect only after a hold
  of 7 days in the log (except a version that only removes steps or
  origins), and the agent keeps the last version that worked (A-09).
- The origins a recipe may visit are the **intersection** of its field 5
  and the exact origins saved with the vault item; a recipe cannot add an
  origin, and registrable-domain matching is not used.
- A recipe can name only slots, never values. The agent substitutes values
  at fill time, after checking the current top-level origin as the browser
  reports it, and only into fields of the matching type: `old` and `new`
  (and `password`) into password inputs, `totp` into one-time-code inputs, `username` into
  username or email inputs. A recipe cannot place a secret into a field
  the site would display or forward (A-09).
- Click steps are reviewed in the repository; the agent refuses a click
  whose target text or form action matches a destructive-action list
  (delete, close account, unsubscribe all, transfer, remove two-factor),
  as a backstop, not a guarantee.
- The procedure runs in an isolated browser profile with no other site
  data, under the agent's `process` and `network` authority, in a
  component that holds no secret except the slots of the item being
  changed.
- A recipe whose expectations fail aborts at that step; 26.3's invariant
  then holds.

**Recipe-less sites (OPTIONAL, off by default, never for items marked
high-value).** An automated agent MAY attempt the change from the site's
page structure. It MUST NOT see secret values: it
operates on slot placeholders, and the agent performs the substitution
under the same origin checks. Page content is untrusted input to such an
agent (prompt injection), so it may only issue the step kinds above, on
the item's own site. Commercial attempts at this exist and are still
unreliable (Chrome's experimental assistant-driven change, 2026).

### 26.5 Re-registering Threshold credentials

When a relying party's record must change (26.2), the agent creates a new
credential under a new chain code (or a new root key after a full
compromise) and retires the old one:

1. **Rollover extension (preferred, relying-party opt-in).** In an
   ordinary assertion the authenticator includes an extension output
   `symbolonRollover = {credentialId', P'}` inside `authenticatorData`, so
   the assertion's signature under the old key `P` vouches for `P'`.
   Rollover is safe only while the old key is the principal's alone: after
   a confirmed compromise of the root key, an attacker can roll over too,
   and the relying party cannot tell the two apart. Then the relying
   party's own recovery is required, and the agent says so rather than
   racing the attacker (A-19). A supporting relying party SHOULD notify the
   account holder of a rollover and hold the old key valid for a short
   overlap. A
   relying party that supports it stores `P'` as pending, promotes it at
   its first successful use and then deletes `P`; one that does not ignores
   it. This needs browser pass-through of the extension and relying-party
   support; until then, method 2 applies.
2. **Recipe.** A recipe's `passkey-register` step runs the site's own
   registration ceremony (which WebAuthn requires the relying party to
   start) from its account-security page, then deletes the old passkey
   there, verifying sign-in with the new one first, as in 26.3.
3. **At next sign-in.** Where neither is possible, the agent re-registers
   when the site next offers passkey creation and asks the principal only
   if the site requires a step it cannot perform.

The agent keeps signing with the old credential until the new one is
verified.

### 26.6 Migrating to passkeys

Whenever a site that has a legacy password supports passkeys, rotation
prefers migration: register a Threshold passkey (26.5 method 2), verify
it, then, where the site allows, remove the password or set it to a long
random value the agent holds and never uses.

### 26.7 Other credentials

| Credential | Rotation |
|---|---|
| DPoP and session keys (Section 16) | New key per session or per refresh-token lifetime; automatic. |
| SSH keys | New key; the agent updates `authorized_keys` on hosts it is permitted to reach and on code hosts through their APIs, verifies login with the new key, then removes the old (two-phase, as 26.3). |
| API tokens issued by services with token APIs | Through the service's API, two-phase; otherwise by recipe. |
| TOTP seeds | By recipe (re-enroll the authenticator), two-phase: the new seed is verified with a code before the old one is removed. |
| Recovery codes issued by sites | Regenerated by recipe after any use or exposure. |
| Vault keys, chain code, shares, DEKs | Sections 18.6, 11.2, 11.3; DEKs on every refresh. |

### 26.8 Accounting

Every rotation is recorded in the vault (what, when, why, result), and
the agent shows a single status: credentials current, credentials pending,
and the few that need the principal (with the one action each needs).

---

## 27. Formal verification

No security property of this specification may be claimed until it is
proven as this section requires. "Proven" always means *proven under a
stated model and stated assumptions*; every claim names its lemma, its
model and what the model leaves out.

### 27.1 Method: three layers

| Layer | Establishes | Tools | Status of the tools |
|---|---|---|---|
| 1. Symbolic | The protocol logic: an adversary controlling the network and the compromised parties cannot reach a bad state. Primitives are ideal. | **Tamarin** (primary); **ProVerif** (cross-check, and privacy properties stated as observational equivalence) | The tools used for TLS 1.3, 5G authentication and Apple's iMessage PQ3 |
| 2. Computational | Primitives and constructions are secure against any efficient adversary, with concrete probability bounds. | **CryptoVerif** (automated); **EasyCrypt** (interactive); CV2EC to carry CryptoVerif assumptions into EasyCrypt; paper proofs where a published proof exists | Peer-reviewed tools; CV2EC presented at CSF 2024 |
| 3. Implementation | The code behaves as the model. | Test vectors generated from the models, differential testing against a reference, fuzzing, the constant-time gate (Section 23.3) | Evidence, not proof: Resid has no verified compiler |

Tamarin is primary because Symbolon is stateful (epochs, delays, vetoes,
leases, duress windows), which Tamarin's multiset rewriting and induction
handle directly, and because it has machine-checked proofs of a deployed
protocol with unbounded loops (PQ3).

### 27.2 The adversary in the models

- Dolev-Yao network: the adversary reads, drops, replays, reorders and
  forges every message, including everything the sync service stores
  (A1, A3).
- Compromise rules, each a separate rule the adversary may fire at any
  time, so that each lemma states exactly which compromises it tolerates:
  `RevealShare(party, epoch)`, `RevealDK(device)`, `StealKit`,
  `CorruptCosigner`, `CorruptWitness(w)`, `CorruptGuardian(g)`,
  `Coerce(device, duration)`, `MaliciousRP`.
- Time: Tamarin has no clock. Delays are modelled as orderings: a
  `recover` takes effect only after an event `DelayElapsed(e)` that the
  model allows only after `WitnessTime(e)` from a majority of witnesses
  and after every honest device has had a `Notified(e)` step it can follow
  with a veto. This abstracts, and depends on, Section 13.4's polling
  rule; the assumption is stated in each lemma that uses it.

### 27.3 Properties and their lemmas

Each row is one or more lemmas in the models. "Tolerates" lists the
compromise rules under which the lemma must hold.

| ID | Property | Tolerates | Layer, tool |
|---|---|---|---|
| L-01 | **Log integrity.** Every head an honest party accepts extends the head it accepted before; no event is accepted that the signing rules of 8.2 did not authorize. | `RevealDK` of fewer than `policy[1]` devices, `CorruptWitness` minority | 1, Tamarin |
| L-02 | **Fork detection.** If two honest parties accept different events at one sequence and later contact each other or a common honest witness, both raise a fork alarm. | sync service | 1, Tamarin |
| L-03 | **No single-party signing.** A passkey signature under `P` exists only if `t` parties of one epoch took part. | any `t - 1` of `RevealShare`, `CorruptCosigner` | 1, Tamarin (threshold signing abstracted as an ideal functionality, 27.4) |
| L-04 | **Revocation.** After a `reshare` that excludes party D completes, no signature at any RP uses D's share. | `RevealShare(D, old epoch)` | 1, Tamarin |
| L-05 | **Kit isolation (A-02).** With a cosigner, the kit takes part in a signature only after a path-1 `recover` took effect. | `StealKit` + `RevealDK` + `RevealShare` of one device | 1, Tamarin |
| L-06 | **Offline currency (A-03).** At every epoch the kit can obtain a share of the current epoch. | sync service (availability assumed) | 1, Tamarin |
| L-07 | **Recovery safety (G10).** A `recover` takes effect only if every honest device of the preceding quorum was notified and did not veto within the delay, or the contest rule of 13.4 resolved it. | sync service, `StealKit`, `CorruptGuardian` minority, `CorruptWitness` minority | 1, Tamarin |
| L-08 | **Recovery liveness.** A principal holding the kit, with honest witnesses and cosigner, recovers within four times the delay against an adversary holding at most one device. | `RevealDK` + `RevealShare` of one device | 1, Tamarin |
| L-09 | **Contest outcome (A-20).** The contest rule's results are exactly those stated in 13.4, including the undecidable one-device-versus-kit case. | as L-07 | 1, Tamarin (a lemma that the stated losing case is reachable, so the documentation of the limit is itself checked) |
| L-10 | **Duress containment (G11).** During a duress window no re-share, enrollment, recovery or policy change involving the duress device succeeds, and no signature is produced for a credential outside the subset. | `Coerce`, sync service | 1, Tamarin |
| L-11 | **Duress unobservability (A-05).** A coercer observing the coerced device, the sync service and the RPs cannot distinguish a duress unlock from a normal one. | `Coerce`, sync service, `MaliciousRP` | 1, ProVerif (observational equivalence); Tamarin diff mode as cross-check |
| L-12 | **Cosigner blindness (G12).** The cosigner cannot distinguish two sessions for the same credential from sessions for two credentials, nor learn an RP identity. | `CorruptCosigner` | 1, ProVerif (equivalence) |
| L-13 | **Vault integrity (G6, G7).** An honest device accepts a vault state only if it equals, item for item, a state written by a device of its current quorum, at a version no lower than any it accepted; no moved, swapped, deleted, injected or rolled-back item is accepted. | sync service, `RevealDK` of a removed device | 1, Tamarin |
| L-14 | **No downgrade (G8).** No honest device decrypts or encrypts under parameters other than suite 1's. | sync service | 1, Tamarin |
| L-15 | **Authenticated sharing (G5).** An honest member opens a shared key only if it was wrapped by a device in the sender's verified log, and wraps only to keys in a recipient's verified log. | sync service, key substitution | 1, Tamarin |
| L-16 | **Credential-ID binding (A-12).** No assertion is produced for RP B from a credential registered at RP A. | `MaliciousRP` | 1, Tamarin |
| L-17 | **Never locked out (G18).** In the two-phase change, at every step the vault holds a password the site's model accepts, under any interleaving of crashes, network loss and concurrent devices honoring the lease. | site and network faults | 1, Tamarin (the site modelled as a password store with a change endpoint) |
| L-18 | **Continuity-token unlinkability.** Redemptions at two RPs cannot be linked within the issuer's anonymity set; issuance does not depend on duress. | `MaliciousRP`, curious issuer with a single logged key | 1, ProVerif (equivalence) |
| L-19 | **Update acceptance.** An honest device installs only a build that is threshold-signed and present in the log. | minority of release keys | 1, Tamarin |
| L-20 | **Import containment (22.3).** An imported item enters the vault only as a device-signed item version; no import changes the log, quorum or policy; an imported origin is never filled or visited by a recipe before the principal consents at it; a merge never removes a value from item history. | malicious import source, sync service | 1, Tamarin |
| C-01 | **Tweak lemma (A-10).** ECDSA under `x + τ` with `τ` a PRF output under `cc` is unforgeable for an adversary without `cc`, given signing oracles for other tweaks; and the blind-tweak extension of Section 10.3 (the extra aff-p MtA, `S` points and abort-2 openings to the designated party only) keeps CGGMP21's security against the other signers and reveals nothing about `τ` to them. | -- | 2, paper proof or EasyCrypt |
| C-02 | **Vault construction.** The key derivation and AEAD of 18.1-18.3 give authenticated encryption with key separation per (vault, item, field, version). | -- | 2, CryptoVerif |
| C-03 | **Threshold ECDSA.** The chosen protocol's published security proof covers the variant implemented, including the designated party's tweak and output delivery to one party (6.2). | -- | 2, the paper's proof; any deviation needs its own proof |
| C-04 | **Credential-ID MAC.** HMAC truncation to 16 bytes gives the binding L-16 assumes. | -- | 2, standard PRF argument (paper) |
| L-21 | **Protected-item containment (G19).** An adversary holding one device's DK, share and `vault_key` obtains `pitem_key` for at most as many protected items as evaluations the quorum answered for that device; the kit before a recovery takes effect, and the cosigner, obtain none. | `RevealDK` + `RevealShare` of one device, `StealKit`, sync service | 1, Tamarin (the OPRF as an ideal functionality that answers only `t` parties of one epoch) |
| L-22 | **Evaluation blindness (G12).** An evaluating party cannot distinguish two evaluations of one item from evaluations of two items. | `CorruptCosigner` | 1, ProVerif (equivalence) |
| C-05 | **Threshold OPRF.** 2HashTDH over P-256 with RFC 9497's hashing, per-party batched DLEQ proofs and a joint Feldman key, combined as `HKDF(vault_key ‖ y)`, gives keys that are pseudorandom to any party lacking `vault_key` or `t` shares, and the culprit named on a failed proof is the party that cheated. | -- | 2, the published proof for 2HashTDH, plus a paper argument for the Feldman key and the combiner |

### 27.4 Abstractions

- The threshold ECDSA protocol appears in the symbolic models as an ideal
  functionality: it outputs a signature under `X + τ` exactly when `t`
  parties of one epoch request it with the same `m`, delivers it only to
  the initiator, and reveals `x` only if `t` shares are revealed. C-03
  justifies this.
- HPKE, AEAD, signatures and hashes are ideal (perfect) in layer 1 and
  justified by their standard proofs in layer 2.
- Out of every model: the user interface, page content and recipes beyond
  their slot and origin rules, side channels (covered by Section 23.3's
  constant-time gate, not by proof), the operating system, and hardware
  roots of trust (assumed per Section 3.2).

### 27.5 Deliverables and acceptance

- Models live in the repository under `models/`, one file per area
  (`log.spthy`, `recovery.spthy`, `duress.spthy`, `vault.spthy`,
  `sharing.spthy`, `rotation.spthy`, `fork.spthy`, `blindness.pv`, `unobservable.pv`),
  with the tool versions pinned.
- Every lemma is listed in `models/STATUS.md` as **verified**, **falsified**
  (with the attack trace and the specification change it led to), or
  **not yet attempted**. A falsified lemma blocks the release that claims
  it.
- A continuous-integration job re-runs every model on each change to the
  specification or the models; a lemma that regresses fails the build.
- Every security claim in documentation cites its lemma IDs. A claim with
  no verified lemma is not made.
- Each model ships with sanity lemmas (`exists-trace`) showing that the
  honest protocol can complete, so a verified safety lemma cannot be
  vacuous.
- Before any release that claims security, the models and the
  specification are reviewed by a party independent of their authors.

### 27.6 Order of work

1. `log.spthy` and `recovery.spthy`: L-01, L-05 to L-09. The red-team round
   found three critical holes in this area.
2. `duress.spthy`, `blindness.pv`, `unobservable.pv`: L-10 to L-12.
3. `vault.spthy`, `sharing.spthy`: L-13 to L-16, the malicious-server
   classes.
4. `rotation.spthy`: L-17.
5. C-01, C-02, C-04; choose the threshold protocol by the strength of the
   proof for C-03.
6. L-02, L-03, L-04, L-18, L-19, L-20.
7. L-21, L-22, C-05 (protected items, 18.10).

---

## 28. Open issues

1. Threshold ECDSA: the CGGMP21 line is chosen (Section 6.2). Open: an
   audited implementation strategy; the t-of-n construction (Shamir shares
   converted to additive shares for each signing subset) and the P-256
   instantiation of every proof; constant-time Paillier private operations.
2. Re-registration after removing a device that knew the chain code:
   automatic at next sign-in, or a separately keyed chain code held only
   by non-device parties.
3. Whether the duress sub-key (Section 14.3) can be made indistinguishable
   to the cosigner's operator as well as to the coercer.
4. Witness and issuer ecosystem; relation to IETF keytrans.
5. OS credential-provider availability per platform (not yet verified).
6. The verification programme of Section 27 (L-01 to L-20, C-01 to C-04)
   before any claim of security.
7. Legal review of duress (Section 14.5).
8. Defining capability sets in provenance records precisely enough for
   Section 17.4 to be a sound policy, not a label.
9. Recipe repository governance: who signs recipes, review, and how
   quickly a broken recipe is withdrawn.
10. Standardizing a machine-readable password-change endpoint and the
    rollover extension (26.5) with browser vendors and the W3C.
11. A proof (or a reference to an existing one) that ECDSA under the
    additive tweak of Section 10.3 is secure when `τ` is a PRF output.
12. A second red-team round over draft 2 (Appendix A's fixes introduce
    new mechanisms: the split kit, contests, rotator devices).
13. Protected items in collections and group folders (18.10.6): an OPRF key
    per collection would need a quorum spanning several principals' parties.
14. Whether the cosigner's limit on protected openings (18.10.4) should
    rise with a second device's approval, so that a large legitimate export
    is not throttled.

---

## 29. Organizations

An organization is a company whose people each keep their own Symbolon
identity (their own log, devices, cosigner and recovery) and who share
work secrets in **group folders**. Nothing in this section gives the
organization's server, or any one administrator, a person's keys (G9);
the one exception, opt-in per organization, is Section 29.8.

### 29.1 The organization record

```
org record = { org_id (16 random bytes), version, name,
               owners:  [ log-id ],
               admins:  [ { log-id, label } ],
               members: [ { log-id, label, ext_id } ],
               groups:  [ { group_id (16 bytes), name, members: [ log-id ] } ],
               policy, recovery, log_sequence, signer_log, signer, sig }
```

Owners, administrators, policy and recovery form the **governance
chain**: `orggov-<id>-<v>` for v = 1, 2, ..., version 1 signed by the
founder and each later version by an owner of the version before, over
`"symbolon v1 org gov"`. The org id is the first 16 bytes of
`SHA-256("symbolon v1 org" || founder log-id || nonce)`, so a device that
knows the org id and the founder (from its enrolment, 29.3) verifies the
whole chain with no history of its own, and a server cannot substitute
another organization. The membership record (`org-<id>`: members and
groups, and the governance version it was signed under, which must be the
latest) is signed over `"symbolon v1 org"` by a device of an owner or
administrator of that governance version. Every signature is checked
against the signer's verified log at a sequence already verified. Both
versions strictly increase; a device keeps the highest of each it saw
and refuses lower ones. `ext_id` is the directory's id for the person (SCIM `id`), so the
directory and the record can be matched; the record holds no e-mail
addresses or other directory attributes.

### 29.2 Group folders

A group folder is a shared collection (Section 19) whose people are the
members of one or more groups, not a list kept by its owner:

```
group folder = { coll_id, version, org_id, groups: [ group_id ],
                 name_ct, deleted, log_sequence, signer_log, signer, sig }
```

At the server as `gfolder-<id>`, signed over `"symbolon v1 group folder"`
by a device of an owner or admin in the current org record. Its people
are the members of its groups in the current org record, and every owner
and administrator (they re-key it when people leave, so they hold its
key). Wraps, items
and heads are as in Section 19 (`wrap-<log>-<id>`, `coll-<id>`), with the
group folder in place of the roster. When the org record moves on:

- a person added to a group gets the key from any device that holds it
  and opens the folder (as Section 19.2 adds wraps for new devices), at
  the current group folder version;
- a person no longer in any of its groups, or no longer a member, is
  removed by an admin device: a new key, every item sealed again, a new
  version citing the new org version, empty wraps for them. Until then the
  server already refuses them the folder's objects (29.4).

A group folder's vault head may be signed by any member of the
organization, not only its current people: the last writer may since
have left its groups, and until the next re-key the folder must still
open. An administrator device re-keying it takes the head from anyone
whose log verifies (the last writer may have left the organization), and
signs the new one itself. Residual risk until then: someone who left a
group still holds the old key and could write a version, which the
server's access control (29.4) refuses and the re-key seals again.

Group folders always survive any one person leaving, which is what makes
the strict model (no admin recovery) workable: work secrets belong in
them, not in personal vaults.

### 29.3 Enrolment and who is who

Comparing fingerprints (Section 19.3) does not scale to a company, so an
organization binds people to its directory instead, with invites. An
owner or administrator (or `org sync` for a new directory user, 29.7)
makes an invite `invite-<org>-<id>` for one directory id (`ext_id`), a
name and groups, good for 14 days by witness time, signed by their
device. The invite code is 16 random bytes; it is a key: the record holds
the P-256 public key of `SHA-256("symbolon v1 invite key" || code)` and
`id` is the first 16 bytes of `SHA-256("symbolon v1 invite" ||
public_key)`. The code reaches the person through the company (work
e-mail, device management, the console). Their device runs `org join ORG
FOUNDER CODE`: it verifies the governance chain (29.1), signs with the
code's key `"symbolon v1 accept" || org_id || log_id`, and stores the
answer `accept-<org>-<id>`, also signed by one of its devices. Neither the
server nor anyone who sees the answer learns the code. An administrator's
next `org sync` checks the invite (signed by an owner or administrator
of the current governance, unexpired), the code's signature and the
device's, adds the person with the invite's `ext_id`, name and groups in
one new membership record, and clears the invite and the answer. A code
answers once (the server keeps the first answer, 29.4); an answer to no
invite is ignored. Residual risk, stated: whoever holds the code first
becomes that directory person, as with any enrolment link; the binding
rests on how the company delivers codes. The app still shows
fingerprints, and an organization may require the comparison for
administrators.

### 29.4 Access at the server

The relay (an organization's, a household's, Symbolon Home's) signs
devices in and controls who writes what. Sign-in: the device fetches a
challenge (32 bytes the relay MACs with its time, good once for five
minutes), signs `"symbolon v2 relay auth " || NAME || "\n" || challenge`
with its DK, NAME being the relay as the device reaches it
(`HOST:PORT`, the host in lower case), and posts the challenge, its log
id, party id, signature and NAME. The relay takes only its own names
(`relay serve --name HOST:PORT[,...]`, and the console's origin), so a
relay cannot hand a device another relay's challenge and sign in there
as it; a relay started with no name takes any (and says so when it
starts). The relay verifies the log itself, from the events it stores
and at the time its witnesses sign (8.3), finds the device in the quorum
and checks the signature; it answers a bearer token for seven days, kept
by its SHA-256 with the log, party, the device's key and the length of
the log at sign-in. When the log has grown since, the relay verifies it
again before it honours the token, and the token is good only while its
device is still a device of the log with the same key: a device removed
from the quorum loses its sessions with the next event. Expired sessions
and used challenges are removed as devices sign in. A device signs in
again when its PIN unlocks it and its session is a day old, and before a
write when it has none; under the duress PIN it keeps the session it has
(signing in would need the real profile). (Version 1 signed `"symbolon
v1 relay auth" || challenge`, bound to no relay; a relay no longer takes
it, so devices and relay are upgraded together.)

The relay then serves:

- `orggov-` to any device signed in (joining needs it before membership);
- `org-<id>` and `gfolder-` to members of the organization;
- `audit-`, `invite-` and `accept-` to owners and administrators;
- a group folder's `coll-`, `roster-`, `wrap-` and `leave-` objects, to
  read and to write, only to the folder's people, so someone taken out of
  a group can no longer write with the old key before the next re-key;
- listings (`/list/`) without the names the caller may not read, a page
  at a time (`?after=`), so listings are no longer capped at 4096 names
  (each request reads at most eight store pages of keys).

Every write needs a signed-in device, but a cosigner's sealed alert
(`alrt-<log>-<time>-<nonce>`, which a cosigner writes without a session:
written once, never replaced, at most 64 KiB). A person's own objects
(`vault-<log>`, `kit-<log>-a`, `kit-<log>-secrets`, `kitv-<log>-a`,
`card-<log>`) are written only by a device of that log. A household
folder (19): its first roster makes its writer the owner, and only the
owner's devices write it after; its `coll-` and `wrap-` objects are
written by the owner's and the members' devices; `leave-<id>-<log>` by
that member, cleared by the owner. Wraps for an id with no roster yet (a
folder being made, a recovery share) are their writer's: only that log
replaces them. A name with no rule is refused. Mailboxes stay open to
anyone (cosigners and peers post without a session; messages are sealed
and a mailbox keeps its next index, so a post does not list it).

It verifies records before storing them: a governance version is written
once, in order, version 1 by the founder binding the org id and each
later one by an owner of the version before; a membership record under
the latest governance, by an owner or administrator, newer than the one
stored; a group folder by an owner or administrator, newer than the one
stored, never on an id that is already someone else's folder (a roster
or items whose owner is neither the signer nor a member: the first
record of an id wins); an audit event once, by its own device, from a
member; an answer to an invite once, by the device it names, with a
signature by the invite's code; an escrow only by the folder's owner (its
roster's), never over another's; a recovery request once (cleared before
another), with a time within five minutes of the relay's clock. Each
record's signer must be the device that signed in, so the relay checks
signatures with the key it verified at sign-in. A log an organization's
directory turned off (29.7) reads and writes nothing of that
organization's at once; it still signs in, and the suspension says
nothing about another organization or a household.

Access control is a second line only: every object is still verified on
the device, and the server can still withhold or serve stale objects
(down to what each device last saw). A household's relay works as before:
objects that are not an organization's keep the plain relay's rules.

### 29.5 Policy

The org record's `policy` binds every member device (it is signed, so
the server cannot weaken it):

```
policy = { min_pin_len, allow_biometric, allow_duress, allow_offline_copy,
           max_offline_days, allow_personal_export, require_attestation,
           password_rules }
```

A device in an organization refuses to join, and refuses every change,
with a PIN shorter than `min_pin_len` (default 4, the device minimum)
until the person changes it (`device pin`: the real profile sealed again
under the new PIN on the unprotected and Keystore profiles; on the TPM
profile the device key's and the real unlock key's authValue changed with
TPM2_ObjectChangeAuth, both made persistent again at a second handle and
the old ones evicted; the new PIN may not be the duress PIN). It does not
keep offline copies of group folders when `allow_offline_copy` is false
(and forgets them), reads a shared folder from its own copy no longer
than `max_offline_days` after it last reached the relay for that folder
(`share-<id>.seen`), and offers no duress choice for group folders when
`allow_duress` is false (Android device management can also hide the
setting, 29.9). `password_rules` is a comma list of `min=N`, `upper`,
`lower`, `digit`, `symbol`: a device refuses to save a password or secret
into a shared folder that breaks it. `require_attestation` names the
platform attestation kinds (Section 21) a member device must present;
`tpm` is the one defined:

- A device in the TPM profile sends its evidence (`attev-<org>-<party>`,
  signed by the device): its TPM's EK certificate, the chain the TPM
  stores plus any intermediates and CRLs the organization supplies, and
  the AK's public area (the TCG template AK, a primary key, so the same AK
  each time).
- An owner's or administrator's `org sync` answers with a credential
  challenge for that EK and AK (`attchal-`, TPM2_MakeCredential with a
  fresh challenge record kept on the administrator's device, sealed under a
  key from its vault key, used once). The device's next `org attest`
  activates it in its TPM and adds TPM2_Certify of its device key by the
  AK over `"symbolon v1 enroll"`, the challenge value and its log id
  (`attresp-`).
- The administrator's next sync verifies with Resid's TPM verifier: the
  EK chain to a TPM maker's root pinned in Resid, with a current CRL for
  every certificate below the root (a chain without one is refused as
  stale, never accepted), the AK in the TPM whose EK it is, and the device
  key the log names fixed to that TPM, signing only and usable only
  through its PIN policy (11.1, 21.1). The device's party then joins the
  membership record's `attested` list.

When the policy requires `tpm`, the relay serves group folders, the audit
log and the administrators' objects only to attested devices; an owner's
device cannot turn the requirement on until it is attested itself. A TPM
whose maker publishes no CRL for an intermediate cannot be attested until
it does (the STMicroelectronics STSAFE intermediate on the reference
machine publishes none: the exchange completes and is refused as stale).
Policy never reaches a person's own vault or passkeys beyond the PIN.

### 29.6 Audit

Each device appends events it signs, chained per device, to
`audit-<org>-<log>-<seq>`:

```
event = { org_id, log-id, party, seq, prev (SHA-256 of the previous event),
          time (witness time), action, object, detail }
```

`action` is one of `member`, `group`, `policy`, `share`, `item`,
`recovery`; `object` is an org, group or folder id, never a name; `detail`
holds no secret. Every change a member's device makes to a shared folder
is an `item` event with the folder's version and item count (item names
stay sealed). A gap in a device's chain, or two events with one `seq`,
shows that the server dropped or forked events; `org audit` and the
console mark such an event as broken.

`org export` sends the events, each verified on the exporting device
first, to a security monitoring system (SIEM) as JSON lines (`time, org,
log, seq, action, object, detail, verified, problem`): to standard
output, POSTed over HTTPS (`application/x-ndjson`, a bearer token, as
Splunk HEC and similar collectors take), or as RFC 5424 messages over
syslog with TLS (RFC 5425, octet counting) or TCP (RFC 6587). An
organization can run it on a schedule from an administrator's device.

### 29.7 Directory synchronization (SCIM)

The relay implements SCIM 2.0 (RFC 7643, RFC 7644) Users and Groups for
the company's identity provider (Okta, Microsoft Entra ID, Google
Workspace and others): create, read, filter (`userName`, `externalId`,
`displayName` eq), replace, patch (including Entra's string booleans and
`members[value eq "..."]` paths) and delete, with a bearer token the
server's operator makes (`relay scim-token DIR ORG`). A member's `ext_id`
names a directory user when it equals the user's `userName` (ignoring
case) or `externalId`. The server cannot sign the org record, so SCIM
changes act in two ways:

- at once, at the server (29.4): a user made inactive or deleted has every
  member log they name suspended in this organization
  (`suspended/<org>/<log>`), so their sessions read and write nothing of
  the organization's (one organization's directory cannot turn anyone
  off elsewhere); and a
  directory group that no longer lists a member takes away, at once, the
  group folders the member has only through the organization's group of
  that name (the directory can take away, never give: owners and
  administrators keep every group folder);
- in the signed record, when an owner's or administrator's device next
  runs `org sync`: it reads the directory (`GET /directory/<org>`, active
  users and groups), takes out members whose `ext_id` the directory no
  longer lists (members added by hand, without an `ext_id`, and owners
  stay; an administrator stays until an owner takes the role), sets the
  organization's group of each directory group's name to the members it
  lists (making the group when there is none), signs one new membership
  record, invites each directory user who is neither a member nor
  invited (29.3), and re-keys the group folders people left. An
  organization may run `org sync` on a schedule on a dedicated admin
  device (an automation administrator): an identity of its own, listed
  as an admin, whose devices hold the group folders' keys like any
  admin's. Owners decide whether to have one; it should not run on the
  server.

### 29.8 Recovery (opt-in)

By default no one can open a person's vault but that person (G9 holds).
An organization's owners may turn on recovery for **work folders** only
(`org recovery on K DELAY ADMIN,...`):

- The owner's device makes a recovery secret (a scalar below the P-256
  order), derives an HPKE P-256 key pair from it, splits the secret
  k-of-n with Shamir over the P-256 scalar field among the named recovery
  administrators (each an owner or administrator and a member), wraps
  each share to that administrator's devices as a folder key is wrapped
  (HPKE mode_auth, 19.1), and forgets the secret. The new governance
  version's `recovery` holds the public key, k, the administrators in
  share order, `delay_sec`, the governance version the shares were made
  at and the owner who wrapped them. Turning it on again makes a new key;
  escrows under the old one no longer open.
- A member escrows a shared folder they own (`org escrow CID`): its key
  sealed by HPKE base mode to the recovery public key, bound to the org,
  the folder and its roster version, signed by their device
  (`escrow-<org>-<cid>`). The person's own vault is never escrowed; group
  folders need none (owners and administrators hold their keys). After the
  folder's key changes the person escrows it again; an escrow of an older
  version does not open.
- A recovery administrator asks to open a folder (`org recover request`):
  a signed request with the witness time (`recreq-<org>-<cid>`). The
  time is only the requester's word, so the relay takes a request only
  within five minutes of its own clock and records, once, when it took it
  (`recat-<org>-<cid>-<h>`, h the first 16 bytes of SHA-256 of the
  request, written by the relay alone); a request is written once and
  cleared before another. The request opens at the later of its time and
  the relay's receipt, plus `delay_sec`. The
  folder's owner sees it at once in `org show` ("recovery-request CID
  REQUESTER OPENS-AT"), and it is audited. No earlier than that, by
  witness time, each approving administrator's
  device opens its own share and wraps it to the requester's devices
  (`org recover approve`). With k shares the requester's device rebuilds
  the secret, checks it gives the recorded public key, opens the escrow
  and reads the folder (`org recover open`); each step is an audit event.

The delay is enforced twice: approving devices refuse before the
opening time (by witness time), and the relay serves an escrow to anyone
but its owner only to a recovery administrator with a request of their
own whose delay, from the relay's receipt, has passed by the relay's
clock. A relay that lies about its receipt can shorten the delay only
for a requester who also controls it; witness signatures over the
request's hash would close that and are not yet in the format. A delay under
72 hours (259200 seconds) needs `--short-delay`, so an owner sets one
only on purpose. The owner's device escrows a folder again by itself
whenever it changes the folder's roster (people added or removed, a new
key), so an escrow follows the folder. Residual risk, stated: k
administrators acting together can read a person's escrowed work folders
after the delay; turning recovery on is visible to every member in the
signed governance.

### 29.9 Running at scale

The relay keeps everything in a store (`relay serve ... --store SPEC`):
a directory (the default; Symbolon Home), PostgreSQL
(`postgres://USER:PASSWORD@HOST:PORT/DB`) or an S3-compatible object
store (`s3://KEY-ID:SECRET@HOST:PORT/BUCKET?region=R`, HTTPS under
`--store-ca`); `@FILE` reads the specification from a file so a password
is not on a command line. Sessions, sign-in challenges, suspensions and
the SCIM directory live in the store too, so the relay holds nothing of
its own and several relay processes run behind a load balancer.

- PostgreSQL: one table `symbolon_objects (k text COLLATE "C" PRIMARY KEY,
  v bytea)`, made when a relay starts; a connection per request,
  authenticated with SCRAM-SHA-256 (the password never crosses the wire),
  the extended query protocol with binary parameters. Objects written
  once (log events, mailbox messages, audit events) use `INSERT ... ON
  CONFLICT DO NOTHING`, so one writer wins across relays. With
  `?sslmode=verify-full` and `--store-ca` the relay asks for TLS
  (SSLRequest) and runs TLS 1.3 on the same socket, the server's
  certificate checked for its address; each statement then has a
  connection of its own, and the SCRAM salted password is cached on the
  relay's disk so that costs a handshake, not a key derivation.
- S3: path-style requests signed with Signature Version 4; objects
  written once use `If-None-Match: *` (412 for the loser); listings use
  ListObjectsV2 with `start-after` and continuation tokens.
- A directory: an object written once is first claimed with an exclusive
  create (`O_EXCL`) of `.NAME.claim` beside it, which one writer wins; the
  winner writes the bytes to a temporary file and renames it onto the
  name, so a reader sees nothing or all of it. Claims stay (listings skip
  names starting with `.`); a writer that dies between its claim and its
  rename leaves the name claimed and empty until an operator removes the
  claim.

A mailbox index is the first free one from a kept hint (`mboxn/<to>`,
the number after the last message), written once, so two relays never
give out the same index. Witnesses run apart
from the relay, ideally in different places and operated by different
people (Section 13.4). The server is configured by the organization's
device management: Android managed configurations and iOS managed app
configuration carry the server address, the org id and an invite code,
and lock settings policy fixes. Device management carries no keys.

### 29.10 The administrator console

The relay serves a console at `/console/<org>` when it is given its origin
(`--console-origin https://HOST:PORT`; Symbolon Home sets it). Owners and
administrators sign in with a passkey:

- A browser registers a passkey at the console (ES256); the relay keeps it
  waiting for a day and shows a short code (the first 8 hex digits of the
  credential id's SHA-256). The administrator's own device approves that
  code (`org console-key`, or the app): it recomputes the code from each
  waiting credential id itself (the relay's pairing of code and key is not
  taken on its word), refuses when more than one waiting passkey has the
  code, shows the key's fingerprint (the first 16 hex digits of SHA-256 of
  the public key, as the browser can show it) and signs a record binding the
  credential and its public key to their log (`conkey-<org>-<id>`), which
  the relay stores only from that device's session and only for a passkey
  waiting with the same key. Waiting passkeys older than a day are removed
  as new ones register.
- Signing in is a WebAuthn assertion over a fresh relay challenge (once,
  five minutes): the client data's type, challenge and origin, the
  authenticator data's RP ID hash and user-presence flag, and the ECDSA
  signature under the approved key are checked; the person must still be an
  owner or administrator. The session is an HttpOnly, Secure, SameSite=Strict
  cookie for eight hours. The page loads no inline script (its policy allows
  only the console's own script).

The console shows the organization as the relay holds it (records the
relay verified when they were written: governance, policy, recovery,
people, groups) and the changes queued there. It changes nothing signed:
a change made in the console (invite, add to or remove from a group,
remove a person, a policy setting, a sync) is queued, and takes effect only
when an owner's or administrator's device approves it (`org changes`, `org
approve`, or the app's list): the device shows the change, signs it as it
would its own, and tells the console the result; the relay records which
administrator's log did (a ninth field, "BY-DONE", after the result). The
server holds no administrator key.

`org console DIR PORT` also serves a read-only page on the
administrator's own machine (127.0.0.1, behind a token) with everything
verified by that device, each audit event marked verified or broken.

---

## Appendix A. Red-team audit of draft 1

Adversarial review of draft 1, 2026-10-12. Severity: Critical (defeats a
core goal for a realistic attacker), High (defeats a goal under stated
conditions, or endangers the principal), Medium, Low.

| ID | Sev. | Finding | Fix (draft 2) |
|---|---|---|---|
| A-01 | High | The cosigner could receive the final signature; with `m` it could recover each credential's public key by ECDSA key recovery and link every use (breaks G12). | Signature delivered only to the initiating device (6.2, 12.2). |
| A-02 | Critical | A stolen kit plus one compromised device met `t = 2` and signed everything with no cosigner, delay or veto involved. | Kit material split with the cosigner and released only after an effective recovery (10.2, 10.6, 13.2). |
| A-03 | Critical | Refresh every 30 days put the offline kit's share in a dead epoch: recovery would silently stop working a month after setup. | Offline parties hold static keys; their current material is computed by the online parties and stored wrapped (10.6). |
| A-04 | High | A single device could sign authority events (if `policy[1] = 1`), evicting the others; a thief holding one device could veto every recovery forever; the DK was usable without unlock. | `policy[1] >= 2`, delayed single-signer events, weakening policy always delayed (8.2); DK gated on unlock (9.1); veto needs unlock; contested recoveries escalate (13.4). |
| A-05 | High | Duress wrote an event to the log and stopped continuity tokens: both observable by a coercer, endangering the principal. A sync service could suppress recovery notices. | No duress trace outside the cosigner (8.1, 14.2); tokens independent of duress (15); refusals look like faults (14.3); devices poll witnesses directly (13.4). |
| A-06 | Critical | The duress profile held the share and the chain code, so it could compute any credential's tweak and sign for it with the cosigner, which is blind to the credential. | Duress blob holds subset tweaks only, never `cc` (9.2, 14.3). |
| A-07 | High | Delays were measured by an advisory, signer-chosen time. | Witness time, majority of witnesses (8.3, 13.4). |
| A-08 | Medium | Assertion flags unspecified; UV could be asserted without verification. | Truthful BE/BS/UV/UP (10.4). |
| A-09 | High | Recipes: a compromised repository or recipe could direct secrets into visible fields, visit added origins, or click destructive controls; the AI fallback was available for every item. | Threshold-signed, logged recipes with a hold; origin intersection; typed slots; destructive list; fallback off by default and never for high-value items (26.4). |
| A-10 | Medium | Additive tweaks have related-key pitfalls; no analysis. | Requirement that `τ` stay unpredictable; proof listed as open (10.3, 27.3 C-01, 28). |
| A-11 | Medium | PCR-bound seals break on firmware updates, locking the principal out of a device. | `PolicyAuthorize` only; recovery path, never a weaker seal (9.1). |
| A-12 | High | A relying party could replay another relying party's credential ID; the encrypted ID was not bound to the request's RP ID. | MAC'd credential ID checked against the request's RP ID (10.3). |
| A-13 | Medium | Verifier-constrained release checked one entry point's capabilities, which shared state bypasses; it risked being presented as a guarantee. | Whole-program capability set, declassification points, secret typing, marked experimental (17.4). |
| A-14 | High | A removed device could sign an acceptable vault head by citing an old log sequence; a new device's first vault state came from the untrusted service. | Signer must be in the verifier's current quorum (18.4); new device anchored to the enrolling device's heads (11.1). |
| A-15 | Critical | No rule for agent updates: one malicious update compromises every principal. | Threshold-signed, transparency-logged, reproducible updates; peers pin builds (21.4). |
| A-16 | Low | Co-signing requests were replayable. | Session identifiers (10.4). |
| A-17 | Medium | Verification sign-ins could trigger site lockouts; concurrent rotations on two devices could leave the site's state unknown; rotation assumed vault access while locked. | Rationed attempts, per-item lease, rotator role (26.1, 26.3). |
| A-18 | Medium | A continuity-token issuer could deanonymize with per-principal keys. | One logged key per epoch; agents check (15). |
| A-19 | Medium | Rollover after a root-key compromise races the attacker. | Rollover only while the key is uncompromised; relying-party recovery otherwise (26.5). |
| A-20 | High | Second pass, on the contest rule: one device against a stolen kit, without guardians, is undecidable, and the rule awards it to the kit. | Stated; setup recommends guardians, a second device and a kit passphrase (13.4). |
| A-21 | Low | Second pass: writes to the duress blob at each epoch would reveal that a duress profile exists. | Devices without one rewrite the random blob on the same schedule (9.2). |

Not changed, accepted as residual (24.2): cosigner plus one compromised
unlocked device meets `t = 2`; threshold-ECDSA implementation risk;
timing correlation by a colluding cosigner and relying party; recipes as
a supply chain; inferable duress.

