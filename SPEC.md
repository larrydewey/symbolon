# Symbolon: A Credential Agent for Continuity of Control

**Draft 2 -- 2026-10-12 (red-team revision, see Appendix A). Confidential (see NOTICE.md).**

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
27. Open issues

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
| Local stretching | Argon2id (RFC 9106), m = 256 MiB, t = 3, p = 1 |
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

Candidate families are the oblivious-transfer-based DKLs line and the
CGGMP line; the choice is open (Section 27). Published attacks on
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

### 8.4 Monotonicity

Each agent and the cosigner store the highest head they have verified per
log. A lower sequence, or the same sequence with another digest, is a fork
(Section 20.4).

---

## 9. Local unlock and duress

### 9.1 Unlock

```
pin_stretch = Argon2id(pin, salt_local, m, t, p)
hw_secret   = TPM2_Unseal(blob, PolicyAuthValue(pin_stretch) [& PolicyPCR(boot PCRs)])
unlock_key  = HKDF(hw_secret, salt_local, "symbolon v1 unlock", 32)
```

`unlock_key` decrypts the device's share, chain code, vault keys and DEK.
The TPM's lockout limits PIN guesses. The DK MUST be usable only after
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

### 9.3 Lock

On lock, auto-lock (RECOMMENDED 15 minutes idle), session lock or suspend,
the agent MUST wipe `unlock_key`, the share and every derived secret.

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
item (Section 27, A-10).

In signing, the designated device party adds `τ` to its additive share
inside the protocol; no other party learns `τ` or `P`. Because the tweak
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
26.5, Section 27), since D could link them. Vault keys are rotated (Section 18.6).

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
whose digest is in the log's field 6, and an HPKE key. To recover, a new
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

A `recover` by path 2 carries COSE_Sign1 approvals over `H(payload)` from
`policy[4]` guardians, each verified against that guardian's own log
head. A guardian's agent MUST show the requester's attestation summary and
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
- **Release.** The cosigner MUST NOT release its half of the kit's
  material, or take part in any session with the recovering device, until
  the event carries co-signatures from a majority of the policy's witnesses
  whose witness time is at least the delay in the past.
- **Veto.** A veto is signed by the DK of a device in the quorum preceding
  the event, which requires that device to be unlocked (Section 9.1). A
  thief with a locked device therefore cannot veto.
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
   (A-05);
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
- guardians named in the policy are notified, through their own agents.

Refusals during duress MUST look like ordinary transient failures (the
same errors and timing as an unreachable cosigner), so the coercer cannot
tell a refusal from a network fault. This cannot be made perfect: a
coercer who demands a new device enrollment and watches it fail
repeatedly may infer duress.

Without a cosigner, containment is enforced by the other devices alone:
they refuse to co-sign authority events with the duress device's sub-key
(which they learn at setup), and the duress profile still cannot sign
outside the subset.

### 14.4 Limits

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
item_key  = HKDF(vault_key, vault_id, "symbolon v1 item" || item_id, 32)
field_key = HKDF(item_key, nil, "symbolon v1 field" || field_name || u64(item_version), 32)
nonce     = HKDF(item_key, nil, "symbolon v1 nonce" || field_name || u64(item_version), 12)
```

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

### 18.3 Encryption

`aad = CBOR([1, vault_id, item_id, item_version, kind, field_name])`;
`ct = AES-256-GCM(field_key, nonce, plaintext, aad)`.

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
and the suite is format version 1's (G6-G8). KDF parameters are never read
from storage. Partial fetches carry inclusion proofs; absence is never
deletion without a head proving it.

### 18.5 Duress

The duress profile holds its own vault key covering only items with
field 5 set, re-encrypted under it, so the duress device cannot decrypt
anything else.

### 18.6 Rotation

After removing a device or a member, suspected compromise, or ending
duress: new `vault_key`, re-encrypt everything with incremented versions,
new head, wrap to current parties only.

### 18.7 TOTP

Computed in the core (RFC 6238); the seed never leaves it.

---

## 19. Sharing

A shared collection is a vault with its own key whose members are
principals. A member's DEKs MUST come from the member's verified log head,
checked against the policy's witnesses or a fingerprint compared out of
band (G5); never from the sync service alone. The collection key is
wrapped with HPKE mode_auth, `info = "symbolon v1 share" || vault_id ||
member log-id || u64(vault_version)`. The recipient MUST verify that the
sender key used by mode_auth belongs to a device in the sender's verified
log head. Removing a member rotates the key.

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

### 20.3 Witnesses

Witnesses co-sign `(log-id, seq, digest)` and refuse a second digest for
the same `(log-id, seq)`. Agents and the cosigner MUST require a
majority of the policy's witnesses on `recover`, delayed and `reshare`
events and on heads they release material against, and SHOULD require
them on all heads. A policy MUST name at least three witnesses run by
independent operators.

### 20.4 Fork and freeze detection (G17)

Parties exchange their highest verified heads at every contact and alarm
on a fork. A party that sees no newer witnessed head within a configured
interval warns that it may be frozen.

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

### 22.2 Consent outside the page (G14)

No credential, code or attribute is released into a page without a gesture
in agent-owned interface outside the page's DOM showing the origin (and
frame origin) as the browser or OS reports it. No fill on in-page clicks;
no fill into frames of another origin. The clipboard is avoided; where
used, content is marked sensitive and cleared within 30 seconds.

### 22.3 Credential exchange

The agent implements FIDO CXP/CXF (when final) for **import**, converting
imported keys to the Synced profile and offering re-registration as
Threshold. Threshold credentials are **not exportable** (Section 10.3); an
export produces a list of RPs to re-register at, never a private key.

### 22.4 Applications

Local socket readable only by the principal's user, peer authenticated by
process credentials; the agent shows which executable asks.

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

### 23.4 What Resid lacks (checked 2026-10-12)

| Missing | Needed by |
|---|---|
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
| G9 | No party holds `x`; guardian shares opt-in | 10, 13 |
| G10 | Delay and veto | 13.4 |
| G11 | Duress profile and containment | 14 |
| G12 | Cosigner receives only `m` and epoch | 12.2 |
| G13 | DBSC, DPoP | 16 |
| G14 | Consent outside the DOM | 22.2 |
| G15 | Secret types, ct gate, secret mode, mlock | 23.3 |
| G16 | Selective disclosure; verifier-constrained release | 17 |
| G17 | Head exchange; witnesses | 20 |
| G18 | Rotation triggers, two-phase change, recipes, rollover | 26 |

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
- Duress protection is bounded (Section 14.4).
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
}

step = [0, url: tstr]                        ; navigate (must be in field 5)
     / [1, selector: tstr, value: slot]      ; fill
     / [2, selector: tstr]                   ; click
     / [3, condition]                        ; expect: URL, element, or text present/absent
     / [4, passkey-register: true]           ; run the site's passkey registration (26.6)

slot = "username" / "old" / "new" / "totp"
```

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
  into password inputs, `totp` into one-time-code inputs, `username` into
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

## 27. Open issues

1. Choice of threshold ECDSA protocol (DKLs line vs. CGGMP line), and an
   audited implementation strategy.
2. Re-registration after removing a device that knew the chain code:
   automatic at next sign-in, or a separately keyed chain code held only
   by non-device parties.
3. Whether the duress sub-key (Section 14.3) can be made indistinguishable
   to the cosigner's operator as well as to the coercer.
4. Witness and issuer ecosystem; relation to IETF keytrans.
5. OS credential-provider availability per platform (not yet verified).
6. Formal models (Tamarin/ProVerif) of Sections 8, 10-14 and 18 before any
   claim of security.
7. Legal review of duress (Section 14.4).
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
| A-10 | Medium | Additive tweaks have related-key pitfalls; no analysis. | Requirement that `τ` stay unpredictable; proof listed as open (10.3, 27). |
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

