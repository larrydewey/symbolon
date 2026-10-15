# Plan: threshold ECDSA in Resid (CGGMP21 over P-256)

Decision: the CGGMP21 line (SPEC Section 6.2, 2026-10-14). This file is the
implementation and verification plan. Nothing here is a security claim; a
layer is "done" only when its gate below passes.

## Where the code lives

The cryptography is Resid standard-library code in the Resid repository
(`lib/`), with its tests in `tests/crypto/` and its constant-time cases in
`tests/ct/`, because Symbolon needs it and so would anyone else. Symbolon's
`src/threshold/` holds only the protocol glue: sessions, the quorum, epochs
and the tweak. Nothing is written in another language except test oracles.

## Layers

| # | Layer | Resid module (planned) | Gate |
|---|---|---|---|
| 1 | Big integers: add, sub, mul, divmod, shifts, modular exponentiation (Montgomery), inverse, gcd, Miller-Rabin, random below, bytes | `lib/bignum.resid` | Differential tests against Python `int` over thousands of random and edge cases (zero, one, limb boundaries, equal operands, 2048- and 4096-bit) |
| 2 | Safe-prime and Blum-prime generation (takes random bytes as a parameter) | `lib/bignum.resid` | Every output prime checked by OpenSSL `prime -safe` and by Python |
| 3 | Paillier (keygen, encrypt, decrypt, homomorphic add and scalar multiply, rerandomize) and Pedersen commitments | `lib/paillier.resid` | Python reference implementation of the same maths; ciphertexts from each decrypt in the other; Taurus `pkg/paillier` as a second oracle |
| 4 | P-256 point and scalar API for protocols (add, scalar multiply, scalar field, hash-to-scalar) | `lib/p256.resid` (extend) | OpenSSL and Python `cryptography` |
| 5 | Shamir sharing and Feldman commitments over the P-256 scalar field; Lagrange; Shamir-to-additive conversion for a signing subset | `lib/shamir.resid` | Python reference; reconstruct equals the secret for every subset |
| 6 | Zero-knowledge proofs, each with prover and verifier: mod, prm, fac, enc, aff-g, log*, dec (and the rest the protocol calls) | `lib/cggmp_zk.resid` | A proof made by the Resid prover verifies in the Go verifier and the reverse, on the same transcript hash; a tampered proof or statement is refused |
| 7 | Protocol: key generation with auxiliary info, presigning with identifiable abort, signing, proactive refresh, re-share, additive tweak by a designated party | `lib/cggmp.resid` | The final signature verifies under OpenSSL ECDSA for the joint key, for every `t`-of-`n` up to 8, after refresh and re-share; every abort path names the cheater |
| 8 | Constant-time work: secret-typed Paillier and scalar paths | `tests/ct/` | valgrind probe clean, or a named, reviewed `declassify` |
| 9 | Symbolon glue: `src/threshold/`, tweak, epochs, session identifiers, delivery of `s` to the initiator only | `symbolon-resid/src/threshold/` | Models in `models/` stay consistent with the interface |

## Oracles

- **Python** (`int`, `cryptography`, `hashlib`): bignum, Paillier, Shamir,
  P-256, final signatures. A second implementation written independently of
  the Resid code, used only to generate expected values.
- **OpenSSL** (`openssl prime`, `openssl dgst -verify`): primality and
  signature verification.
- **Taurus multi-party-sig** (Go, a CGGMP21 implementation, cloned from
  github.com/taurusgroup/multi-party-sig): the proof statements and
  parameters as implemented and reviewed there. It supports secp256k1 only
  and hashes its transcripts with BLAKE3-based code, so for interoperability
  a local fork adds a P-256 curve and a SHA-256 transcript hash. The fork is
  an oracle, never a dependency.
- The paper (ePrint 2021/060) is the primary source; where Taurus and the
  paper differ, the difference is written down here and decided, not guessed.

## What this will cost

Taurus's equivalent (Paillier, Pedersen, the seven proofs, key generation,
presigning, signing) is about 7,000 lines of Go. A Resid version with
differential tests is of the same order, built layer by layer, and each
layer is committed only after its gate passes.

## Known residual risks (to be carried into SPEC 24.2 as they are found)

- Paillier private operations are hard to make constant-time; layer 8 may end
  with a named, reviewed `declassify` rather than a clean probe.
- Safe-prime generation is slow on a phone; it is a once-per-epoch cost to be
  done ahead of time, and the proofs of Paillier-Blum modulus and no small
  factors are mandatory, never skipped (SPEC 6.2).
- The extension from CGGMP21's native n-of-n to the t-of-n that Symbolon
  needs, and the tweak by one designated party, are Symbolon's design on top
  of the protocol; they need their own review and models (SPEC 27, C-01).

## Status (2026-10-14)

| Layer | State | Evidence |
|---|---|---|
| 1 Big integers | done (public values, variable time) | `tests/crypto/bignum_test.resid`: 55 blocks against Python `int` |
| 2 Safe primes | done | `safe_primes_test.resid`: results equal an independent Python search over the same streams; every prime passes `openssl prime -safe` (about 6 s for 1024 bits) |
| 3 Paillier | done (Pedersen not yet) | `paillier_test.resid`: 1024- and 2048-bit moduli against a separate Python Paillier |
| 4 P-256 scalar and point API | done (public values) | `p256ops_test.resid`: against a Python P-256 that is itself checked against `cryptography` |
| 5 Shamir, Feldman, Lagrange, additive conversion | done | `shamir_test.resid`: 1-of-1 to 8-of-8, wrong shares, wrong ids, short subsets |
| 6 Zero-knowledge proofs | done: prm, mod, fac, enc, aff-g, aff-p, log*, enc-elg, elog, log, sch, prover and verifier, both directions | `cggmp_zk_test.resid` (32 tests, Taurus-made proofs checked by Resid, tampering refused); `cggmp_oracle/interop.py` and `interop_proofs.py` (Resid-made proofs checked by Taurus: 9 kinds x 3 keys, tampering refused); transcript framing as Taurus with a SHA-256 output stream |
| 7 Protocol | done for the Symbolon scope: keygen, refresh, presign, signing, t-of-n re-share to a new set, hidden additive tweak, initiator-only delivery, and identifiable abort all have Resid tests or end-to-end OpenSSL oracles. Re-share scalar core, round-1 dealer transport (Feldman + Paillier parts + Nth nonce proofs), announcement proofs (mod/prm), assembly, complaint openings, and harness are in `lib/cggmp_reshare*.resid`; tweak and delivery in `lib/cggmp_tweak.resid`, `lib/cggmp_delivery.resid`. Layer 8 constant-time is still open. | `cggmp_reshare_test.resid` (12), `cggmp_reshare_harness_test.resid` (3), `cggmp_tweak_test.resid` (2), `cggmp_delivery_test.resid` (3), `cggmp_oracle/run_all.sh`, `cggmp_oracle/reshare.py`, `tweak.py`, `delivery.py`, `session.py`, `keygen.py` |
| 8 Constant time | baseline CT gate green (79 cases, 0 failures); real secret paths now exist: `cggmp_secret_types.resid` (private storage), `cggmp_secret_config.resid` (secret material tweak and byte conversions), `cggmp_secret_protocol.resid` (private CGGMP context), `cggmp_secret_scalar.resid` (P-256 scalars), and `cggmp_secret_paillier.resid` (masked Paillier, N up to 1024 bits), all without production declassification and covered by CT cases. They are not wired into CGGMP. CGGMP21 private material (`CgConfig.ecdsa`, `.elgamal`, Paillier `p/q`, RID/chain key) remains public `List(UInt(64))` in the reference implementation. No CGGMP `declassify` exists and no `Secret(T)` is silently converted; this code is test/oracle-only. Production secret-typed Paillier for 2048-bit N and protocol-state paths remain open and are a release blocker. | `tests/ct/run.sh`; secret modules above; no `declassify` in `lib/cggmp*.resid` |
| 9 Symbolon glue | not started | |

Wide integers in lists: the runtime boxes a wide integer put in a list only up
to 512 bits (`resid_box_u512`), so scalars held in lists are `UInt(256)`;
`UInt(576)`, the width `p256.resid` computes in, has no box.
