# Prior art

Compiled 2026-10-12 from web searches and the Resid repository. This is a
starting point for a professional prior-art search, not a substitute for
one. Every mechanism in SPEC.md is listed with the closest known prior work.

## Component by component

| SPEC section | Mechanism | Closest prior art | Source |
|---|---|---|---|
| 8 | Append-only signed key-event log with pre-rotation (digest of the next keys committed in the current event); witnesses | KERI (Smith): pre-rotation, key event receipt logs, witnesses | [arXiv 1907.02143](https://arxiv.org/pdf/1907.02143), [draft-ssmith-keri](https://datatracker.ietf.org/doc/html/draft-ssmith-keri), [ToIP KERI v1.1 (2026-01-21)](https://trustoverip.org/wp-content/uploads/KERI-V1.1-2026-01-21.pdf) |
| 8, 10 | Per-device keys in a signature chain; paper keys as backup devices; existing device provisions a new one over a server relay authenticated by a shared offline secret; per-user key rolled on revocation | Keybase sigchain, paper keys, KEX, PUK | [Keybase KEX](https://book.keybase.io/docs/crypto/key-exchange), [Keybase PUK](https://book.keybase.io/docs/teams/puk), [Keybase account](https://book.keybase.io/account) |
| 9 | Password stretched locally with Argon2id | Bitwarden (Argon2id option, OWASP parameters) | [Bitwarden KDF algorithms](https://bitwarden.com/help/kdf-algorithms/) |
| 9.3 | Password never reaches the server; uncrackable verifier | 1Password Two-Secret Key Derivation + SRP; OPAQUE (RFC 9807) | [1Password SRP](https://1password.com/blog/developers-how-we-use-srp-and-you-can-too), [1Password white paper](https://1password.com/files/1password-white-paper.pdf), [RFC 9807](https://www.rfc-editor.org/rfc/rfc9807.html) |
| 10, 11, 18 | Device-bound keys in the TPM; access only from devices meeting a posture policy | Beyond Identity (vendor claims) | [Device Trust](https://www.beyondidentity.com/products/device-trust), [Binding identity to device](https://www.beyondidentity.com/resource/binding-identity-to-device) |
| 11 | Origin-bound public-key authentication; device-bound vs synced passkeys | WebAuthn / FIDO2; NIST SP 800-63-4 (July 2025) | [arXiv 2501.07380](https://arxiv.org/html/2501.07380v1), [Thoughtworks Radar](https://www.thoughtworks.com/radar/techniques/passkeys) |
| 11, 18 | Authenticator attestation; enterprise attestation with per-device serial | WebAuthn attestation formats (packed, tpm) | [Yubico guidance](https://developers.yubico.com/Passkeys/Passkey_relying_party_implementation_guidance/Attestation), [w3c/webauthn PR 1954](https://github.com/w3c/webauthn/pull/1954/files) |
| 12.1 | Browser session cookies bound to a TPM key | Chrome DBSC (Chrome 146, Windows, April 2026) | [Google](https://blog.google/security/protecting-cookies-with-device-bound-session-credentials/), [Help Net Security](https://helpnetsecurity.com/2026/04/10/google-chrome-device-bound-session-credentials) |
| 12.2 | Sender-constrained OAuth tokens | DPoP, RFC 9449 | [RFC 9449](https://rfc-editor.org/rfc/rfc9449) |
| 13 | Selective disclosure; unlinkable presentations | SD-JWT, ISO mdoc, EUDI wallet; BBS (draft-irtf-cfrg-bbs-signatures-12, Sept 2026); device-bound anonymous credentials | [BBS draft](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-12.html), [EUDI privacy analysis](https://orbilu.uni.lu/handle/10993/66335), [AEPD](https://www.aepd.es/en/press-and-communication/blog/eidas2-the-eudi-wallet-and-the-gdpr-ii), [ePrint 2025/1995](https://eprint.iacr.org/2025/1995.pdf) |
| 14 | Vault design against a malicious server: whole-vault integrity, key separation, no downgrade, authenticated keys | The anti-patterns are catalogued in Scarlata, Torrisi, Backendal, Paterson (USENIX Security 2026); the paper discusses mitigations | [ePrint 2026/058](https://eprint.iacr.org/2026/058), [USENIX](https://www.usenix.org/conference/usenixsecurity26/presentation/scarlata) |
| 14.4 | Merkle tree commitment with domain-separated leaves | Certificate Transparency (RFC 9162) | -- |
| 15 | Authenticated public keys for sharing; key transparency | IETF keytrans (draft-ietf-keytrans-architecture-09, June 2026); Dashlane evaluating key transparency | [keytrans architecture](https://datatracker.ietf.org/doc/html/draft-ietf-keytrans-architecture-09), [Dashlane](https://www.dashlane.com/blog/zero-knowledge-malicious-server) |
| 17.3 | Guardian / social recovery, threshold approvals, Shamir backups | Ethereum social-recovery wallets; SLIP-39; SoK on web authentication with E2EE | [arXiv 2406.18226](https://arxiv.org/pdf/2406.18226) |
| 17.4 | Recovery delay with veto | Social-recovery wallets commonly use timelocks (not verified in a primary source this session) | -- |
| 17.5 | PIN-protected backup with guess limit in attested enclaves | Signal SVR3 (OSDI 2024) | [OSDI 24](https://www.usenix.org/conference/osdi24/presentation/connell), [ePrint 2024/887](https://eprint.iacr.org/2024/887) |
| 19.2 | Fill only after gesture outside the page | Mitigations for DOM-based extension clickjacking (DEF CON 33) | [The Hacker News](https://thehackernews.com/2025/08/dom-based-extension-clickjacking.html) |
| 20.2 | Security properties as types (opaque "verified" types) | Language-based security in general; Resid's own `Trust` / `Verified(Claims)` (public, MIT) | [Resid](https://github.com/larrydewey/Resid) |

Patents surfaced by one search (none covered the combination; not read in
full): [US9769167B2](https://patents.google.com/patent/US9769167B2/en),
[US8667265B1](https://patents.google.com/patent/US8667265),
[WO2016154001A1](https://patents.google.com/patent/WO2016154001A1/en),
USPTO "Binding with cryptographic key attestation"
([11750384](https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/11750384),
[12113898](https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/12113898)).

## What may be new

Every individual mechanism above has prior art. Candidates for novelty lie
in specific combinations and in the enforcement method, and each needs a
professional search:

1. Recovery that restores *identity* through guardian approvals over a
   pre-rotated key-event log, separately from *data*, which guardians can
   restore only through opt-in shares released after an unvetoed delay
   (SPEC 17.3-17.4).
2. Enrollment of a new device gated on attestation of both the hardware
   key and the agent's build provenance, verified by an existing device
   against the principal's own policy (SPEC 10.1, 18).
3. A password vault whose head is signed by keys reached only from the
   owner's key-event log, with parameters fixed by format version
   (SPEC 14.4 with 8).
4. Enforcing the malicious-server anti-patterns as compile-time type and
   capability errors in the implementation language (SPEC 20.1-20.2). Note
   that Resid, which already contains the pattern, is public.

Under U.S. law (KSR v. Teleflex), a combination of known elements that
yields predictable results is likely obvious, so items 1-3 are uncertain.
Software claims also face eligibility review under Alice v. CLS Bank.
