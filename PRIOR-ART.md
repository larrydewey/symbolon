# Prior art

Compiled 2026-10-12 from web searches and the Resid repository. This is a
starting point for a professional prior-art search, not a substitute for
one. Section numbers refer to SPEC.md draft 1.

## Mechanism by mechanism

| SPEC | Mechanism | Closest prior art | Source |
|---|---|---|---|
| 8 | Append-only signed key-event log; pre-rotation; witnesses | KERI | [arXiv 1907.02143](https://arxiv.org/pdf/1907.02143), [draft-ssmith-keri](https://datatracker.ietf.org/doc/html/draft-ssmith-keri), [ToIP KERI v1.1](https://trustoverip.org/wp-content/uploads/KERI-V1.1-2026-01-21.pdf) |
| 8, 11 | Per-device keys in a signature chain; backup keys as devices; provisioning over an untrusted relay | Keybase sigchain, paper keys, KEX, PUK | [KEX](https://book.keybase.io/docs/crypto/key-exchange), [PUK](https://book.keybase.io/docs/teams/puk), [account](https://book.keybase.io/account) |
| 9 | Local Argon2id; password never sent to server | Bitwarden; 1Password 2SKD + SRP; OPAQUE (RFC 9807) | [Bitwarden KDF](https://bitwarden.com/help/kdf-algorithms/), [1Password SRP](https://1password.com/blog/developers-how-we-use-srp-and-you-can-too), [RFC 9807](https://www.rfc-editor.org/rfc/rfc9807.html) |
| 10 | Passkey whose key is split between parties (two-party ECDSA) | Larch: two-party FIDO2 signing with a log server, ~150 ms; stateless two-party ECDSA for FIDO2 with a helper ("passkeys_mpc"), ~100 ms | [Larch, OSDI 2023](https://www.usenix.org/conference/osdi23/presentation/dauterman), [ePrint 2025/1475](https://eprint.iacr.org/2025/1475.pdf) |
| 10, 11 | t-of-n threshold ECDSA, resharing to new thresholds, proactive refresh | MPC wallets (DKLs19/DKLs23, CGGMP21); Web3Auth resharing | [Web3Auth](https://web3auth.io/docs/infrastructure/mpc-architecture), [cheatsheet](https://cheatsheets.davidveksler.com/mpc-wallet-architecture.html), [arXiv 2607.08226](https://arxiv.org/pdf/2607.08226), [USPTO 12580774](https://image-ppubs.uspto.gov/dirsearch-public/print/downloadPdf/12580774) |
| 10.3 | Additive, unhardened key derivation from a chain code | BIP32 non-hardened derivation (general knowledge; not searched this session) | -- |
| 11, 12 | Logging every login so a compromised device leaves evidence; server blind to the RP | Larch | [Larch](https://www.usenix.org/conference/osdi23/presentation/dauterman) |
| 5.2, 10 | Device-bound vs synced passkeys; providers as single point of failure | Büttner & Gruschka 2025; W3C devicePubKey / supplementalPubKeys (2023) | [arXiv 2501.07380](https://arxiv.org/html/2501.07380v1), [W3C PR](https://lists.w3.org/Archives/Public/public-webauthn/2023Nov/0093.html), [diff](https://github.com/w3c/webauthn/commit/431fd4edfa285d253472afe279b7ef5e9455b8f4.diff) |
| 11 | RP-side revocation signals | WebAuthn Signal API (per RP, RP-initiated) | [Chrome docs](https://developer.chrome.com/docs/identity/webauthn-signal-api) |
| 13 | Guardian recovery, Shamir backups, timelocks | Social-recovery wallets; SLIP-39; SoK web authentication and recovery (PoPETs 2025) | [PoPETs 2025](https://www.petsymposium.org/popets/2025/popets-2025-0113.php), [arXiv 2406.18226](https://arxiv.org/pdf/2406.18226) |
| 13 | Backup credentials registered in advance for WebAuthn recovery | ARKG (Yubico proposal; later analyses) | [ePrint 2023/1575](https://eprint.iacr.org/2023/1575) |
| 13 | PIN-protected backup with guess limits in attested enclaves | Signal SVR3 | [OSDI 2024](https://www.usenix.org/conference/osdi24/presentation/connell) |
| 14 | Duress passwords, silent alarms | Stefanov & Atallah 2010; PAM Duress; ITU survey; coercion-resistant authentication | [ITU](https://pure.itu.dk/en/publications/the-password-you-hope-you-never-use-use-cases-for-duress-authenti/), [MIT Tech Review](https://www.technologyreview.com/s/601445/how-to-make-passwords-that-cannot-be-compromised-by-torture-or-coercion), [Bitwarden forum](https://community.bitwarden.com/t/plausible-deniability-a-way-to-offer-more-protection-over-passwords/11425?page=2) |
| 14 | Decoy (honey) vaults and attacks distinguishing them | Kamouflage, NoCrack, honey encryption; USENIX Security 2025 classifier attacks | [USENIX Sec 2025](https://www.usenix.org/conference/usenixsecurity25/presentation/cheng-haibo), [USENIX Sec 2021](https://www.usenix.org/conference/usenixsecurity21/presentation/cheng-haibo) |
| 15 | Unlinkable tokens from attestation or authentication | Privacy Pass (RFC 9576-9578) | [RFC 9576](https://datatracker.ietf.org/doc/rfc9576/) |
| 15 | Unlinkable revocation for FIDO and anonymous credentials | Verheul 2016; Braavos accumulators; TU Wien thesis on FIDO | [ePrint 2016/217](https://eprint.iacr.org/2016/217), [ePrint 2017/043](https://eprint.iacr.org/2017/043), [TU Wien](https://repositum.tuwien.at/handle/20.500.12708/2174) |
| 16 | Hardware-bound browser sessions; sender-constrained tokens | Chrome DBSC (April 2026); DPoP (RFC 9449) | [Google](https://blog.google/security/protecting-cookies-with-device-bound-session-credentials/), [RFC 9449](https://rfc-editor.org/rfc/rfc9449) |
| 17.1-17.3 | Selective disclosure, unlinkability | SD-JWT, mdoc, EUDI wallet critiques; BBS draft; device-bound anonymous credentials | [BBS -12](https://www.ietf.org/archive/id/draft-irtf-cfrg-bbs-signatures-12.html), [EUDI analysis](https://orbilu.uni.lu/handle/10993/66335), [AEPD](https://www.aepd.es/en/press-and-communication/blog/eidas2-the-eudi-wallet-and-the-gdpr-ii), [ePrint 2025/1995](https://eprint.iacr.org/2025/1995.pdf) |
| 17.4 | Releasing data only to attested, verified code | Project Oak transparent release; in-enclave privacy-policy checking; semantic remote attestation (2004, general knowledge) | [Google](https://security.googleblog.com/2023/06/bringing-transparency-to-confidential.html), [arXiv 2007.10513](https://arxiv.org/pdf/2007.10513) |
| 18 | Malicious-server anti-patterns in password managers | Scarlata, Torrisi, Backendal, Paterson (USENIX Security 2026) | [ePrint 2026/058](https://eprint.iacr.org/2026/058) |
| 19 | Key transparency | IETF keytrans | [architecture -09](https://datatracker.ietf.org/doc/html/draft-ietf-keytrans-architecture-09) |
| 22.2 | Clickjacking of autofill extensions | DEF CON 33 (Tóth) | [The Hacker News](https://thehackernews.com/2025/08/dom-based-extension-clickjacking.html) |
| 26.1 | Change passwords on evidence of compromise, not periodically | NIST SP 800-63B-4 (secondary summaries) | [Enzoic](https://www.enzoic.com/blog/nist-sp-800-63b-rev4/), [Sakimura](https://www.sakimura.org/en/2025/10/7710/) |
| 26.4 | Locating a site's change-password page | W3C "A Well-Known URL for Changing Passwords" (Working Draft, June 2024) | [W3C](https://www.w3.org/TR/change-password-url/) |
| 26.4 | Automated password change on sites | Chrome automatic change of compromised passwords on supported sites; Gemini-driven change in Canary (Aug 2026, failing in tests); Dashlane and LastPass changers (launch reported; current status unconfirmed) | [Android Authority](https://androidauthority.com/chrome-canary-gemini-change-bad-passwords-3698237), [Shelly Palmer](https://shellypalmer.com/2025/09/google-chromes-ai-makeover-ten-new-features-that-could-change-how-you-browse/), [blog-nouvelles-technologies](https://www.blog-nouvelles-technologies.fr/?p=58569) |
| 26.4 | Automated rotation with check-out/verify | Enterprise privileged-access management (general knowledge; not searched) | -- |
| 26.5 | Key rollover signed by the old key | ACME account key rollover, RFC 8555 §7.3.5 (general knowledge; not searched) | -- |
| 22.3 | Migration and credential exchange | FIDO CXP/CXF drafts | [CXP draft](https://fidoalliance.org/specs/cx/cxp-v1.0-wd-20241003.html) |
| 23.2 | Security properties as types | Resid's `Trust` / `Verified(Claims)` (public, MIT) | [Resid](https://github.com/larrydewey/Resid) |

## Assessment

Every mechanism has prior art. The searches found no single source
combining:

1. a passkey held as a t-of-n threshold key across the principal's own
   devices, recovery kit and a blind cosigner, with re-sharing used as
   revocation at every RP and recovery that needs no RP flow (SPEC 10-13);
2. a cosigner that enforces the principal's own key-event-log policy
   (revocation, recovery delay, duress) while blind to the RP (SPEC 12, 14);
3. duress realized as a genuine subset plus containment of durable
   changes through the quorum (SPEC 14);
4. release gated on compiler-checked capability sets carried in an
   attested provenance record (SPEC 17.4).

Absence from these searches is weak evidence. Each item is a combination
of known techniques, and under U.S. law (KSR v. Teleflex) a combination of
known elements with predictable results is likely obvious; software claims
also face eligibility review (Alice v. CLS Bank). Items 2 and 3 are the
least obviously anticipated. A professional search would be needed before
relying on any of them.
