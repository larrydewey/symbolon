# Symbolon

A *symbolon* was a token broken in two: each party kept one half, and
the halves fitting together proved who was who, with nothing secret said
aloud. That is the idea here.

Symbolon is the design of a **credential agent** built around continuity
of control. It speaks ordinary passkeys to every site, but behind each
passkey is a threshold key: any quorum of the person's devices, recovery
kit and an optional blind cosigner signs together, and no single device,
account or service can sign alone or lose the credential. Revoking a
device is a re-share that kills its share at every site at once; recovery
goes through the quorum under a delay any device can veto; a duress PIN
opens a real subset and blocks lasting changes. Around that core: hardware
bound sessions, minimal and verifier-constrained disclosure of attributes,
and a legacy password vault designed against the malicious-server attacks
published in 2025-2026.

The reference implementation is planned in
[Resid](https://github.com/larrydewey/Resid), whose secret types,
capability checks, attestation verifier and TPM access carry much of the
design's enforcement.

## Status

Draft design. No code yet. **Confidential: see [NOTICE.md](NOTICE.md)
before sharing anything in this repository.**

## Documents

- [SPEC.md](SPEC.md) -- the formal specification (draft 2, with its red-team audit in Appendix A).
- [PRIOR-ART.md](PRIOR-ART.md) -- what already exists, component by
  component, with sources, and an honest account of what may be new.
- [NOTICE.md](NOTICE.md) -- confidentiality and intellectual-property notes.
