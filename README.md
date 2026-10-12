# Symbolon

A *symbolon* was a token broken in two: each party kept one half, and
the halves fitting together proved who was who, with nothing secret said
aloud. That is the idea here.

Symbolon is the design of a **credential agent**: software that holds a
person's keys rather than their passwords, proves itself and the device it
runs on, binds sessions to hardware, discloses only the facts a service
asks for, and recovers lost devices cryptographically instead of by email
link. Passwords survive only as a legacy profile, kept in a vault designed
against the malicious-server attacks published in 2025-2026.

The reference implementation is planned in
[Resid](https://github.com/larrydewey/Resid), whose secret types,
capability checks, attestation verifier and TPM access carry much of the
design's enforcement.

## Status

Draft design. No code yet. **Confidential: see [NOTICE.md](NOTICE.md)
before sharing anything in this repository.**

## Documents

- [SPEC.md](SPEC.md) -- the formal specification (draft 0).
- [PRIOR-ART.md](PRIOR-ART.md) -- what already exists, component by
  component, with sources, and an honest account of what may be new.
- [NOTICE.md](NOTICE.md) -- confidentiality and intellectual-property notes.
