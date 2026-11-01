# Symbolon

A *symbolon* was a token broken in two: each party kept one half, and
the halves fitting together proved who was who, with nothing secret said
aloud. That is the idea here.

Symbolon is a **credential agent** built around continuity
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

The implementation is in [Resid](https://github.com/larrydewey/Resid),
whose secret types, capability checks, attestation verifier and TPM
access carry much of the design's enforcement.

## Status

v0.1.3: the agent, relay, witnesses and cosigner, Symbolon Home (a
self-hosted box for a household) and organizations for companies, with an
Android and Linux app. See the
[releases](https://github.com/larrydewey/symbolon/releases).

The guide, for people using it and for those running it, is at
**[larrydewey.github.io/symbolon](https://larrydewey.github.io/symbolon/)**:
the mobile app, the desktop app, Symbolon Home, organizations, and moving in.

## Layout

- [SPEC.md](SPEC.md) -- the specification, with its red-team audit in Appendix A.
- [symbolon-resid](symbolon-resid) -- the agent and servers, in Resid.
- [symbolon-flutter](symbolon-flutter) -- the app (Android, Linux).
- [symbolon-home](symbolon-home) -- Symbolon Home's container build.
- [website](website) -- the guide's pages, published by resid-book.

## License

MIT; see [LICENSE](LICENSE).
