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

v0.3.4: the agent, relay, witnesses and cosigner, Symbolon Home (a
self-hosted box for a household) and organizations for companies, with an
Android and Linux app, a browser extension for logins and cards, an SSH
agent, security keys (YubiKey and other FIDO2 keys) as a second factor, and
new devices added by scanning a QR code.
See the
[releases](https://github.com/larrydewey/symbolon/releases).

The guide, for people using it and for those running it, is at
**[larrydewey.github.io/symbolon](https://larrydewey.github.io/symbolon/)**:
the mobile app, the desktop app, Symbolon Home, organizations, and moving in.

## Layout

- [SPEC.md](SPEC.md) -- the specification, with its red-team audit in Appendix A.
- [symbolon-resid](symbolon-resid) -- the agent and servers, in Resid.
- [symbolon-flutter](symbolon-flutter) -- the app (Android, Linux).
- [symbolon-extension](symbolon-extension) -- the browser extension (Chromium, Firefox); fills logins and cards through the agent.
- [symbolon-home](symbolon-home) -- Symbolon Home's container build.
- [website](website) -- the guide's pages, published by resid-book.

## License

MIT; see [LICENSE](LICENSE). The Android app includes [ZXing](https://github.com/zxing/zxing)'s
core library, under the Apache License 2.0: its license and notice are in
[symbolon-flutter/android/app/src/main/assets/third_party/zxing](symbolon-flutter/android/app/src/main/assets/third_party/zxing),
and in the APK under `assets/third_party/zxing/`.
