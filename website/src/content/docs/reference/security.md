---
title: Security model
description: What Symbolon protects against, what it relies on, and what it does not do.
---

This page is a summary. The specification,
[SPEC.md](https://github.com/larrydewey/symbolon/blob/main/SPEC.md), states
every goal, the threats and the residual risks, with a red-team audit in its
Appendix A.

## Protected against

- **A stolen or compromised device.** It holds one share; without the
  cosigner it signs nothing, and its PIN is held by the TPM or Keystore,
  which count wrong tries.
- **A compromised cosigner or relay.** The cosigner holds one share and is
  blind to which site it signs for. The relay holds only signed and sealed
  objects; it can withhold or serve old ones, which devices notice.
- **A server rewriting your identity.** Every change is in a log your
  devices sign and witnesses countersign, checked by each device.
- **A recovery you didn't start.** It waits a period measured by witness
  time, during which any of your devices can veto it.
- **Coercion.** The duress PIN opens a real subset and blocks lasting
  changes, with no trace in the log or at the relay.
- **A malicious password-manager server**, of the kind published in 2025
  and 2026: vault items are sealed per item under a signed head, and rollback
  is refused.
- **A web page tricking you into a fill.** The browser extension fills only
  after you approve in a Symbolon window outside the page, showing the
  origin your browser reports; logins go only to their own site, card fields
  only to the page and a short list of payment processors' frames.
- **A program misusing your SSH keys.** Every signature asks first, naming
  the program, what is signed and the server, whose host key is checked;
  the agent answers only your own user and verifies each signature.
- **A stolen device and a known PIN**, with a security key enrolled: the
  device does not open without the key and a touch.

## Relied on

- **Witnesses** that are independent of your relay. Symbolon Home runs its
  witnesses on the same box for now, so a household's box vouches for its
  own log; independent public witnesses are planned.
- **Fingerprints compared out of band** when you share a folder, so a relay
  cannot slip in a key of its own.
- **Your recovery kit**, kept somewhere safe and offline.
- **The hardware key store** (TPM, Android Keystore) for counting PIN tries.

## Organizations

The company's servers add access control, but every record is still checked
on the devices. Owners and administrators cannot open a person's own vault
or sign for anyone. Opt-in recovery lets several administrators together
open escrowed work folders after a waiting period the person is told about;
turning it on is visible to every member. The directory can take access away
at once, never give it.

## Not built yet

- Security keys on Android.
- Removing a device from an identity by re-sharing without it.
- Moving an identity to another relay.
- An iOS app.
