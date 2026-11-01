---
title: Recovery
description: The recovery kit, the waiting period, the veto, and the duress PIN.
---

## The recovery kit

At setup you write down a **recovery kit**: hex digits, shown once. It holds
material for a share of your key that is kept offline, and with it you can
get your identity back even after losing every device.

## Recovering

On a new device: **More › Recovery › With your recovery kit**. Give the kit
and your identity log's id (shown under Home on your devices; keep a note of
it). The new device starts a recovery that takes effect after a **waiting
period** measured by the witnesses' time, then re-shares your key to itself.
You write down a **new kit**; it replaces the old one when the recovery takes
effect.

Every passkey keeps its public key, so sites notice nothing.

## Stopping a recovery

If someone else starts a recovery with your kit, every device you still hold
sees it pending (under Home) and can **veto** it during the waiting period:
**More › Recovery › Stop a recovery**. A thief with your kit and no device
cannot outwait you, and a thief with one device cannot veto your own recovery
forever: contested recoveries escalate (see the specification, section 13).

## The duress PIN

If someone forces you to unlock, the duress PIN opens a separate profile: a
subset of passkeys and folders you chose, in a vault of its own. It looks
like the real thing. Lasting changes fail as if the server were having
trouble, and nothing in the log or at the relay shows a duress unlock.
