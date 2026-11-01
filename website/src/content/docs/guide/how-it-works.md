---
title: How it works
description: The split key, the cosigner, the witnesses, the relay and the vault.
---

Symbolon is a credential agent: a program on your devices that holds your
share of your keys and speaks to sites and services for you. Around it are
three kinds of servers, none of which can act alone.

## Your key is split

When you set up, your device and a **cosigner** make your key together
(threshold ECDSA, the CGGMP protocol). Neither ever holds the whole key:

- your **device** holds one share, unlocked by your PIN;
- the **cosigner** holds another; it is blind to which site a signature is
  for, so it cannot track you;
- a **recovery kit** you write down holds material for a third share, kept
  offline.

Any two of them sign together. A stolen phone cannot sign without the
cosigner; a hacked cosigner cannot sign without a device. Every passkey you
register is a key derived from this one, so a site sees an ordinary ES256
passkey with an ordinary public key.

Adding a device, or recovering with the kit, is a **re-share**: the parties
make new shares of the same key, and the old ones stop working. Public keys
never change, so no site needs to be told. (A re-share that drops a device
is designed but not built yet.)

## Changes go into a watched log

Your identity is a **log** of signed events: the first (inception), each
device added or removed, a recovery started or stopped. Each event is signed
by your devices and countersigned by **witnesses**, which also sign the time.
A device trusts only a log it has checked against its witnesses, so a server
cannot hand it a different identity or roll it back.

Changes that weaken your protection, such as a recovery, take effect only
after a delay measured by witness time, and any of your devices can veto
them in that time.

## The relay keeps copies it cannot read

The **relay** stores your log, your devices' messages to each other and your
encrypted vault. It is deliberately dumb: every object it holds is signed or
sealed, and every device checks what it gets. The worst a relay can do is
withhold or serve something old, and devices notice the latter.

## The vault

Your passwords, cards, notes and other secrets live in a **vault**: each item
sealed with a key only your devices have, under a signed head that says
which version is current. Devices keep a verified copy, so the vault opens
read-only even with no network. Shared folders and organizations' group
folders are vaults of their own, with their own keys.

## The duress PIN

A second PIN, if you set one, opens a separate profile: a subset of passkeys
and folders you chose. It looks and works like the real thing, refuses
lasting changes as if the server were having trouble, and leaves no trace in
the log.

## Where the servers run

| Setup | Relay and witnesses | Cosigner |
|---|---|---|
| [Symbolon Home](/symbolon/guide/home/) | a box in your home | the same box |
| [An organization](/symbolon/org/servers/) | the company's servers | the company's |
| The demo | your desktop | your desktop |

The full design is in [SPEC.md](https://github.com/larrydewey/symbolon/blob/main/SPEC.md).
