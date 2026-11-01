---
title: Desktop app
description: Symbolon on Linux: the app, the command-line agent, and the TPM.
---

On a Linux desktop Symbolon is two things: the **app** (the same Flutter app
as on Android, built for Linux) and the **agent** (`symbolon`), a single
static binary the app runs for every operation. Everything the app does,
the command line does too.

## The key store: a TPM

On a PC with a TPM 2.0 that your user can open (`/dev/tpmrm0`, usually by
joining the `tss` group), setup keeps the device's unlock keys and its
device key in the TPM. The device key is usable only with your PIN, through
a TPM policy, and the TPM counts wrong PINs (it locks for a while after too
many). **More › Hardware key store** says whether you have one and how to
turn it on.

Without a TPM the agent can run in the *unprotected* profile: keys in files,
protected by your PIN stretched with Argon2id. It is meant for tests and for
servers that hold no person's keys.

## The command line

The agent keeps a device in a directory (`DIR` below). PINs and secrets go
on standard input, never on the command line.

```sh
# set up against a relay, then make the key with the cosigner and witnesses
printf '%s\n%s\n' "$PIN" "$DURESS_PIN" | symbolon device new ~/.symbolon relay.example 47101 --ca ca.pem
printf '%s\n' "$PIN" | symbolon device init ~/.symbolon COSIGNER-KEYS W1 W2 W3

# passkeys
printf '%s\n' "$PIN" | symbolon device webauthn register ~/.symbolon example.com
# the vault
printf '%s\nhunter2\n' "$PIN" | symbolon device vault put ~/.symbolon mail
printf '%s\n' "$PIN" | symbolon device vault list ~/.symbolon --long
# change the PIN
printf '%s\n%s\n' "$PIN" "$NEW_PIN" | symbolon device pin ~/.symbolon
```

With Symbolon Home you don't type the setup by hand: the app's setup (or
the pairing link) does it. Every command is listed in the
[reference](/symbolon/reference/).

## Running the servers

The same binary is every server: `symbolon relay serve`, `symbolon witness
serve`, `symbolon cosigner serve` and `symbolon home serve`. For a household,
use [Symbolon Home](/symbolon/guide/home/); for a company, see
[Running the servers](/symbolon/org/servers/).

## Trying it without a box

`symbolon-flutter/tools/demo.sh` starts a relay, three witnesses and a
cosigner on your desktop, sets up a device, and opens the app (PIN 2468).
With `--lan` a phone on the same network can set up against it. The demo
uses test key material: don't keep anything real in it.
