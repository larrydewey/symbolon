---
title: Security keys
description: Require a YubiKey or another FIDO2 key, besides your PIN, to open a device.
---

A security key adds something you have to the PIN you know. With one
enrolled, a device opens only when the key is plugged in and touched: a
thief who learns your PIN still cannot open it without the key.

Any FIDO2 key with the `hmac-secret` extension works: YubiKey 5, and most
current keys. Security keys are for the desktop app and agent on Linux;
the Android app does not use them yet.

## Adding a key

In the desktop app, **More › Security keys › Add a security key**. Name the
key, type your PIN, and touch the key when it blinks: twice, once to make
its credential and once to check it.

From then on, every action that opens the device asks for a touch as well as
the PIN. The key's light blinks when it is waiting; touch it within about
30 seconds.

Add a **backup key** the same way, while the first is plugged in. Either key
then opens the device. Keep the backup somewhere else.

## What it changes

- The device's sealed keys are sealed once more under a key that only an
  enrolled security key gives back, after a touch. The key's answer is
  checked against the credential it made, so another key, or a key not
  touched, opens nothing.
- Your PIN works as before, including the limits your TPM puts on wrong
  tries.
- The duress PIN needs the key too.
- A security key is not part of your quorum: it does not hold a share of
  your passkeys, and losing it does not lose them. Recovery with your kit
  works as before.

## Removing a key

**More › Security keys**, then the bin beside the key. Removing needs the
PIN and a touch of any enrolled key. Removing the last one returns the
device to the PIN alone.

If you lose every enrolled key, the device cannot open: recover from
another device or your kit, as for a lost device.

## On Linux

The agent talks to the key over USB, through a sandboxed helper that writes
only to a device that declares itself a FIDO key, never to your keyboard or
mouse. Most desktops give the logged-in user access to a plugged-in key; if
yours does not, add a udev rule for it (your distribution's `libfido2` or
`yubikey-manager` package usually installs one).

```sh
printf '%s\n' "$PIN" | symbolon device key add ~/.symbolon yubikey
symbolon device key list ~/.symbolon
printf '%s\n' "$PIN" | symbolon device key remove ~/.symbolon yubikey
```
