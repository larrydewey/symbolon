---
title: Mobile app
description: Symbolon on Android: setup by QR code, passkeys for sites and apps, fingerprint unlock.
---

The Android app is the agent in a pocket: the same `symbolon` program as on
the desktop runs inside the app, and the app gives it a screen. The app
itself holds no keys.

## What you need

- **Android 9 or newer.** The device's share and its unlock keys live in the
  Android Keystore, in StrongBox on phones that have it.
- **Android 14 or newer** to use Symbolon as the passkey provider for sites
  in your browser and for apps.
- Somewhere to set up against: a [Symbolon Home](/symbolon/guide/home/) box,
  your company's servers, or the demo on your desktop.

Install the APK from the [releases](https://github.com/larrydewey/symbolon/releases)
(see [Install](/symbolon/guide/install/)).

## Set up

The first start shows a short tour (skip it, or find it later under
**More › How Symbolon works**). Then **More › Set up this device**:

1. **Scan the code** your Symbolon Home box or your administrator gave you.
   The code carries the box's address and its certificate's fingerprint, so
   the phone talks only to that box from the first byte.
2. **Choose a PIN**, and a **duress PIN** if you want one (it must differ).
   On a phone with a fingerprint reader, let it unlock Symbolon.
3. **Wait while the phone and the box make your key.** This is real work
   for a phone: a few minutes, with the app kept open.
4. **Write down the recovery kit.** It is shown once. With it you can get
   your identity back after losing every device.

## Everyday use

The app has four tabs: **Home** (your identity and anything waiting, such as
a recovery someone started), **Passkeys**, **Vault** and **More**.

- **Unlock** with your PIN or fingerprint. The app stays unlocked for a
  while (**More › Settings › Stay unlocked**) and locks when you leave it or
  tap the lock.
- **Passkeys**: **Turn on Symbolon for passkeys**, or choose it under
  Android's *Settings › Passwords, passkeys and accounts*. Sites and apps
  then offer Symbolon passkeys; on a computer, "Use a phone or tablet" shows
  a QR code to scan with the phone.
- **Vault**: logins, cards, identities, notes, bank accounts, Wi-Fi networks
  and secrets, with folders. Without a connection it opens read-only from
  the phone's own verified copy and says so.
- **Sharing** (**More › Sharing**): folders shared with your household. See
  [Sharing](/symbolon/guide/sharing/).
- **Organization** (**More › Organization**): your company, if you have
  one. See [Organizations](/symbolon/org/).
- **Import** (**More › Import**): bring your passwords from another manager.
  See [Moving in](/symbolon/guide/migration/).

## Devices and recovery

- **More › Devices** adds a device to your identity or removes one. See
  [Moving in](/symbolon/guide/migration/#a-new-phone).
- **More › Recovery** recovers with your kit on a new device, or stops a
  recovery someone else started. See [Recovery](/symbolon/guide/recovery/).

## When your company manages the phone

A company's device management can set the app up (Android managed
configurations): its organization, the founder that binds it, your invite
code, and whether the duress setting is shown. You still choose your own
PIN, and the company never receives a key. See
[Organizations › Setup](/symbolon/org/setup/#managed-phones).
