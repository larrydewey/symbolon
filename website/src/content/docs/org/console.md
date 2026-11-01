---
title: Console
description: The administrators' console on the relay, with passkey sign-in, and the local console.
---

## On the relay

The relay serves a console at `/console/ORG-ID` when it is given its origin
(`--console-origin https://HOST:PORT`; Symbolon Home sets it).

**Sign in with a passkey.** Register a passkey in the console (Symbolon on
your phone works as the passkey provider). The console shows a short code;
approve it on your own device:

```sh
printf '%s\n' "$PIN" | symbolon device org console-key ~/.symbolon CODE
```

or **More › Organization › Approve a console passkey**. From then on that
passkey signs you in. The relay checks each sign-in's challenge, origin,
relying-party hash and signature, and that you are still an owner or
administrator.

**What it shows**: the organization as the relay holds it (its records were
verified when they were written): policy, recovery, people, groups and the
changes queued.

**Changes wait for a device.** An invite, adding or removing someone from a
group, removing a person, a policy setting or a sync made in the console is
queued. It takes effect only when an administrator's device approves it:

```sh
symbolon device org changes ~/.symbolon            # what is queued
printf '%s\n' "$PIN" | symbolon device org approve ~/.symbolon CHANGE-ID
```

or **Approve** in the app's list. The device signs it as it would its own
change and tells the console the result. The server holds no
administrator's key.

## On your own machine

```sh
symbolon device org console ~/.symbolon 8080
# console at http://127.0.0.1:8080/?t=TOKEN
```

A read-only page, on 127.0.0.1 behind a random token, with everything
verified by your device, each audit event marked verified or broken.
