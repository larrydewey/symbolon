---
title: Moving in
description: Bring your passwords from another manager, add a new phone, recover after losing devices, join your company.
---

## From another password manager

Symbolon reads the export file your password manager makes and brings
everything across in one go: logins, cards, identities, notes, bank
accounts, Wi-Fi networks and secrets, keeping your folders. It is added to
your vault as one new version, under one signature, however many items.

| From | Export |
|---|---|
| Bitwarden, Vaultwarden | Tools › Export vault, as `.json` (unencrypted), or `.csv` |
| LastPass | Advanced options › Export (`.csv`; typed secure notes come across) |
| 1Password | File › Export › the account, as CSV |
| Chrome, Edge | Password manager › Settings › Export passwords |
| Firefox | `about:logins` › ••• › Export passwords |
| Safari, Passwords app | File › Export › Passwords |
| KeePassXC | Database › Export › CSV file |
| Proton Pass, Dashlane | Settings › Export, as CSV |
| Anything else | any CSV with a header row: Symbolon finds the name, address, username, password, notes and folder columns |

In the app: **More › Import**, pick where you are coming from, choose the
file, check the preview (what will come across, and what is left out and
why), and import. On the command line:

```sh
symbolon device vault import ~/.symbolon export.csv --dry-run   # no PIN needed
printf '%s\n' "$PIN" | symbolon device vault import ~/.symbolon export.csv
```

Nothing in your vault is replaced: a name already in use gets a number, as
"Email (2)".

**What doesn't come across.** Passkeys from another manager: their private
keys are whole keys, and a Symbolon passkey is split between your device and
the cosigner, so you make a new passkey at each site (sign in once with the
old one or your password, then add a passkey). A password-protected Bitwarden
export: export it again unencrypted.

**Afterwards**, delete the export file and empty the trash: anyone who finds
it can read every password in it. Once you have checked your vault, you can
close the old account.

## A new phone

A new device joins your identity from one you already have. Your key is
re-shared to include it: the parties make new shares of the same key, so
every passkey keeps its public key and no site needs to be told.

1. On the **new** device: install the app, then **More › Devices › Join**.
   It shows its keys as a code.
2. On a device that **has** your identity: **More › Devices › Add a device**,
   and give it the new device's code.
3. Wait while the two devices and the cosigner re-share. The new device then
   has your vault and your passkeys.

On the command line, `symbolon device join DIR ENROLLER-KEYS` on the new
device and `symbolon device enroll DIR NEW-KEYS` on the old one.

**Retiring the old phone**: **More › Devices › Remove this device's keys**
(`symbolon device forget DIR`) deletes its keys from its TPM or Keystore, so
it can no longer unlock or sign. Taking a device out of your identity's
quorum with a re-share is not built yet (see below).

On Symbolon Home a re-share is heavy for the box for now (up to about 10 GB
of memory in one process); see [Hardware](/symbolon/guide/home/#hardware).

## After losing every device

Recover with the kit you wrote down at setup: see
[Recovery](/symbolon/guide/recovery/). It takes effect after a waiting
period, and then you have everything back, passkeys included.

## Into your company

If your company runs Symbolon, you join its organization with the invite
code it gives you (**More › Organization › Join**, or `symbolon device org
join DIR ORG-ID FOUNDER CODE`). Nothing moves: your own vault stays yours
and no one at work can open it. Your team's group folders appear beside your
shared folders. See [Organizations](/symbolon/org/).

## Not built yet

- **Removing a device from your identity** by re-sharing without it. Today
  a retired device's keys are deleted on the device itself; a re-share that
  drops it, so its old share is worthless even if copied, is planned.

- **Moving an identity to another relay**, for example from the demo to a
  Symbolon Home box, or from one box to a new one. An identity lives with
  its relay, cosigner and witnesses; for now, set up a new identity at the
  new box and move your passwords across with the vault's own items (or an
  export from your old manager, if you still have one). Moving a whole box
  to new hardware works: copy its `data/` directory and keep its addresses.
- **Moving a relay between storage backends** (a directory, PostgreSQL, S3):
  pick the backend when you set the relay up; there is no copying tool yet.
