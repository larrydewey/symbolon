---
title: Moving in
description: Bring your passwords from another manager, add a new phone, recover after losing devices, join your company.
---

## From another password manager

### Bitwarden or Vaultwarden: sign in

No export file needed: in the app, **More › Import › Bitwarden or
Vaultwarden**. Choose bitwarden.com, bitwarden.eu or your own server's
address, enter your email and master password, and the code from your
authenticator app (or email) if Bitwarden asks for one. Symbolon downloads
your encrypted vault and opens it on your phone or computer; nothing is
saved unencrypted, and your master password is used once and not kept.
Check the preview, then import with your PIN.

```sh
symbolon device vault signin-bitwarden ~/.symbolon https://vault.example.com --dry-run
```

(On the command line it is a conversation: the email, then the master
password, then a code if asked, on standard input.)

If your account still uses fewer than 100,000 key-derivation iterations,
raise them first in Bitwarden (Settings › Security › Keys): Symbolon refuses
weaker settings, which a malicious server could otherwise lower on purpose.
Duo and security-key two-step login, and accounts on Bitwarden's newest key
format, need the export file for now.

### Everything else: the export file

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

**Passkeys from Bitwarden** come across as *Synced* passkeys. Their private
keys are whole keys, and a Symbolon passkey is split between your device and
the cosigner; a whole key is never split after the fact. So each is kept as
it came, sealed in your vault, and signs on your device alone, without the
cosigner, and anyone holding a copy of the export can use it too. Only
ES256 passkeys (ECDSA on P-256, which is what Bitwarden makes) can be kept;
any other is left out, and the preview says so.

So replace each one with a Symbolon passkey. **More › Passkeys** lists them
under *Imported passkeys to replace*, each with its next step:

1. Sign in to the site; the imported passkey still works (Android offers it,
   marked "imported").
2. In the site's security settings, add a passkey and choose Symbolon. It
   sees that the account has an imported passkey and records that the new
   one replaces it.
3. Sign in once with the new passkey. Then, under Passkeys, **Retire** the
   imported one: it is deleted from your vault, and Android stops offering
   it.
4. Remove the old passkey in the site's security settings too: until you
   do, a copy of the export can still sign in there.

On the command line: `symbolon device webauthn synced DIR` lists them,
`device webauthn register DIR SITE --replaces CID` makes the replacement,
and `device webauthn retire DIR CID` retires one (`--force` retires one
nothing replaced). The browser extension doesn't offer imported passkeys
yet.

**What doesn't come across.** Passkeys from managers whose export has none
(every CSV export), and a password-protected Bitwarden export: export it
again unencrypted.

**Afterwards**, delete the export file and empty the trash: anyone who finds
it can read every password in it. Once you have checked your vault, you can
close the old account.

## A new phone or computer

A new device joins your identity from one you already have, by a code:
nothing to type or copy. Your key is re-shared to include it: the parties
make new shares of the same key, so every passkey keeps its public key and
no site needs to be told.

1. On the **new** device: install the app, open **Set up this device** and
   choose **Join from your other device**. Pick a PIN for it. It shows a QR
   code.
2. On a device that **has** your identity: **More › Devices › Add a device ›
   Scan the new device's code** (on a computer without a camera, paste the
   link the new device can copy).
3. Wait one to three minutes with both devices on and on the same network. The new
   device learns your relay from the other one, makes its keys and joins;
   then it has your vault and your passkeys.

The code carries a one-time key: only the device that scanned it can answer,
so another machine on the network cannot slip in.

On the command line, `symbolon device link-new DIR --host ADDRESS` on the
new device prints the code's link, and `symbolon device link-add DIR LINK`
on the old one adds it. (`device join` and `device enroll`, with the two
devices' keys copied by hand, still work where the devices cannot reach each
other.)

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

- **Replacing imported passkeys without visiting each site.** Today each
  site's own "add a passkey" page makes the replacement. Doing it from a
  recipe, or by a rollover the site accepts during an ordinary sign-in
  ([SPEC 26.5](https://github.com/larrydewey/symbolon/blob/master/SPEC.md)),
  and offering imported passkeys in the browser extension, are next.

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
