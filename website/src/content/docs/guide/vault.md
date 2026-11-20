---
title: The vault
description: Logins, cards, notes and secrets, sealed on your devices; offline reading; changing passwords for you.
---

The vault keeps your passwords and other secrets. Each item is sealed with a
key only your devices hold, under a signed head that names the current
version. The relay keeps a copy it cannot read or quietly change: a device
accepts a vault only when its head is signed by one of your devices and is
not older than one it has seen.

## What it holds

Logins (site, username, password, one-time codes), cards, identities, notes,
bank accounts, Wi-Fi networks, secrets and [SSH keys](/symbolon/guide/ssh/),
each with its own fields, plus custom fields and folders. An item's type is
itself sealed, so the relay sees only that you have some number of items.

A card is drawn as the card itself, in its network's colours, with the
number laid out as the network prints it and masked to its last four digits
until you tap it; the editor shows it as you type.

## In the browser

The [browser extension](/symbolon/guide/browser/) fills logins and cards
into web pages, each fill approved in a Symbolon window the page cannot
reach.

## Offline

Every device keeps a verified copy. With no connection the vault opens
read-only from that copy and says so; changes wait until the relay is back.
An organization can limit how long a copy of a shared folder may be read
offline.

## Changing a password for you

Symbolon can change a login's password at the site itself, following a
signed recipe for that site (**rotate** on the command line). Recipes are
checked against the sites they name, never type a secret into a field they
don't expect, and stop before anything destructive.

## Breached passwords

**More › Breached passwords** (or **Check for breached passwords** under the
vault list) checks every login's current password against
[Pwned Passwords](https://haveibeenpwned.com/Passwords), the collection of
passwords seen in published breaches. Only the first five hex digits of each
password's SHA-1 hash leave the device, in a padded request, so the service
learns neither the password nor which of the several hundred it returned
under that prefix was yours. Each breached login is listed with the number
of times it has been seen; change those passwords first, starting with your
email.

The app remembers what the last check found, on this device: the vault shows
a banner and marks each breached login, the login's page warns, and so do
the fill windows of the [browser extension](/symbolon/guide/browser/) and
Android autofill. A login is still filled, so you can sign in and change it.
Changing its password in Symbolon, or at the site with **Change password at
the site…**, clears the warning. A shared folder has its own check, under
its list.

If the service cannot be reached, its certificate does not verify or an
item does not open, the check fails rather than calling your logins clean.
Protected items are skipped, and the check says how many.

On the command line it is `symbolon device vault breach DIR`.
`SYMBOLON_BREACH_URL` and `SYMBOLON_BREACH_CA` point it at a mirror of your
own and its certificate.

## Moving items

An item moves between your own vault and a shared folder (**Move** on the
item, or `symbolon device vault move`): it is written in its new place first,
then removed from the old one.

## Under the duress PIN

The duress profile has a vault of its own, and the shared folders you chose
for it read-only. It never shows the real vault.
