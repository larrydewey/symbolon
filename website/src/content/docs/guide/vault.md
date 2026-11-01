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
bank accounts, Wi-Fi networks and secrets, each with its own fields, plus
custom fields and folders. An item's type is itself sealed, so the relay
sees only that you have some number of items.

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

## Moving items

An item moves between your own vault and a shared folder (**Move** on the
item, or `symbolon device vault move`): it is written in its new place first,
then removed from the old one.

## Under the duress PIN

The duress profile has a vault of its own, and the shared folders you chose
for it read-only. It never shows the real vault.
