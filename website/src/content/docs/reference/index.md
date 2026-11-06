---
title: Command line
description: Every symbolon command, grouped.
---

`symbolon` is one binary: the agent and every server. A device lives in a
directory (`DIR`). PINs and secrets are read from standard input, never
from the command line; values that may hold any text are printed as hex.

## A device

| Command | Does |
|---|---|
| `device new DIR RELAY-HOST RELAY-PORT [--unprotected] [--ca CA.pem]` | makes the device's keys (PIN, duress PIN on stdin) |
| `device init DIR COSIGNER-KEYS W1 W2 W3` | makes the identity with the cosigner, witnesses `host:port:key` |
| `device status DIR` | the identity, its devices and anything pending |
| `device pin DIR` | changes the PIN (PIN, new PIN on stdin) |
| `device forget DIR` | deletes the device's keys from its TPM or Keystore |
| `device link-new DIR [--host ADDR,…]` / `device link-add DIR LINK` | adds a device by code: the new one shows it, the old one scans it |
| `device enroll DIR NEW-KEYS` / `device join DIR ENROLLER-KEYS` | adds a device with keys copied by hand (on the old one / the new one) |
| `device recover DIR KIT LOG-ID` | starts a recovery with the kit |
| `device veto DIR` | stops a pending event, such as a recovery |

## Passkeys

| Command | Does |
|---|---|
| `device webauthn register DIR RP-ID [--uv] [--duress]` | a new passkey: credential id, public key, authenticator data, attestation object |
| `device webauthn assert DIR RP-ID CRED-ID CLIENT-DATA-HASH [--uv]` | signs a WebAuthn assertion |
| `device register DIR RP [--duress]` / `device sign DIR RP CRED-ID MESSAGE` | the same, raw |

## The vault

Each takes a last `--share ID` to work in a shared folder.

| Command | Does |
|---|---|
| `device vault list DIR [--kinds\|--long]` | the items (offline: from the device's copy) |
| `device vault show DIR NAME` | an item's fields |
| `device vault set DIR NAME TYPE` | adds or changes an item (`FIELD VALUE-HEX` lines on stdin) |
| `device vault put DIR NAME` / `get DIR NAME` | a plain secret |
| `device vault delete DIR NAME` | removes an item |
| `device vault move DIR NAME TO` | to `own` or a shared folder |
| `device vault import DIR FILE [--format F] [--dry-run]` | from another password manager |
| `device rotate DIR NAME BUNDLE REPOSITORY` | changes a login's password at the site |

## SSH keys

| Command | Does |
|---|---|
| `ssh-agent DIR [SOCKET]` | the SSH agent (`SYMBOLON_CONSENT` names the app, which shows each request) |
| `device ssh new DIR NAME` | a key held by your quorum; prints its public line |
| `device ssh import DIR NAME FILE` | an OpenSSH private key (PIN, then any passphrase, on stdin) |
| `device ssh list DIR` | the keys' public lines (no PIN) |
| `device ssh sign DIR NAME [rsa-sha2-256\|rsa-sha2-512]` | signs (PIN, then the data in hex, on stdin) |
| `device ssh delete DIR NAME` | removes a key |

## Security keys

| Command | Does |
|---|---|
| `device key add DIR NAME` | enrolls the plugged-in FIDO2 key (two touches) |
| `device key list DIR` | the enrolled keys (no PIN) |
| `device key remove DIR NAME` | removes one (a touch of any enrolled key); the last returns the device to the PIN alone |

## The browser extension

| Command | Does |
|---|---|
| `browser host` | the extension's native messaging host, started by the browser (`install.sh` registers it; `SYMBOLON_CONSENT` names the app) |

## Sharing

| Command | Does |
|---|---|
| `device share me DIR` / `share people DIR` | your fingerprint / the people at the relay |
| `device share card DIR NAME` | the name others see |
| `device share new DIR NAME` | a shared folder |
| `device share list DIR` / `members DIR ID` | folders / a folder's people |
| `device share add DIR ID LOG-ID NAME` / `remove DIR ID LOG-ID` | people (the owner) |
| `device share leave DIR ID` / `delete DIR ID` | leave / delete (the owner) |
| `device share duress DIR ID on\|off` | open it under the duress PIN on this device |

## Organizations

| Command | Does |
|---|---|
| `device org new DIR NAME` | founds one |
| `device org join DIR ORG-ID FOUNDER [CODE]` | joins, answering an invite |
| `device org show\|members\|groups DIR` | reads it (no PIN) |
| `device org invite DIR EXT-ID NAME [GROUP,…]` | an invite code |
| `device org add\|remove\|role DIR …` | people and roles |
| `device org group new\|add\|remove DIR …` / `folder new DIR NAME GROUPS` | groups and group folders |
| `device org policy DIR KEY VALUE` | the policy (an owner) |
| `device org sync DIR` | invites, directory, attestation, re-keys |
| `device org attest DIR` | this TPM device's attestation, in two steps |
| `device org recovery on DIR K DELAY ADMINS [--short-delay]` / `recovery off DIR` | opt-in recovery |
| `device org escrow DIR FOLDER` / `recover request\|approve\|open DIR FOLDER` | work-folder recovery |
| `device org audit DIR` / `export DIR [--https URL --token T] [--syslog H:P --ca F]` | the audit log |
| `device org console DIR PORT` / `console-key DIR CODE` / `changes DIR` / `approve DIR ID` | consoles |

## Servers

| Command | Does |
|---|---|
| `relay serve DIR PORT [--tls CERT KEY] [--bind ADDR] [--ca F] [--store SPEC] [--store-ca F] [--console-origin URL]` | the relay |
| `relay scim-token DIR ORG-ID [--store SPEC]` | a SCIM bearer token |
| `witness keygen KEYFILE` / `witness serve DIR PORT KEYFILE [--tls CERT KEY]` | a witness |
| `cosigner new DIR RELAY-HOST RELAY-PORT` / `pair DIR DEVICE-KEYS` / `serve DIR` | a cosigner |
| `home init DIR HOST… [--ports BASE] [--bind ADDR]` / `home invite DIR NAME` / `home serve DIR` | Symbolon Home |
