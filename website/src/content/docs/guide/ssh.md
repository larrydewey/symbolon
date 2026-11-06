---
title: SSH keys
description: SSH logins and git signatures with keys held by your quorum or kept in your vault, each signature approved by you.
---

Symbolon runs an SSH agent: `ssh`, `git`, `scp` and anything else that
uses `SSH_AUTH_SOCK` can sign with keys Symbolon keeps. Every signature
opens a Symbolon window first, so nothing signs without you.

## Turning it on

In the desktop app, **More › SSH keys › Start the agent at login** installs
a user service that starts the agent when you log in. Then add this to your
shell's profile:

```sh
export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/symbolon/ssh-agent.sock"
```

Or start it by hand:

```sh
SYMBOLON_CONSENT=/path/to/symbolon_ui symbolon ssh-agent ~/.symbolon
```

The agent's socket is reachable only by you: it lives in a directory only
you can open, and the agent turns away any connection from another user.

## Your keys

Two kinds, both on the **SSH keys** page:

- **New key held by your quorum.** An ECDSA key that, like your passkeys,
  no device or server holds in full: your device and the cosigner sign
  together. A stolen device cannot sign with it alone, and a new or
  recovered device signs with the same key, so no server needs to change
  anything.
- **Import a key file.** An existing OpenSSH key (`~/.ssh/id_ed25519`,
  ECDSA, or RSA of 2048 to 4096 bits), with or without a passphrase. Symbolon
  seals it in your vault; delete the file once you have checked that the
  key works.

Copy a key's public line from the page and add it to the server's
`authorized_keys` or to your code host (GitHub, GitLab) like any other key.
`ssh-add -L` lists them without asking for your PIN.

## What the window shows

For each signature:

- **which key**, by name and fingerprint;
- **which program** asks, with its command line (`ssh git@github.com`);
- **what is signed**: "Sign in as git", "Sign a git commit or tag", or a
  warning when Symbolon cannot tell;
- **which server**, by its host key, with the names your `known_hosts`
  gives it. The agent checks the server's own signature over the session
  before showing it, and refuses a request meant for another session or
  another server.

A request that comes through a forwarded agent (from a server you are
logged in to) carries a warning. Approve only what you started.

Type your PIN and press **Sign**. The agent checks the signature against the
key before it goes back to the program.

## Signing git commits

Copy the key's public line from the **SSH keys** page into a file, say
`~/.ssh/github.pub`, then:

```sh
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/github.pub
git config --global commit.gpgsign true
```

git finds the private half through the agent, so each commit asks in the
Symbolon window. Add the same public key to your code host as a *signing*
key so it shows commits as verified.

## What it refuses

- `ssh-add` adding or removing keys: keys are managed in Symbolon.
- RSA signatures with SHA-1 (`ssh-rsa`); modern clients ask for SHA-2.
- Locking and smart-card requests.

## From the command line

```sh
printf '%s\n' "$PIN" | symbolon device ssh new ~/.symbolon github
printf '%s\n%s\n' "$PIN" "$PASSPHRASE" | symbolon device ssh import ~/.symbolon work ~/.ssh/id_rsa
symbolon device ssh list ~/.symbolon
printf '%s\n' "$PIN" | symbolon device ssh delete ~/.symbolon work
```
