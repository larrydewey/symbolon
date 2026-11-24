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

`ssh-add -L` lists them without asking for your PIN.

Every device of your identity shares these keys: the key you make on the
laptop is the one your phone signs with. On another device, the sync
button on the **SSH keys** page brings in keys made elsewhere.

## Letting a server in

A server lets you in when it trusts one of your keys. You tell each server
once, in one of two ways. Either way, one setup covers every device.

### One key at a time

Add the key's public line to `~/.ssh/authorized_keys` on the server (or to
your code host, GitHub or GitLab, like any other key). On the **SSH keys**
page, each key has **Set up a server**: type the user and server
(`larry@server.example`) and copy the command it gives, which you run from
a device that can already log in:

```sh
pylon authorize larry@server.example 'ecdsa-sha2-nistp256 AAAA… github'
```

Pylon adds the line without touching what is there and fixes the file's
permissions. Or paste the line into the file yourself.

### With a certificate authority

Symbolon can also be your own SSH certificate authority. Each server is told
once to trust it, and from then on every key with a certificate from it
logs in, as the user names the certificate lists. A new key needs no change
on any server.

1. **Create it.** On the **SSH keys** page, **Create a certificate
   authority**. Your quorum holds it like your keys; it signs only
   certificates, never logins, and the agent never offers it.
2. **Trust it on each server**, once:
   - *For one user, without root*: **Trust it on a server › One user**
     gives
     ```sh
     pylon authorize --ca larry@server.example 'ecdsa-sha2-nistp256 AAAA… myca'
     ```
     which adds `cert-authority,principals="larry" ecdsa-sha2-nistp256 AAAA… myca`
     to that user's `authorized_keys`: certificates that name `larry` log
     in as larry.
   - *For the whole server, as root*: put the line in
     `/etc/ssh/symbolon_user_ca.pub`, add
     `TrustedUserCAKeys /etc/ssh/symbolon_user_ca.pub` to
     `/etc/ssh/sshd_config` (above any `Match` block), check it with
     `sudo sshd -t` and reload sshd. **Whole server** gives these commands
     ready to copy. Each user then logs in with a certificate that names
     their user name.
3. **Issue each key a certificate**: **Issue a certificate** under the key,
   with the user names you log in as on your servers and how many days it
   lasts (30 unless you choose, at most 366).

The agent offers a key's certificate first and the key after it, as
OpenSSH's own agent does; an expired certificate is not offered. When you
log in with less than a third of a certificate's time left, Symbolon renews
it right after the signature you approved, with a second signature by your
quorum, so the login is a little slower that time. **Renew** does it by
hand. The renewal uses only what the vault remembers (the authority, the
user names and the days), never anything a program on your computer could
change.

If you delete the authority, its certificates are dropped here, but servers
that trust it accept them until they expire: remove its line from those
servers.

## What the window shows

For each signature:

- **which key**, by name and fingerprint;
- **which program** asks, with its command line (`ssh git@github.com`);
- **what is signed**: "Sign in as git", "Sign a git commit or tag", or a
  warning when Symbolon cannot tell;
- **which certificate**, when the key logs in with one: its authority, the
  user names it lists and when it ends;
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

## On Android, for other apps

Apps Symbolon trusts by their signature, such as Pylon, can use your SSH
keys on the phone. When a server asks for a signature, the app opens
Symbolon's consent sheet: it names the app, the key, the user and the
server's key fingerprint, and takes your PIN. Check that the fingerprint
matches the host the app says it is connecting to. Other apps cannot
reach the agent at all.

## From the command line

```sh
printf '%s\n' "$PIN" | symbolon device ssh new ~/.symbolon github
printf '%s\n%s\n' "$PIN" "$PASSPHRASE" | symbolon device ssh import ~/.symbolon work ~/.ssh/id_rsa
symbolon device ssh list ~/.symbolon
printf '%s\n' "$PIN" | symbolon device ssh delete ~/.symbolon work

printf '%s\n' "$PIN" | symbolon device ssh ca-new ~/.symbolon myca
symbolon device ssh cas ~/.symbolon
printf '%s\n' "$PIN" | symbolon device ssh certify ~/.symbolon github myca --principal larry --principal deploy --days 30
symbolon device ssh certs ~/.symbolon
printf '%s\n' "$PIN" | symbolon device ssh renew ~/.symbolon github
printf '%s\n' "$PIN" | symbolon device ssh refresh ~/.symbolon
```
