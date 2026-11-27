---
title: Symbolon Home
description: One box at home runs the relay, a witness and a cosigner for each person, with its keys sealed.
---

Symbolon Home is one box for a household: a NAS, a mini PC or a Raspberry Pi
runs everything the family's devices need. Nobody else's servers are
involved.

- **The relay** keeps each person's encrypted vault and identity log on the
  box's disk. Nothing on it can be read without the person's devices.
- **A cosigner per person** holds the second share of each key, so a stolen
  phone can't sign alone.
- **Witnesses** record and timestamp every change to an identity. The box
  runs one; at least two more run outside it (a household computer that is
  usually on, or a hosted witness), so the box alone is never a majority.
- **Pairing**: a one-time QR code per person. The phone scans it and sets
  itself up.

The box makes its own small certificate authority, so it needs no domain
name and no Let's Encrypt. Phones pin the box's certificate from the QR code.

## The keys are sealed

The cosigners' keys, the witness key and the certificate keys are sealed on
the box's disk to its **TPM** (when it has one) or to a **passphrase**
(Argon2id). `home serve` unseals them into memory at start, and only then:
a copy of the disk or a backup of `data/` is useless without the TPM or the
passphrase. With a passphrase, give it from a file you mount at start (a
Docker secret) or type it, and keep it off the box's disk and its backups.

## Witnesses outside the box

On a household computer that is usually on:

```sh
symbolon witness keygen ~/witness.key        # prints the witness's KEY
# on the box, after home init: home witness-cert DATA pc.lan OUTDIR
symbolon witness serve ~/witness 47110 ~/witness.key 0 --bind 192.168.1.30 --tls server.pem server.key
```

Or use a hosted witness: its `HOST:PORT:KEY` (and `--witness-ca FILE` when
its certificate is not under the box's CA).

## Run it with Docker

Build the image from `symbolon-home/` (after building the agent with
`symbolon-flutter/tools/bundle-agent.sh`):

```sh
./build.sh            # for this machine
./build.sh --multi    # amd64 and arm64, for a NAS
```

Set the box up once. Give every address your devices reach it at (the LAN
address, and a WireGuard or Tailscale address for when you are away) and
two witnesses outside the box. `HOME_ADDR` is the address compose publishes
the ports on (it refuses to start without it); `HOME_PASSPHRASE_FILE` the
passphrase, on a box without a TPM.

```sh
echo HOME_ADDR=192.168.1.20 > .env
echo HOME_PASSPHRASE_FILE=/media/usb/symbolon-home.pass >> .env
mkdir data && sudo chown 65532:65532 data
docker compose run --rm symbolon-home home init /data 192.168.1.20 10.8.0.1 --bind 0.0.0.0 \
    --witness pc.lan:47110:KEY1 --witness witness.example.org:443:KEY2
```

Invite each person. This prints a pairing link; show it as a QR code. The
link is a **bearer secret**: it works once and for a day, and whoever uses
it first pairs as that person, so show it in person:

```sh
docker compose run --rm symbolon-home home invite /data alice
# symbolon://pair?h=192.168.1.20&p=47100&c=...&f=...
```

Start it:

```sh
docker compose up -d
```

## Or run the binary

The same steps with the agent directly:

```sh
symbolon home init ~/home-box 192.168.1.20 --witness pc.lan:47110:KEY1 --witness witness.example.org:443:KEY2
symbolon home invite ~/home-box alice
symbolon home serve ~/home-box
```

The binary listens on the first address given (`--bind ADDR` for another).

## A box set up before sealing

`home serve`, `home invite` and the app remind you until an older box is
secured. Stop it, run `home secure DATA --witness ... --witness ...` (it
seals every key and gives people invited from now on the witnesses outside
the box), and start it again. Identities made before keep the box's three
witnesses until one of their devices moves them: `home secure` prints the
command, `symbolon device witnesses DIR --add ... --remove ...`, which
asks each new witness for a signed time first, then publishes the change.
It takes effect after the recovery delay (three days by default), during
which any of that person's devices can veto it. The reminder names them
until then.

## On the phone

**More › Set up this device**, then **Scan the code**. Choose a PIN (and, on
a phone with a fingerprint reader, let it unlock Symbolon), and wait while
the phone and the box make the key together: one to four minutes, with the app
kept open. Then write down the recovery kit. See [Mobile app](/symbolon/guide/mobile/).

## Network

The box listens on ports from 47100: pairing, the relay, and its witness
(an older box: three witnesses, to 47104; `--ports BASE` moves them).

- **At home**: compose publishes them on `HOME_ADDR` only.
- **Away**: reach the box over your VPN (WireGuard, Tailscale). Don't
  forward these ports on your router.
- **Box unreachable**: the vault still opens read-only from the phone's own
  copy. Signing in with a passkey needs the box (the cosigner is on it).

The relay also serves a console for organizations at `/console/`; a
household has no use for it.

## Hardware

- **Key generation**, once per person, peaks near 1.2 GB of memory on the
  box and near 1.7 GB on the phone.
- **Adding a second device** to someone's identity (a re-share) currently
  needs up to about 10 GB in one process on the box. Plan for a box with
  enough memory.
- **Disk**: a few megabytes per person.

## Back it up

`data/` holds the cosigners' shares, sealed. If it is lost, each person must
recover with their recovery kit.

A backup of `data/` plus the box's passphrase (or its TPM) plus a person's
recovery kit is that person's identity. Keep the backup encrypted, the
passphrase apart from it, and the recovery kits somewhere else again. A kit
passphrase is recommended (SPEC 10.6); the app does not offer one yet.
