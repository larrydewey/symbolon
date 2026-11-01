---
title: Symbolon Home
description: One box at home runs the relay, the witnesses and a cosigner for each person.
---

Symbolon Home is one box for a household: a NAS, a mini PC or a Raspberry Pi
runs everything the family's devices need. Nobody else's servers are
involved.

- **The relay** keeps each person's encrypted vault and identity log on the
  box's disk. Nothing on it can be read without the person's devices.
- **A cosigner per person** holds the second share of each key, so a stolen
  phone can't sign alone.
- **Three witnesses** record and timestamp every change to an identity. For
  now they run on the box itself, so the box vouches for its own log;
  independent public witnesses are planned.
- **Pairing**: a one-time QR code per person. The phone scans it and sets
  itself up.

The box makes its own small certificate authority, so it needs no domain
name and no Let's Encrypt. Phones pin the box's certificate from the QR code.

## Run it with Docker

Build the image from `symbolon-home/` (after building the agent with
`symbolon-flutter/tools/bundle-agent.sh`):

```sh
./build.sh            # for this machine
./build.sh --multi    # amd64 and arm64, for a NAS
```

Set the box up once. Give every address your devices reach it at: the LAN
address, and a WireGuard or Tailscale address for when you are away.

```sh
mkdir data && sudo chown 65532:65532 data
docker compose run --rm symbolon-home home init /data 192.168.1.20 10.8.0.1
```

Invite each person. This prints a pairing link; show it as a QR code, or
send it to them:

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
symbolon home init ~/home-box 192.168.1.20
symbolon home invite ~/home-box alice
symbolon home serve ~/home-box
```

## On the phone

**More › Set up this device**, then **Scan the code**. Choose a PIN (and, on
a phone with a fingerprint reader, let it unlock Symbolon), and wait while
the phone and the box make the key together: a few minutes, with the app
kept open. Then write down the recovery kit. See [Mobile app](/symbolon/guide/mobile/).

## Network

The box listens on five ports from 47100: pairing, the relay, and three
witnesses (`--ports BASE` moves them).

- **At home**: publish them on the LAN address only (see `compose.yaml`).
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

`data/` holds the cosigners' shares. If it is lost, each person must recover
with their recovery kit. Back it up like any other secret: encrypted.
