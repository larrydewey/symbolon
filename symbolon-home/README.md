# Symbolon Home

One box for a household: a NAS, a mini PC or a Raspberry Pi runs everything
the family's Symbolon devices need. Nobody else's servers are involved.

- **The relay**: stores each person's encrypted vault and identity log on
  the box's disk. Nothing on it can be read without the person's devices.
- **A cosigner per person**: holds the second half of each key, so a
  stolen phone can't sign alone.
- **Witnesses**: record every change to an identity. For now they run on the
  box itself; independent public witnesses are planned.
- **Pairing**: a one-time QR code per person. The phone scans it and sets
  itself up.

The box makes its own small certificate authority, so it needs no domain and
no Let's Encrypt. Phones pin the box's certificate through the QR code.

## Run it

Build the image (from this directory, after building the agent with
`symbolon-flutter/tools/bundle-agent.sh`):

    ./build.sh            # this machine
    ./build.sh --multi    # amd64 + arm64, for a NAS

Set the box up once. Pass every address your devices reach it at: the LAN
address, and a WireGuard or Tailscale address for use away from home.

    mkdir data && sudo chown 65532:65532 data
    docker compose run --rm symbolon-home home init /data 192.168.1.20 10.8.0.1

Invite each person. This prints a pairing link; show it as a QR code, or send
it to them:

    docker compose run --rm symbolon-home home invite /data alice
    # symbolon://pair?h=192.168.1.20&p=47100&c=...&f=...

Start it:

    docker compose up -d

In the app on the phone: **Set up this device**, then **Scan the code**.
Choose a PIN (and, on a phone with a fingerprint, let it unlock Symbolon),
and wait while the phone and the box make the key together. That is real
work for a phone: a few minutes, with the app kept open. Then write down
the recovery sheet.

## Network

The box listens on ports 47100 to 47104 (pairing, relay, three witnesses).

- **At home**: publish them on the LAN address only (see `compose.yaml`).
- **Away**: reach the box over your VPN (WireGuard, Tailscale). Don't
  forward these ports on the router.
- If the phone can't reach the box, the vault still opens read-only from
  the phone's own copy. Signing in with a passkey needs the box.

## Hardware

- **Key generation** (once per person) peaks near 1.2 GB on the box, and
  near 1.7 GB on the phone.
- **Adding a second device** to someone's identity (a re-share) currently
  needs up to about 10 GB in one process. Plan for a box with enough RAM,
  or wait for the memory work.
- **Disk**: a few megabytes per person.

## Back it up

`data/` holds the cosigners' keys. Losing it means each person must recover
with their recovery sheet. Back it up like any other secret, encrypted.
