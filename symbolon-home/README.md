# Symbolon Home

One box for a household: a NAS, a mini PC or a Raspberry Pi runs what the
family's Symbolon devices need.

- **The relay**: stores each person's encrypted vault and identity log on
  the box's disk. Nothing on it can be read without the person's devices.
- **A cosigner per person**: holds the second share of each key, so a
  stolen phone can't sign alone.
- **Witnesses**: record every change to an identity. The box runs one of
  them; at least two more run **outside the box** (a household computer, or
  a hosted witness), so the box alone is never a majority and cannot vouch
  for a change by itself.
- **Pairing**: a one-time QR code per person. The phone scans it and sets
  itself up.

The box makes its own small certificate authority, so it needs no domain and
no Let's Encrypt. Phones pin the box's certificate through the QR code.

## The keys are sealed

The cosigners' keys, the witness key and the certificate keys are stored
**sealed** on the box's disk: encrypted under a box key that is itself
sealed to the box's **TPM** (a TPM 2.0 chip, when the box has one) or, without
one, to a **passphrase** (stretched with Argon2id). `home serve` unseals the
keys into memory (`/dev/shm`) when it starts, and only then. A copy of the
disk, or a backup of `data/`, is useless without the TPM or the passphrase.

- With a TPM, the box starts by itself. A disk moved to another machine does
  not open.
- With a passphrase, the box needs it at every start. Give it from a file
  you mount when you start the box (`HOME_PASSPHRASE_FILE`, a Docker
  secret), or type it (`docker compose run -it ... home serve /data`). Keep
  that file **off the box's disk and out of its backups**. Use five or more
  random words.

## Witnesses outside the box

Pick two (or more) witnesses that do not run on the box:

- **A household computer** that is usually on (a desktop, a second small
  computer). On it:

      symbolon witness keygen ~/witness.key          # prints its KEY
      # after `home init` (below), on the box:
      #   home witness-cert /data pc.lan /data/pc-witness
      # copy pc-witness/server.pem and server.key to the computer, then:
      symbolon witness serve ~/witness 47110 ~/witness.key 0 --bind 192.168.1.30 \
          --tls server.pem server.key

- **A hosted witness** you trust to be independent: its `HOST:PORT:KEY`,
  and its CA certificate (`--witness-ca FILE`) if it is not under the box's
  CA.

A witness outside the box should be in a different place from it where it
can (a computer in another room counts less than a hosted one, but it is
still a second machine to steal).

## Run it

Build the image (from this directory, after building the agent with
`symbolon-flutter/tools/bundle-agent.sh`):

    ./build.sh            # this machine
    ./build.sh --multi    # amd64 + arm64, for a NAS

Set the address your devices use, and (without a TPM) the passphrase file:

    echo HOME_ADDR=192.168.1.20 > .env
    echo HOME_PASSPHRASE_FILE=/media/usb/symbolon-home.pass >> .env

Set the box up once. Pass every address your devices reach it at (the LAN
address, and a WireGuard or Tailscale address for use away from home) and
the witnesses outside the box. Inside the container it listens on every
interface (`--bind 0.0.0.0`); compose publishes the ports on `HOME_ADDR`
only.

    mkdir data && sudo chown 65532:65532 data
    docker compose run --rm symbolon-home home init /data 192.168.1.20 10.8.0.1 --bind 0.0.0.0 \
        --witness pc.lan:47110:KEY1 --witness witness.example.org:443:KEY2

Without Docker, `home init` listens on the first address given (`--bind`
to choose another); a name as the first host needs `--bind ADDR`.

Invite each person. This prints a pairing link; show it as a QR code:

    docker compose run --rm symbolon-home home invite /data alice
    # symbolon://pair?h=192.168.1.20&p=47100&c=...&f=...

**The link is a bearer secret**: whoever has it first can pair as that
person. It works once (the first device to fetch the setup spends it) and
for a day. Show it in person; don't post it in a group chat or an email.

Start it:

    docker compose up -d

In the app on the phone: **Set up this device**, then **Scan the code**.
Choose a PIN (and, on a phone with a fingerprint, let it unlock Symbolon),
and wait while the phone and the box make the key together. That is real
work for a phone: a few minutes, with the app kept open. Then write down
the recovery sheet, and keep it locked away, apart from the box and its
backups. A kit passphrase (SPEC 10.6), which the sheet would then need too,
is recommended; this version of the app does not offer one yet.

`home status /data` prints, as JSON, whether the keys are sealed and the
witnesses outside the box are a majority.

## Securing an existing box

A box set up before this version keeps its keys unsealed and runs all three
witnesses itself. `home serve`, `home invite` and the app remind you until
it is secured. Stop the box, then:

    docker compose down
    docker compose run --rm symbolon-home home secure /data \
        --witness pc.lan:47110:KEY1 --witness witness.example.org:443:KEY2
    docker compose up -d

This seals every key on the box (TPM, else the passphrase), and people
invited from now on get the box's one witness and the two outside it. People
paired before keep their identities as they are, on the box's three
witnesses until one of their devices moves them. `home secure` prints the
command; on one of each such person's devices, with the box running:

    symbolon device witnesses DEVICE_DIR \
        --add pc.lan:47110:KEY1 --add witness.example.org:443:KEY2 \
        --remove BOX:47103 --remove BOX:47104

It checks that each new witness answers with a time signed by its key, so
a typo is refused, then publishes the change. Removing witnesses always
waits out the recovery delay (three days by default), and any of that
person's devices can veto it in that time (`device veto`). The new
witnesses need certificates the device already trusts: under the box's CA
(`home witness-cert`), or a hosted witness whose CA the device was given.
The reminder names a person until the change is in force.

## Network

The box listens on ports 47100 to 47104 (pairing, relay, the box's
witness; a box set up before this version runs three witnesses there).

- **At home**: compose publishes them on `HOME_ADDR` only, and refuses to
  start without it.
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
- **Unsealing with a passphrase** takes a few seconds and about 0.6 GB at
  start.
- **Disk**: a few megabytes per person.

## Back it up

`data/` holds the cosigners' keys (sealed). Losing it means each person
must recover with their recovery sheet.

**A backup of `data/` plus the box's passphrase (or the box's TPM) plus a
person's recovery sheet is that person's identity.** Treat them that way:
keep the backup encrypted, the passphrase apart from it, and the recovery
sheets somewhere else again (with a kit passphrase once the app offers
one). A backup of a TPM-sealed box opens only with that box's TPM: if the
box itself dies, each person recovers with their recovery sheet.
