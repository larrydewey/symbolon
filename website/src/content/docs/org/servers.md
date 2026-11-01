---
title: Running the servers
description: The relay, witnesses and cosigners for a company: storage, TLS, scale.
---

A company runs the same pieces as Symbolon Home, on its own servers:

```sh
symbolon relay serve /srv/relay 443 --tls chain.pem key.pem --bind 0.0.0.0 \
    --ca witnesses-ca.pem --console-origin https://relay.acme.example \
    --store @/etc/symbolon/store
symbolon witness keygen /srv/w1.key
symbolon witness serve /srv/w1 8443 /srv/w1.key --tls chain.pem key.pem --bind 0.0.0.0
symbolon cosigner serve /srv/cosigner-alice
```

Witnesses should run apart from the relay, ideally in different places and
run by different people: they are what stops a relay from rewriting history.

## Storage

The relay keeps everything in one store, given by `--store` (`@FILE` reads
it from a file, so the password is not on a command line):

| Store | `--store` |
|---|---|
| A directory (default) | the relay's directory |
| PostgreSQL | `postgres://USER:PASSWORD@HOST:PORT/DB` |
| PostgreSQL over TLS | `postgres://…/DB?sslmode=verify-full`, with `--store-ca ca.pem` |
| S3 or compatible | `s3://KEY-ID:SECRET@HOST:PORT/BUCKET?region=R` (`--store-ca` for HTTPS) |

PostgreSQL: one table, `symbolon_objects`, made on start; SCRAM-SHA-256
authentication; objects written once (log events, mailbox messages, audit
events) use `ON CONFLICT DO NOTHING`, so one writer wins across relays. S3:
Signature Version 4, with `If-None-Match: *` for objects written once.

Sessions, sign-in challenges, the directory and suspensions live in the
store too, so the relay keeps nothing of its own: run several behind a load
balancer.

## Health

`GET /healthz` answers `ok`.

## Memory

Key generation for a person peaks near 1.2 GB on the cosigner's host; adding
a device to an identity currently needs up to about 10 GB in one process.
