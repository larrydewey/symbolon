---
title: Recovery
description: The opt-in recovery of work folders: several administrators, a waiting period, the person told.
---

By default no one can open a person's folders but that person. An
organization's owners may turn on recovery for **work folders**: shared
folders a person owns and chooses to escrow. A person's own vault is never
escrowed.

## Turn it on

```sh
printf '%s\n' "$PIN" | symbolon device org recovery on ~/.symbolon 2 259200 ADMIN-LOG,ADMIN-LOG,ADMIN-LOG
```

The owner's device makes a recovery key, splits it so that any 2 (here) of
the named recovery administrators can rebuild it (Shamir), wraps each share
to that administrator's devices, and forgets the key. The governance records
the public key, the threshold, the administrators and the waiting period, so
every member sees that recovery is on.

The waiting period is in seconds. Under 72 hours (259200) needs
`--short-delay`, so an owner sets a short one only on purpose.

## Escrow a work folder

```sh
printf '%s\n' "$PIN" | symbolon device org escrow ~/.symbolon FOLDER-ID
```

The folder's key is sealed to the recovery key. The owner's device escrows
it again by itself whenever the folder's people or key change.

## Open one

1. A recovery administrator asks: `org recover request DIR FOLDER-ID`. The
   folder's owner sees it at once (**More › Organization**, and `org show`),
   with the time it can open.
2. After the waiting period, by the witnesses' time, enough recovery
   administrators approve: `org recover approve DIR FOLDER-ID`.
3. The requester opens it: `org recover open DIR FOLDER-ID`.

The waiting period is enforced twice: approving devices refuse before it
ends, and the relay serves the escrow to no one but its owner before then,
by its own clock. Every step is in the audit log.
