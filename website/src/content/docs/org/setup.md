---
title: Setup
description: Founding an organization, inviting people, joining, and phones the company manages.
---

## Found it

On the founder's device:

```sh
printf '%s\n' "$PIN" | symbolon device org new ~/.symbolon Acme
# prints: ORG-ID FOUNDER-LOG-ID
```

Give people both values: together they name the organization, and a device
checks that the organization's id comes from that founder.

## Invite people

An invite is for one person of the company directory: their directory id
(usually the work e-mail), a name, and optionally groups.

```sh
printf '%s\n' "$PIN" | symbolon device org invite ~/.symbolon erin@acme.example Erin GROUP-ID
# prints: CODE ID
```

The code works once, for 14 days. Deliver it through the company: work
e-mail, device management, or the console. The code is a key: the person's
device signs with it, so neither the server nor anyone who sees the answer
learns it.

In the app, **More › Organization › Invite someone** does the same.

## Join

On the person's device (**More › Organization**, which the code fills in on
managed phones):

```sh
printf '%s\n' "$PIN" | symbolon device org join ~/.symbolon ORG-ID FOUNDER-LOG-ID CODE
```

The device checks the governance chain, answers the invite, and waits. The
next **sync** by an owner or administrator adds the person with the
invite's directory id, name and groups.

## Sync

`symbolon device org sync` (or **Sync** in the app) is the administrators'
routine:

1. adds the people who answered invites;
2. applies the company directory (see [Directory](/symbolon/org/directory/));
3. checks devices' platform attestation (see [Policy](/symbolon/org/policy/#attestation));
4. gives a new key to every group folder someone left, and key wraps to
   anyone new.

A company can run it on a schedule on a dedicated administrator's device.

## People and groups

```sh
symbolon device org members ~/.symbolon          # no PIN
symbolon device org group new ~/.symbolon Engineering
symbolon device org group add ~/.symbolon GROUP-ID LOG-ID
symbolon device org folder new ~/.symbolon Deploy-keys GROUP-ID
symbolon device org role ~/.symbolon LOG-ID admin   # an owner
symbolon device org remove ~/.symbolon LOG-ID
```

Group folders then work like any shared folder: `device vault ... --share
ID`, and they appear in the app's Sharing list.

## Managed phones

With Android device management (managed configurations), the company can
set the app up for its people:

| Key | Meaning |
|---|---|
| `org_id` | the organization's id |
| `org_founder` | the founder's log id |
| `invite_code` | this person's invite code |
| `disable_duress` | hide the duress setting |

The person still chooses their own PIN; device management carries no keys.
