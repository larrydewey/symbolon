---
title: Organizations
description: Symbolon for a company: owners and administrators, groups and group folders, policy, audit, directory sync.
---

An organization lets a company use Symbolon for its people without holding
their keys. Everything that matters is a record signed on someone's own
device and checked by every other device; the servers store and serve, and
add access control on top.

## The pieces

- **Governance**: a chain of records naming the owners, the administrators,
  the policy and the recovery setting. Version 1 is signed by the founder,
  whose identity is bound into the organization's id; each later version by
  an owner of the version before. A device checks the whole chain, so a
  server cannot hand it another organization or an older policy.
- **Membership**: who is in the organization, with their directory id, and
  its groups. Signed by an owner or administrator under the latest
  governance.
- **Group folders**: shared folders whose people are a group's members plus
  every owner and administrator. Nobody adds people by hand; the groups
  decide. Someone who leaves a group loses the folder at once, and the next
  sync gives it a new key.
- **Policy**: rules every member device follows. See [Policy](/symbolon/org/policy/).
- **Audit log**: every device signs and chains the events it causes. See
  [Policy › Audit](/symbolon/org/policy/#audit).

## Roles

| Role | Can |
|---|---|
| Owner | everything an administrator can, plus roles, policy and recovery |
| Administrator | add and remove people, groups and group folders, invite, sync |
| Member | use the group folders of their groups |

## What the company cannot do

- Open anyone's own vault, or use their passkeys. Those stay under the
  person's own key.
- Sign for anyone: the servers hold no member's or administrator's key.
- Read a work folder, unless the owners turned on [recovery](/symbolon/org/recovery/),
  and then only with several administrators, after a waiting period the
  person is told about.

## Pages

- [Setup](/symbolon/org/setup/): founding, inviting, joining, managed phones.
- [Directory](/symbolon/org/directory/): SCIM from Okta, Entra ID or Google.
- [Policy](/symbolon/org/policy/): PINs, passwords, offline copies, attestation, audit.
- [Recovery](/symbolon/org/recovery/): the opt-in recovery of work folders.
- [Console](/symbolon/org/console/): the administrators' console.
- [Running the servers](/symbolon/org/servers/): storage, TLS, scale.
