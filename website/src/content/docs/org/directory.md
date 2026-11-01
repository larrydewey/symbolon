---
title: Directory
description: SCIM 2.0 from Okta, Microsoft Entra ID or Google Workspace.
---

The relay speaks SCIM 2.0 (RFC 7643, RFC 7644), so the company's identity
provider can tell it who works there. A member's directory id matches a
directory user by `userName` (ignoring case) or `externalId`.

## Connect the identity provider

Make a bearer token on the relay's host:

```sh
symbolon relay scim-token /srv/relay ORG-ID
```

In the identity provider, add a SCIM app with the base URL
`https://RELAY-HOST:PORT/scim/v2` and that token. Users and Groups support
create, read, filters (`userName`, `externalId`, `displayName` eq), replace,
patch (including Entra's string booleans and `members[value eq "…"]`
paths) and delete.

## What happens when

The directory cannot sign anything a device trusts, so it acts in two ways:

**At once, at the relay** (the directory can take away, never give):

- a user made inactive or deleted is cut off: sign-in is refused and their
  sessions stop;
- a directory group that drops someone takes away the group folders they had
  only through the organization's group of the same name. Owners and
  administrators keep every group folder.

**At the next sync**, signed by an owner's or administrator's device:

- members whose directory id the directory no longer lists are removed (an
  administrator stays until an owner takes the role), and their folders get
  new keys;
- each directory group sets the members of the organization's group of the
  same name, made if there is none;
- each directory user who is neither a member nor invited gets an invite,
  once; sync prints the code to deliver.

Members added by hand, with no directory id, are never touched.
