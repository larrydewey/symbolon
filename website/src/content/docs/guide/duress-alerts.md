---
title: Duress alerts
description: Tell people you choose when you unlock with your duress PIN, with your phone's last known location.
---

When you unlock Symbolon with your duress PIN, your Symbolon Home box can
tell people you choose: the time, and your phone's last known location
with a map link. The alert comes from the box, not your phone. Your phone
shows nothing different and sends nothing different: every unlock, with
either PIN, sends the box the same small message.

When the duress window ends, they are told again: when it runs out, or
when you end it from another of your devices.

## Choose who is told

**More › Duress alerts**, unlock with your real PIN, then **Add someone**.
For each person, choose any of:

- **ntfy notification**: a push notification through the ntfy server on
  your box. After saving, each person gets a topic; they subscribe to it
  in the ntfy app (copy it with the button next to their name).
- **Email** and **Text message**: sent by the box, through the mail
  account and text-message gateway your box is set up with.
- **Their Symbolon**: someone in your household with their own account
  on the same box. On their phone: **More › Duress alerts › Receive
  household alerts here**. Their phone checks every 15 minutes and when
  Symbolon opens, and shows a notification.
- **Threnody**: their Threnody fingerprint, when your box runs Threnody.

Then **Save**. The app asks once for permission to read the phone's
location (allow it, or alerts say "location unknown"). It never asks for
a new location fix: it reads the one the phone already has, so no
location icon appears.

Under the duress PIN, this page shows no one and changes nothing. While a
duress window is open, no one can change the list, so it cannot be
switched off under pressure.

## When you are safe

On another of your devices: **More › Duress alerts › I'm safe: end the
alert**, with your real PIN. The phone you unlocked under duress cannot
end its own alert. Everyone is told the alert ended.

## Setting up the box

The box needs to know how to send. On the box:

```sh
symbolon home alerts ~/home-box set ntfy_url https://ntfy.example.lan
symbolon home alerts ~/home-box set ntfy_token tk_...
symbolon home alerts ~/home-box set smtp_host smtp.example.com
symbolon home alerts ~/home-box set smtp_user home@example.com
symbolon home alerts ~/home-box set smtp_pass '...'
symbolon home alerts ~/home-box set smtp_from home@example.com
symbolon home alerts ~/home-box set sms_url https://api.twilio.com/2010-04-01/Accounts/AC.../Messages.json
symbolon home alerts ~/home-box set sms_auth 'Basic ...'
symbolon home alerts ~/home-box set sms_body 'To={to}&From=%2B15550000000&Body={text}'
symbolon home alerts ~/home-box set tz MST            # the label alerts show
symbolon home alerts ~/home-box set tz_minutes -420    # its offset from UTC
symbolon home alerts ~/home-box          # shows them, passwords as (set)
```

Set only the channels you use. Mail goes over TLS on port 465
(`smtp_port` to change it). `sms_type json` sends a JSON body instead of a
form. `ca` names a PEM file of certificate authorities, for servers with
your own certificates. `threnody` names the Threnody binary.

## What to know

- A coercer near one of your contacts might see the alert, and a contact
  who reacts might be noticed. Choose people who will act carefully.
- The location is wherever the phone last had a fix. Alerts say how old
  it is and how accurate.
- The box must be reachable from the phone when you unlock. A phone with
  no network sends nothing then; the alert goes out at the next duress
  unlock that reaches the box.
