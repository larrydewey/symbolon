---
title: Browser extension
description: Fill logins and cards in your browser, approved in a Symbolon window the page cannot reach.
---

The Symbolon extension fills logins and payment cards from your vault in
Chromium-based browsers (Chromium, Chrome, Brave, Edge, Vivaldi) on Linux.
It holds nothing itself: no passwords, no PIN, no copy of the vault. Each
fill is asked of the agent on your computer and approved by you in a
Symbolon window, outside the page.

## Install

From the [release](https://github.com/larrydewey/symbolon/releases), take
`symbolon-extension-<version>.zip`, the agent (`symbolon-<version>-linux-x86_64`)
and the desktop app. Then:

```sh
unzip symbolon-extension-*.zip -d ~/.local/share/symbolon/extension
cd ~/.local/share/symbolon/extension
./install.sh /usr/local/bin/symbolon /path/to/symbolon_ui
```

`install.sh` registers the agent with your browsers (and Firefox) as the
extension's *native messaging host*, the one program the extension may
talk to. Then open `chrome://extensions`, turn on **Developer mode**,
choose **Load unpacked** and pick that directory. Run `install.sh` again if
you move the agent or the app.

Firefox can load it from `about:debugging` (**Load Temporary Add-on**, pick
`manifest.json`); it is not yet tested there.

## Filling

On a sign-in page or a checkout, press the extension's toolbar button or
**Ctrl+Shift+L**. A Symbolon window opens. It shows:

- the site, as your browser reports it, not as the page says;
- any payment processor's frame that would receive card fields;
- the program that asked (your browser; a warning in red if it is not one).

Type your PIN and choose the login or card. The fields fill as if you had
typed them. A login is offered only on the exact site it was saved for.

Nothing fills when you click inside a page, and nothing fills on its own
when a page loads: a page cannot trick you into approving something by
drawing over the window, because the window is not part of the page.

## Where card fields go

Most checkouts keep the card number in a frame served by their payment
processor, so the shop never sees it. Symbolon fills card fields into:

- the page's own frames, and
- the frames of a short list of payment processors, matched exactly:
  Stripe (`js.stripe.com`), Braintree, Adyen and Square.

Any other frame on the page, an ad for instance, receives nothing. Login
fields only ever go to the site's own frames.

## When it says no

The button's tooltip tells you why when nothing was filled: the page is
not https, no field there may be filled, the window was closed, or the
login is for another site. If the page changes while the window is open,
nothing is filled.

On a tiling window manager (Hyprland, sway) the Symbolon window opens
tiled; to have it float, add a rule for the class
`dev.symbolon.symbolon_ui`.
