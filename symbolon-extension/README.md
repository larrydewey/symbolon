# Symbolon browser extension

Fills logins and payment cards from Symbolon in Chromium-based browsers and
Firefox. The extension holds nothing. When you press the toolbar button or
Ctrl+Shift+L, it finds the login and card fields in each frame of the page
and asks the agent for values. The agent opens the Symbolon window, outside
the page, which shows the site, takes your PIN and lets you choose the item.
The agent then checks the item against the page and sends back only the
fields each frame may receive. See SPEC sections 22.2 and 22.5.

Card fields may also go into a payment processor's frame (Stripe,
Braintree, Adyen, Square) on another site's checkout. Login fields go only
to the site they were saved for.

## Install (development)

1. Build the agent (`symbolon-resid`: `target/symbolon`) and the app
   (`symbolon-flutter`: `flutter build linux`).
2. Register the agent as the extension's native messaging host:

       ./install.sh ../symbolon-resid/target/symbolon \
           ../symbolon-flutter/build/linux/x64/release/bundle/symbolon_ui

3. Load this directory as an unpacked extension (`chrome://extensions`,
   Developer mode, "Load unpacked"). The key in `manifest.json` gives it
   the ID `kkhginlcfndkhicoihlaccmmahljipjp`, which `install.sh` allows. In
   Firefox, load `manifest.json` from `about:debugging`.

On Hyprland and other tiling window managers the Symbolon window opens
tiled. To float it, add a rule for the class `dev.symbolon.symbolon_ui`.

## Tests

`symbolon-resid/tests/browser_e2e.sh` runs headless Chromium with this
extension against local test sites that keep their real origins. A
stand-in plays the Symbolon window. The tests check that the card goes into
the processor's frame and the cardholder name onto the page, that the ad
frame and every password field get nothing, that a login fills only on its
own site, and that cancel, a login for another site and an answer without
the token are refused.
