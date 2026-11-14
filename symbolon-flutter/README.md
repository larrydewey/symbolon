# Symbolon app

A Flutter front end to the `symbolon` agent (`../symbolon-resid`), for the
Linux desktop and Android. The app holds no key material: every operation
runs the agent, with PINs and secrets written to its standard input. On
Android the agent ships inside the APK as `lib/<abi>/libsymbolon.so`
(aarch64 for phones, x86_64 for the emulator) and runs as a subprocess.

## Desktop

    ../symbolon-resid: build target/symbolon (see its tests/run.sh)
    tools/demo.sh            # local relay, witnesses, cosigner, an incepted
                             # device, and the app (PIN 2468)

## A phone

On the desktop, with the phone on the same network:

    tools/bundle-agent.sh                    # the agent for Android
    flutter build apk --debug
    adb install -r build/app/outputs/flutter-apk/app-debug.apk
    tools/demo.sh --lan                      # prints http://<address>:47000

In the app (after the short tour, which can be skipped): Set up this device >
the printed URL > Connect, choose a PIN, Create my identity, and write down
the kit. Passkeys, the vault and the rest then work against the desktop's
stack. The phone must reach the desktop on
ports 47000-47013 (open them in the firewall if one runs).

The demo is not for real use: the Paillier keys of the inception are test
fixtures. On a phone (Android 9+) setup keeps the unlock keys and the
device key in the Android Keystore, in StrongBox where the phone has it;
the app serves the Keystore to the agent on loopback. On a Linux desktop
with a TPM 2.0 the user can open (/dev/tpmrm0, the tss group), setup uses
the TPM; More > Hardware key store says how to turn one on.

## Passkeys for sites and apps (Android 14+)

Symbolon is a passkey provider: Passkeys > Turn on Symbolon for passkeys
(or Settings > Passwords, passkeys and accounts). Sites in browsers that
support third-party providers, and apps, then offer Symbolon passkeys;
on a computer, "Use a phone or tablet" shows a QR code to scan with the
phone. To try it without a public site:

    tools/webauthn_site.py                   # a python-fido2 relying party on :8765
    adb reverse tcp:8765 tcp:8765            # then open http://localhost:8765 on the phone

Debug builds also have More > Settings > Developer: system passkeys, which
asks Android for a passkey as an app would.

## The icon

The launcher icon, its themed (monochrome) layer and the splash screen are
made from one drawing of the mark, a token broken in two:

    tools/icon/make_icons.py                 # rewrites android/app/src/main/res

The app draws the same mark itself (lib/brand.dart).

## Tests

    flutter test                             # unit and widget tests, and one
                                             # against the real agent
    flutter test integration_test/phone_demo_test.dart -d <device> \
      --dart-define=DEMO_URL=http://<address>:47000   # the phone flow, with
                                             # tools/demo.sh --lan running

The Android build needs a JDK of 17 or 21 (`flutter config --jdk-dir`).
