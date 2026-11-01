---
title: Install
description: Download the app or the agent, or build them from source.
---

## Download

Each [release](https://github.com/larrydewey/symbolon/releases) has:

| File | What |
|---|---|
| `symbolon-<version>.apk` | the Android app, with the agent inside (arm64 phones, x86_64 emulators) |
| `symbolon-<version>-linux-x86_64` | the agent and every server in one static binary, for PCs |
| `symbolon-<version>-linux-aarch64` | the same, for ARM boards and NAS boxes |
| `SHA256SUMS` | checksums: `sha256sum -c SHA256SUMS` |

The APK is signed with a debug key: install it by side-loading (allow
installs from your browser or file manager, then open the file). It is not
on a store yet.

The Linux binaries need nothing else: they are static, with no C library.
Make one executable and put it on your path:

```sh
chmod +x symbolon-*-linux-x86_64
sudo install symbolon-*-linux-x86_64 /usr/local/bin/symbolon
symbolon device status ~/.symbolon     # "not set up" until you set it up
```

## Build from source

The agent is written in [Resid](https://github.com/larrydewey/Resid) and
needs Resid v0.5.2 or later beside this repository:

```sh
git clone https://github.com/larrydewey/Resid.git
git clone https://github.com/larrydewey/symbolon.git
cd Resid && ./boot.sh && ./install.sh && cd ..
cd symbolon/symbolon-resid
tools/depmap.sh
residc src/main.resid -o target/symbolon -depmap target/deps.map
```

The app is Flutter (3.x):

```sh
cd symbolon/symbolon-flutter
tools/bundle-agent.sh            # the agent for Android, into the APK
flutter build apk --release      # or: flutter build linux
```

Symbolon Home's container image is built by `symbolon-home/build.sh`; see
[Symbolon Home](/symbolon/guide/home/).
