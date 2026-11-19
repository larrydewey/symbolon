#!/usr/bin/env python3
"""The agent for one connection on stdin/stdout (SPEC 16.1.1, Android's
agent service): `symbolon ssh-agent-stdio DIR RUNDIR PEER`.

The consent window is played here: it reads the request file the agent
announces ("consent PATH" on stderr), checks the request names the peer
and the bound server, and answers on the per-request socket after the
one-time token, as Symbolon's SshConsentActivity does on Android. The
signature is made with the test key itself (the real window runs
`device ssh sign`, unchanged from the desktop agent).

    ssh_stdio_e2e.py SYMBOLON
Checks: identities without consent; session-bind checked (a forged one
refused); a signature through the platform consent, verified by the
agent; cancel refused; a signature over other data refused; request
files removed.
"""
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def sstr(b):
    return struct.pack(">I", len(b)) + b


def msg(t, body=b""):
    return struct.pack(">I", len(body) + 1) + bytes([t]) + body


def main():
    bin_ = sys.argv[1]
    w = tempfile.mkdtemp()
    dev, run = f"{w}/dev", f"{w}/run"
    os.makedirs(dev)
    os.makedirs(f"{run}/symbolon", mode=0o700)
    user = ed25519.Ed25519PrivateKey.generate()
    pub = user.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    blob = sstr(b"ssh-ed25519") + sstr(user.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    with open(f"{dev}/ssh-keys", "w") as f:
        f.write(b"ed".hex() + " " + pub + " ed@test\n")
    p = subprocess.Popen([bin_, "ssh-agent-stdio", dev, run, "Pylon (dev.pylon.pylon)"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    mode = {"m": "sign"}
    seen = []

    def window():
        for line in iter(p.stderr.readline, b""):
            l = line.decode().strip()
            if not l.startswith("consent "):
                continue
            req = json.load(open(l[8:]))
            seen.append(req)
            data = bytes.fromhex(req["data"])
            if mode["m"] == "cancel":
                ans = "cancel\n"
            else:
                signed = data if mode["m"] == "sign" else data + b"x"
                sig = sstr(b"ssh-ed25519") + sstr(user.sign(signed))
                ans = "ok " + sig.hex() + "\n"
            s = socket.socket(socket.AF_UNIX)
            s.connect(req["socket"])
            s.sendall((req["token"] + "\n" + ans).encode())
            s.close()

    threading.Thread(target=window, daemon=True).start()

    def call(t, body=b""):
        p.stdin.write(msg(t, body))
        p.stdin.flush()
        n = struct.unpack(">I", p.stdout.read(4))[0]
        r = p.stdout.read(n)
        return r[0], r[1:]

    t, body = call(11)
    assert t == 12 and struct.unpack(">I", body[:4])[0] == 1, (t, body[:8])
    assert blob in body
    host = ed25519.Ed25519PrivateKey.generate()
    hblob = sstr(b"ssh-ed25519") + sstr(host.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    sid = os.urandom(32)
    forged = sstr(b"session-bind@openssh.com") + sstr(hblob) + sstr(sid) + sstr(sstr(b"ssh-ed25519") + sstr(b"\0" * 64)) + b"\0"
    assert call(27, forged)[0] == 5, "a forged session-bind was accepted"
    bind = sstr(b"session-bind@openssh.com") + sstr(hblob) + sstr(sid) + sstr(sstr(b"ssh-ed25519") + sstr(host.sign(sid))) + b"\0"
    assert call(27, bind)[0] == 6, "the session-bind was refused"
    data = b"data for pylon"
    t, body = call(13, sstr(blob) + sstr(data) + struct.pack(">I", 0))
    assert t == 14, f"no signature ({t})"
    sig = body[4:]
    assert sig[4 + 11 + 4:] == user.sign(data)
    req = seen[-1]
    assert req["peer"] == "Pylon (dev.pylon.pylon)" and req["key"] == "ed" and req["host"]["fingerprint"].startswith("SHA256:"), req
    mode["m"] = "cancel"
    assert call(13, sstr(blob) + sstr(data) + struct.pack(">I", 0))[0] == 5, "signed after cancel"
    mode["m"] = "other"
    assert call(13, sstr(blob) + sstr(data) + struct.pack(">I", 0))[0] == 5, "a signature over other data was passed on"
    p.stdin.close()
    p.wait(timeout=10)
    left = [f for f in os.listdir(f"{run}/symbolon")]
    assert not left, f"request files left behind: {left}"
    print("PASS ssh_stdio_e2e")


if __name__ == "__main__":
    main()
