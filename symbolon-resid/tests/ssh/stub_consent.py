#!/usr/bin/env python3
# A stand-in for the app's SSH consent window (--ssh-consent REQUEST) in
# tests/ssh_e2e.sh: it records the request, connects to the agent's
# per-request socket and sends the token, then (STUB_ANSWER) signs with
# `symbolon device ssh sign` as the window does and sends the signature,
# or cancels, or sends a signature over other data.
import json, os, socket, subprocess, sys

assert sys.argv[1] == "--ssh-consent"
req = json.load(open(sys.argv[2]))
with open(os.environ["STUB_LOG"], "a") as f:
    f.write(json.dumps(req) + "\n")
mode = open(os.environ["STUB_MODE"]).read().strip()
s = socket.socket(socket.AF_UNIX)
s.connect(req["socket"])
s.sendall((req["token"] + "\n").encode())
if mode == "cancel":
    s.sendall(b"cancel\n")
else:
    data = req["data"] if mode == "sign" else os.urandom(32).hex()
    r = subprocess.run([os.environ["SYMBOLON_BIN"], "device", "ssh", "sign", os.environ["SYMBOLON_DIR"], req["key"]],
                       input=f"2468\n{data}\n", capture_output=True, text=True)
    sig = [l.split()[1] for l in r.stdout.splitlines() if l.startswith("signature ")]
    s.sendall(("ok " + (sig[0] if sig else "") + "\n").encode())
s.close()
