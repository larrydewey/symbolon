#!/usr/bin/env python3
# A stand-in for the app's SSH consent window (--ssh-consent REQUEST) in
# tests/ssh_e2e.sh: it records the request, signs with
# `symbolon device ssh sign` as the window does and sends the signature,
# or cancels, or sends a signature over other data.
import json, os, socket, subprocess, sys

assert sys.argv[1] == "--ssh-consent"
req = json.load(open(sys.argv[2]))
with open(os.environ["STUB_LOG"], "a") as f:
    f.write(json.dumps(req) + "\n")
mode = open(os.environ["STUB_MODE"]).read().strip()
if mode == "cancel":
    answer = "cancel\n"
else:
    data = req["data"] if mode == "sign" else os.urandom(32).hex()
    alg = [req["alg"]] if req.get("alg") else []
    r = subprocess.run([os.environ["SYMBOLON_BIN"], "device", "ssh", "sign", os.environ["SYMBOLON_DIR"], req["key"]] + alg,
                       input=f"2468\n{data}\n", capture_output=True, text=True)
    sig = [l.split()[1] for l in r.stdout.splitlines() if l.startswith("signature ")]
    answer = "ok " + (sig[0] if sig else "") + "\n"
# The token line and the answer in one write: the agent must take the
# answer that arrives in the same read as the token (a window that answers
# at once).
s = socket.socket(socket.AF_UNIX)
s.connect(req["socket"])
s.sendall((req["token"] + "\n" + answer).encode())
s.close()
