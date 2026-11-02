#!/usr/bin/env python3
# A stand-in for the app's consent window (--fill-consent REQUEST) in
# tests/browser_e2e.sh: it reads the request, records it, and answers with
# the item named by STUB_ANSWER (card, login, other-login, cancel, wrong-token,
# silent) over the host's loopback connection.
import json, os, socket, sys, time

assert sys.argv[1] == "--fill-consent"
req = json.load(open(sys.argv[2]))
with open(os.environ["STUB_LOG"], "a") as f:
    f.write(json.dumps(req) + "\n")
mode = os.environ.get("STUB_ANSWER", "card")
if mode == "silent":
    sys.exit(0)

def hx(s): return s.encode().hex()

items = {
    "card": ("card", {"cardholder": "Ada Lovelace", "number": "4111111111111111", "expiry": "08/29", "cvv": "123", "pin": "9999"}),
    "login": ("login", {"origin": req["top"], "username": "ada@example.com", "current": "pa\"ss\\w0rd é"}),
    "other-login": ("login", {"origin": "https://elsewhere.example", "username": "ada", "current": "x"}),
}
token = "00" * 32 if mode == "wrong-token" else req["token"]
if mode == "squat":
    body = ""
elif mode == "cancel":
    body = token + "\ncancel\n"
else:
    kind, fields = items["card" if mode == "wrong-token" else mode]
    body = token + "\nok " + kind + "\n" + "".join(f"{k} {hx(v)}\n" for k, v in fields.items()) + "end\n"
if mode == "squat":
    # A local process that connects first and sends nothing: the host must
    # drop it and still take the window's connection.
    squatter = socket.create_connection(("127.0.0.1", req["port"]))
    kind, fields = items["card"]
    body = token + "\nok card\n" + "".join(f"{k} {hx(v)}\n" for k, v in fields.items()) + "end\n"
# The window connects and proves the token as it opens, answers later.
s = socket.create_connection(("127.0.0.1", req["port"]))
head, rest = body.split("\n", 1)
s.sendall((head + "\n").encode())
time.sleep(0.3)
s.sendall(rest.encode())
s.close()
