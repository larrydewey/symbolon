#!/usr/bin/env python3
"""Drives `symbolon device vault signin-bitwarden` the way the app does, for
tests/bitwarden_e2e.sh.

  bw_converse.py WANT.json ACCOUNT PIN -- COMMAND...

Sends the account's email and master password; answers "need 2fa" with the
authenticator code (from the account's TOTP secret in WANT.json) and
"need newdevice" with "cancel"; at "ready" sends "import" and PIN (PIN "-"
means a dry run: nothing more is sent). Prints every line the agent wrote,
hex fields decoded ("item login bank -", "fail ..."), and exits with the
agent's status.
"""
import json, os, subprocess, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bw_fixture


def unhex(h):
    try:
        return bytes.fromhex(h).decode()
    except ValueError:
        return h


def main():
    want, acct, pin = json.load(open(sys.argv[1])), sys.argv[2], sys.argv[3]
    cmd = sys.argv[sys.argv.index("--") + 1:]
    a = want[acct] if acct in want else {"email": acct, "password": pin}
    password = a["password"] if acct in want else os.environ["BW_PASSWORD"]
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
    p.stdin.write(a["email"] + "\n" + password + "\n")
    p.stdin.flush()
    for line in p.stdout:
        line = line.rstrip("\n")
        w = line.split(" ")
        if w[0] == "need" and w[1] == "2fa":
            code = bw_fixture.totp(a["totp"]) if "totp" in a and "0" in w[2].split(",") else "000000"
            print(f"need 2fa {w[2]}")
            p.stdin.write(f"code 0 {code}\n")
            p.stdin.flush()
        elif w[0] == "need":
            print(line)
            p.stdin.write("cancel\n")
            p.stdin.flush()
        elif w[0] == "ready":
            print("ready")
            if pin != "-":
                p.stdin.write("import\n" + pin + "\n")
                p.stdin.flush()
        elif w[0] in ("item",) and len(w) >= 4:
            print(f"item {w[1]} {unhex(w[2])} {unhex(w[3]) if w[3] != '-' else '-'}")
        elif w[0] in ("skip",) and len(w) >= 3:
            print(f"skip {unhex(w[1])} {unhex(w[2])}")
        elif w[0] in ("warn", "fail") and len(w) >= 2:
            print(f"{w[0]} {unhex(w[1])}")
        else:
            print(line)
    p.wait()
    sys.exit(p.returncode)


if __name__ == "__main__":
    main()
