#!/usr/bin/env python3
"""Where duress alerts go in tests/duress_alert_e2e.sh, recording what
arrives (one file per message in OUT):

  alert_sinks.py HTTPS_PORT SMTP_PORT CERT KEY OUT

  https://localhost:HTTPS_PORT/TOPIC   ntfy: POST, the body is the text;
                                       wants "Authorization: Bearer tk_test"
  https://localhost:HTTPS_PORT/sms     an SMS gateway: POST form To, Body;
                                       wants "Authorization: Basic dGVzdDp0ZXN0"
  localhost:SMTP_PORT                  SMTP over TLS (port 465 style): AUTH
                                       PLAIN user/secret, then the message
"""
import base64, http.server, os, socket, ssl, sys, threading, time, urllib.parse

HP, SP, CERT, KEY, OUT = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
os.makedirs(OUT, exist_ok=True)


def record(kind, text):
    with open(os.path.join(OUT, f"{kind}-{time.time_ns()}"), "w") as f:
        f.write(text)


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def answer(self, code):
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0"))).decode()
        auth = self.headers.get("Authorization", "")
        if self.path == "/sms":
            if auth != "Basic dGVzdDp0ZXN0":
                return self.answer(401)
            f = urllib.parse.parse_qs(body)
            record("sms", f.get("To", [""])[0] + "\n" + f.get("Body", [""])[0])
            return self.answer(201)
        if auth != "Bearer tk_test":
            return self.answer(401)
        record("ntfy", self.path.lstrip("/") + "\n" + self.headers.get("Title", "") + "\n" + self.headers.get("Priority", "") + "\n" + body)
        return self.answer(200)


def serve_https():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", HP), H)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    srv.serve_forever()


def smtp_session(conn):
    f = conn.makefile("rwb")

    def say(line):
        f.write((line + "\r\n").encode())
        f.flush()

    say("220 sink ESMTP")
    to, mail, authed = "", None, False
    while True:
        line = f.readline()
        if not line:
            return
        l = line.decode().rstrip("\r\n")
        u = l.upper()
        if u.startswith("EHLO") or u.startswith("HELO"):
            f.write(b"250-sink\r\n250 AUTH PLAIN\r\n")
            f.flush()
        elif u.startswith("AUTH PLAIN "):
            parts = base64.b64decode(l[11:]).split(b"\0")
            authed = parts[1:] == [b"user", b"secret"]
            say("235 ok" if authed else "535 no")
        elif u.startswith("MAIL FROM:"):
            say("250 ok" if authed else "530 auth first")
        elif u.startswith("RCPT TO:"):
            to = l[8:].strip().strip("<>")
            say("250 ok")
        elif u == "DATA":
            say("354 go")
            lines = []
            while True:
                d = f.readline().decode().rstrip("\r\n")
                if d == ".":
                    break
                lines.append(d[1:] if d.startswith("..") else d)
            record("mail", to + "\n" + "\n".join(lines))
            say("250 queued")
        elif u == "QUIT":
            say("221 bye")
            return
        else:
            say("500 what")


def serve_smtp():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT, KEY)
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", SP))
    s.listen(8)
    while True:
        c, _ = s.accept()
        try:
            t = ctx.wrap_socket(c, server_side=True)
            threading.Thread(target=lambda: (smtp_session(t), t.close()), daemon=True).start()
        except Exception:
            c.close()


threading.Thread(target=serve_https, daemon=True).start()
threading.Thread(target=serve_smtp, daemon=True).start()
print("ready", flush=True)
while True:
    time.sleep(3600)
