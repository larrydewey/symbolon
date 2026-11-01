#!/usr/bin/env python3
"""A relying party for tests/rotate_e2e.sh: sign-in, an account page and a
change-password form, with plain HTML forms (no scripts). The password is
kept in DIR/password; DIR/mode set to "refuse" makes the change form fail
without changing anything.

    site.py DIR PORT
"""
import html, http.server, os, secrets, sys, urllib.parse

DIR, PORT = sys.argv[1], int(sys.argv[2])
SESSIONS = {}


def read(name, default=''):
    try: return open(os.path.join(DIR, name)).read().strip()
    except FileNotFoundError: return default


def page(title, body):
    return f'<!doctype html><html><head><title>{title}</title></head><body>{body}</body></html>'.encode()


LOGIN = ('<form method="post" action="/login"><input id="user" name="user" type="text" autocomplete="username">'
         '<input id="pw" name="pw" type="password" autocomplete="current-password"><button id="go" type="submit">Sign in</button></form>')
CHANGE = ('<form method="post" action="/account/password"><input id="old" name="old" type="password" autocomplete="current-password">'
          '<input id="new" name="new" type="password" autocomplete="new-password"><button id="save" type="submit">Save</button></form>'
          '<form method="post" action="/account/delete"><button id="delete" type="submit">Delete account</button></form>')


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def user(self):
        for part in self.headers.get('Cookie', '').split(';'):
            k, _, v = part.strip().partition('=')
            if k == 'sid' and v in SESSIONS: return SESSIONS[v]
        return None

    def send(self, code, body, extra=()):
        self.send_response(code)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        for k, v in extra: self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def form(self):
        n = int(self.headers.get('Content-Length', '0'))
        return {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(n).decode(), keep_blank_values=True).items()}

    def do_GET(self):
        u = self.user()
        if self.path == '/login': return self.send(200, page('Sign in', LOGIN))
        if self.path == '/account' and u: return self.send(200, page('Account', f'<div id="account">Signed in as {html.escape(u)}</div>'))
        if self.path == '/account/password' and u: return self.send(200, page('Change password', CHANGE))
        return self.send(303, b'', [('Location', '/login')])

    def do_POST(self):
        f = self.form()
        if self.path == '/login':
            if f.get('user') == read('user') and f.get('pw') == read('password'):
                sid = secrets.token_hex(16); SESSIONS[sid] = f['user']
                return self.send(303, b'', [('Location', '/account'), ('Set-Cookie', f'sid={sid}; Path=/; HttpOnly')])
            with open(os.path.join(DIR, 'failed-logins'), 'a') as fh: fh.write('1\n')
            return self.send(200, page('Sign in', '<p>Wrong password</p>' + LOGIN))
        u = self.user()
        if self.path == '/account/password' and u:
            if read('mode') == 'refuse' or f.get('old') != read('password') or not f.get('new'):
                return self.send(200, page('Change password', '<p>Could not change the password</p>' + CHANGE))
            open(os.path.join(DIR, 'password'), 'w').write(f['new'])
            return self.send(200, page('Change password', '<p>Password changed</p>'))
        if self.path == '/account/delete' and u:
            open(os.path.join(DIR, 'deleted'), 'w').write('1')
            return self.send(200, page('Deleted', '<p>Account deleted</p>'))
        return self.send(303, b'', [('Location', '/login')])


http.server.ThreadingHTTPServer(('127.0.0.1', PORT), H).serve_forever()
