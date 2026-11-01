#!/usr/bin/env python3
"""A small S3-compatible object store for store_e2e.sh, independent of the
Resid client: it checks every request's AWS Signature Version 4 itself
(the signing steps from the AWS documentation, with the standard library),
and serves GET, PUT (If-None-Match: *), and ListObjectsV2 (prefix,
start-after, continuation-token, 1000 keys a page) on one bucket in memory.

usage: s3_oracle.py PORT KEY-ID SECRET BUCKET REGION
"""
import hashlib, hmac, sys, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from xml.sax.saxutils import escape

PORT, KEY_ID, SECRET, BUCKET, REGION = int(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
OBJECTS = {}
PAGE = 1000

def sign(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()

def check(handler, body):
    auth = handler.headers.get('Authorization', '')
    if not auth.startswith('AWS4-HMAC-SHA256 '):
        return False
    parts = dict(p.strip().split('=', 1) for p in auth[len('AWS4-HMAC-SHA256 '):].split(','))
    cred = parts['Credential'].split('/')
    if cred[0] != KEY_ID or cred[2] != REGION or cred[3] != 's3' or cred[4] != 'aws4_request':
        return False
    signed = parts['SignedHeaders'].split(';')
    payload = handler.headers.get('x-amz-content-sha256', '')
    if payload != hashlib.sha256(body).hexdigest():
        return False
    url = urllib.parse.urlsplit(handler.path)
    pairs = urllib.parse.parse_qsl(url.query, keep_blank_values=True)
    q = '&'.join(urllib.parse.quote(k, safe='-_.~') + '=' + urllib.parse.quote(v, safe='-_.~') for k, v in sorted(pairs))
    path = urllib.parse.quote(urllib.parse.unquote(url.path), safe='/-_.~')
    heads = ''.join(h + ':' + handler.headers.get(h, '').strip() + '\n' for h in signed)
    canonical = '\n'.join([handler.command, path, q, heads, ';'.join(signed), payload])
    when = handler.headers.get('x-amz-date', '')
    scope = '/'.join(cred[1:])
    to_sign = '\n'.join(['AWS4-HMAC-SHA256', when, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    k = sign(sign(sign(sign(('AWS4' + SECRET).encode(), cred[1]), REGION), 's3'), 'aws4_request')
    return hmac.compare_digest(hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest(), parts['Signature'])

class H(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *a):
        pass

    def reply(self, status, body=b'', ctype='application/octet-stream'):
        self.send_response(status)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def body(self):
        n = int(self.headers.get('Content-Length', '0'))
        return self.rfile.read(n) if n else b''

    def key(self):
        p = urllib.parse.unquote(urllib.parse.urlsplit(self.path).path)
        if not p.startswith('/' + BUCKET):
            return None
        return p[len(BUCKET) + 2:]

    def do_GET(self):
        if not check(self, b''):
            return self.reply(403, b'<Error><Code>SignatureDoesNotMatch</Code></Error>')
        k = self.key()
        if k is None:
            return self.reply(404)
        if k == '':
            q = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(self.path).query))
            prefix = q.get('prefix', '')
            after = q.get('continuation-token', '') or q.get('start-after', '')
            keys = sorted(x for x in OBJECTS if x.startswith(prefix) and x > after)
            limit = min(PAGE, int(q.get('max-keys', PAGE)))
            page, more = keys[:limit], len(keys) > limit
            xml = '<ListBucketResult>' + ''.join('<Contents><Key>%s</Key></Contents>' % escape(x) for x in page)
            xml += '<IsTruncated>%s</IsTruncated>' % ('true' if more else 'false')
            if more:
                xml += '<NextContinuationToken>%s</NextContinuationToken>' % escape(page[-1])
            return self.reply(200, (xml + '</ListBucketResult>').encode(), 'application/xml')
        if k not in OBJECTS:
            return self.reply(404)
        return self.reply(200, OBJECTS[k])

    def do_PUT(self):
        b = self.body()
        if not check(self, b):
            return self.reply(403, b'<Error><Code>SignatureDoesNotMatch</Code></Error>')
        k = self.key()
        if not k:
            return self.reply(400)
        if self.headers.get('If-None-Match') == '*' and k in OBJECTS:
            return self.reply(412)
        OBJECTS[k] = b
        return self.reply(200)

ThreadingHTTPServer(('127.0.0.1', PORT), H).serve_forever()
