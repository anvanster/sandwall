#!/usr/bin/env python3
"""Webhook receiver for the alerts e2e test.

Appends one JSON line per POST to --out: {"ok": <signature valid>, "body": <payload>}.
With --secret, the X-Sandwall-Signature header is checked against
HMAC-SHA256(secret, "<X-Sandwall-Timestamp>.<body>"). --fail N answers the
first N requests with 500.
"""
import argparse
import hashlib
import hmac
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ARGS = None
FAILS = 0


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        global FAILS
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if FAILS < ARGS.fail:
            FAILS += 1
            self.send_response(500)
            self.end_headers()
            return
        ok = True
        if ARGS.secret:
            ts = self.headers.get("X-Sandwall-Timestamp", "")
            want = "sha256=" + hmac.new(ARGS.secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
            ok = hmac.compare_digest(want, self.headers.get("X-Sandwall-Signature", ""))
        with open(ARGS.out, "a") as f:
            f.write(json.dumps({"ok": ok, "body": json.loads(body)}) + "\n")
        self.send_response(204 if ok else 401)
        self.end_headers()

    def log_message(self, fmt, *args):
        pass


def main():
    global ARGS
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--secret")
    ap.add_argument("--fail", type=int, default=0)
    ARGS = ap.parse_args()
    ThreadingHTTPServer(("127.0.0.1", ARGS.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
