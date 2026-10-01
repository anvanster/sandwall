#!/usr/bin/env python3
"""Mock exfiltration endpoint for e2e tests and demos.

Answers GET with "attacker" and records every POST body to a file, so tests
can assert whether anything was exfiltrated. Unlike `python3 -m http.server`
it does no reverse DNS lookup at startup, which would hang in a netns
without a resolver.
"""

import argparse
import socketserver
from http.server import BaseHTTPRequestHandler


class Handler(BaseHTTPRequestHandler):
    loot_path = ""

    def do_GET(self):
        self._reply(b"attacker\n")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        with open(self.loot_path, "ab") as f:
            f.write(body + b"\n")
        self._reply(b"received\n")

    def _reply(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print("%s %s" % (self.client_address[0], fmt % args), flush=True)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--loot", required=True, help="file that receives POST bodies")
    args = ap.parse_args()
    Handler.loot_path = args.loot
    with Server((args.bind, args.port), Handler) as srv:
        print("listening on %s:%d" % (args.bind, args.port), flush=True)
        srv.serve_forever()


if __name__ == "__main__":
    main()
