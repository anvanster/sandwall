#!/usr/bin/env python3
"""Fake upstream HTTP proxy for the proxy-mode e2e test.

Handles CONNECT host:port and absolute-form requests (GET http://host/...).
Every request line is appended to --log together with whether a
Proxy-Authorization header was present. Names under attacker.test resolve to
--origin; anything else, and blocked.attacker.test, is refused with 403, so
the test never reaches the internet through it.
"""
import argparse
import socket
import socketserver
import threading
from urllib.parse import urlsplit

ARGS = None
LOCK = threading.Lock()


def log(line):
    with LOCK, open(ARGS.log, "a") as f:
        f.write(line + "\n")


def resolve(host):
    if host == "blocked.attacker.test" or not (host == "attacker.test" or host.endswith(".attacker.test")):
        return None
    return ARGS.origin


def pipe(a, b):
    def one(src, dst):
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    t = threading.Thread(target=one, args=(b, a), daemon=True)
    t.start()
    one(a, b)
    t.join()


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        c = self.request
        # Byte by byte, so nothing after the request head is consumed here.
        head = b""
        while not head.endswith(b"\r\n\r\n"):
            ch = c.recv(1)
            if not ch:
                return
            head += ch
        lines = head.split(b"\r\n")
        line = lines[0].decode("latin-1")
        headers = [h + b"\r\n" for h in lines[1:] if h]
        auth = any(h.lower().startswith(b"proxy-authorization:") for h in headers)
        log("%s auth=%s" % (line, "yes" if auth else "no"))
        method, target, _ = line.split(" ", 2)
        if method == "CONNECT":
            host, port = target.rsplit(":", 1)
        else:
            u = urlsplit(target)
            host, port = u.hostname, u.port or 80
        ip = resolve(host)
        if ip is None:
            c.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            return
        try:
            up = socket.create_connection((ip, int(port)), timeout=5)
            up.settimeout(None)
        except OSError:
            c.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            return
        with up:
            if method == "CONNECT":
                c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            else:
                u = urlsplit(target)
                path = (u.path or "/") + ("?" + u.query if u.query else "")
                fwd = [h for h in headers if not h.lower().startswith(b"proxy-")]
                up.sendall(("%s %s HTTP/1.1\r\n" % (method, path)).encode() + b"".join(fwd) + b"\r\n")
            pipe(c, up)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    global ARGS
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--origin", required=True)
    ap.add_argument("--log", required=True)
    ARGS = ap.parse_args()
    Server((ARGS.bind, ARGS.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
