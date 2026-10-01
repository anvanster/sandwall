#!/usr/bin/env python3
"""Mock remote endpoint for e2e tests and demos.

HTTP on --port:
  GET /             -> "attacker"
  GET /bytes/<n>    -> n bytes of zeros (download size tests)
  POST <any>        -> body appended to --loot (exfiltration evidence)

Optional:
  --hold-port P     accept TCP connections and hold them open (conn limits)
  --udp-port P      append every UDP datagram to --loot as "udp: <payload>"
                    (delivery evidence for forwarded UDP)
  --dns-port P      answer UDP DNS for --dns-zone and its subdomains with
                    --bind's address, NXDOMAIN for anything else; every
                    query name is appended to --loot (DNS exfiltration evidence)

Unlike `python3 -m http.server` it does no reverse DNS lookup at startup,
which would hang in a netns without a resolver.
"""

import argparse
import socket
import socketserver
import struct
import threading
from http.server import BaseHTTPRequestHandler

CHUNK = b"\0" * 65536


class Handler(BaseHTTPRequestHandler):
    loot_path = ""

    def do_GET(self):
        if self.path.startswith("/bytes/"):
            try:
                n = int(self.path[len("/bytes/"):])
            except ValueError:
                self.send_error(400)
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(n))
            self.end_headers()
            while n > 0:
                part = CHUNK[: min(n, len(CHUNK))]
                self.wfile.write(part)
                n -= len(part)
            return
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
    request_queue_size = 512


def hold_server(addr, port):
    """Accept connections and keep them open until the peer closes.

    Closing our side when the peer does matters: a half-closed connection
    stays in conntrack's CLOSE_WAIT and still counts against max_conns.
    """
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((addr, port))
    ls.listen(1024)
    while True:
        conn, _ = ls.accept()
        threading.Thread(target=hold_until_eof, args=(conn,), daemon=True).start()


def hold_until_eof(conn):
    try:
        while conn.recv(4096):
            pass
    except OSError:
        pass
    finally:
        conn.close()


def dns_server(addr, port, zone, loot_path):
    """Minimal UDP DNS responder: A records for zone and its subdomains."""
    zone = zone.lower().rstrip(".")
    ip = socket.inet_aton(addr)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((addr, port))
    while True:
        data, peer = s.recvfrom(4096)
        if len(data) < 12:
            continue
        qid, flags, qd = struct.unpack("!HHH", data[:6])
        if qd != 1:
            continue
        labels, i = [], 12
        while i < len(data) and data[i] != 0:
            n = data[i]
            labels.append(data[i + 1 : i + 1 + n].decode("ascii", "replace"))
            i += 1 + n
        i += 1
        if i + 4 > len(data):
            continue
        qtype, qclass = struct.unpack("!HH", data[i : i + 4])
        question = data[12 : i + 4]
        name = ".".join(labels).lower()
        with open(loot_path, "a") as f:
            f.write("dns query: %s\n" % name)
        in_zone = name == zone or name.endswith("." + zone)
        answer = b""
        rcode = 0 if in_zone else 3
        if in_zone and qtype == 1 and qclass == 1:
            answer = struct.pack("!HHHIH", 0xC00C, 1, 1, 60, 4) + ip
        rd = flags & 0x0100
        header = struct.pack("!HHHHHH", qid, 0x8000 | 0x0400 | rd | 0x0080 | rcode, 1, 1 if answer else 0, 0, 0)
        s.sendto(header + question + answer, peer)


def udp_sink(addr, port, loot_path):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((addr, port))
    while True:
        data, _ = s.recvfrom(65535)
        with open(loot_path, "a") as f:
            f.write("udp: %s\n" % data.decode("utf-8", "replace").strip())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--loot", required=True, help="file that receives POST bodies")
    ap.add_argument("--hold-port", type=int)
    ap.add_argument("--dns-port", type=int)
    ap.add_argument("--udp-port", type=int)
    ap.add_argument("--dns-zone", default="attacker.test")
    args = ap.parse_args()
    Handler.loot_path = args.loot
    if args.hold_port:
        threading.Thread(target=hold_server, args=(args.bind, args.hold_port), daemon=True).start()
    if args.udp_port:
        threading.Thread(target=udp_sink, args=(args.bind, args.udp_port, args.loot), daemon=True).start()
    if args.dns_port:
        threading.Thread(target=dns_server, args=(args.bind, args.dns_port, args.dns_zone, args.loot), daemon=True).start()
    with Server((args.bind, args.port), Handler) as srv:
        print("listening on %s:%d" % (args.bind, args.port), flush=True)
        srv.serve_forever()


if __name__ == "__main__":
    main()
