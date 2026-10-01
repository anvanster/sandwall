#!/usr/bin/env python3
"""Open N TCP connections to host:port, hold them all, then report as JSON.

Run inside a sandbox to exercise max_conns and new_conns_per_sec.
"""
import json
import socket
import sys
import time

host, port, n = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
timeout = float(sys.argv[4]) if len(sys.argv) > 4 else 2.0
held, result = [], {"connected": 0, "refused": 0, "timeout": 0, "other": 0}
for _ in range(n):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        held.append(s)
        result["connected"] += 1
    except ConnectionRefusedError:
        result["refused"] += 1
        s.close()
    except socket.timeout:
        result["timeout"] += 1
        s.close()
    except OSError:
        result["other"] += 1
        s.close()
hold = float(sys.argv[5]) if len(sys.argv) > 5 else 0
time.sleep(hold)
print(json.dumps(result), flush=True)
for s in held:
    s.close()
