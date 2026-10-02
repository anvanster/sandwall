# TODO

Open work and verification that is still owed. Design decisions and their reasons live in [DECISIONS.md](DECISIONS.md).

## Needs a host with direct internet access

The bare-metal M3 host reaches the internet only through an HTTP proxy, so everything below has only been run there behind that proxy (`REAL_PROXY=...`) or against the local attacker endpoint.
Run these on a host with direct egress, without `REAL_PROXY`.

- [x] **M1 in direct mode** (`make e2e-m1`): real-site fetches through the direct-mode relay, including the in-flight download across a reload. Green on a direct-egress host, 2026-10-01.
- [x] **M3 in direct mode** (`make e2e-m3 CLONE_STAGGER=0 FETCH_CONCURRENCY=20`): guest fetches through the direct-mode relay. Green on a direct-egress host, 2026-10-01.
- [ ] **S1 against real CDNs:**
  - an allowlisted name on a shared CDN works: TLS 1.3, HTTP/2, large downloads;
  - `curl --resolve <unlisted name>:443:<address of an allowlisted name>` is refused as `sni_mismatch`;
  - `curl --http3` to an allowlisted name falls back to TCP after `quic_blocked`;
  - `pip install` (many connections to pypi.org and files.pythonhosted.org) succeeds.
- [ ] **Relay cost:** throughput and latency of a large HTTPS download through the relay compared with `--sni-check=false`, with and without a `max_ingress_bw` cap (the M2 bandwidth checks use port 5201, which the relay does not see).
- [ ] **Demos:** re-run `demo/exfil.sh` and `demo/clones.sh` and refresh the README output; they predate the SNI check and the `relay` event.

## Incident response (ahead of S2/S3)

Detection without a working kill switch is half a control: today nothing acts on a deny, `policy apply` deliberately keeps established flows, and `sandbox destroy` throws away the evidence.

- [x] **`sandbox quarantine <id>` / `sandbox release <id>`:** cut all network access at once, including established flows and relayed connections, refuse all DNS, keep the netns, VM and logs for forensics; optionally freeze the sandbox's processes or pause its VM. Survives a daemon restart.
- [x] **Automatic quarantine:** per-policy trigger rules, e.g. N `dns_bypass` / `sni_mismatch` / `not_allowed` denies within T seconds, that quarantine the sandbox themselves (not only notify).
- [x] **Allowlist linting:** warn about, or require an explicit opt-in for, wildcards over multi-tenant platforms (`*.vercel.app`, `*.herokuapp.com`, `*.cloudfront.net`, ...), where anyone can host an endpoint that passes the SNI check. The private section of the Public Suffix List covers most of them.

## Features

- [ ] **S2:** per-sandbox policy-violation webhooks.
- [ ] **S3:** OTel log export.
- [ ] **Synthetic DNS** for proxy-only networks whose resolver answers internal names only (design in DECISIONS.md, "Upstream proxy" / DNS).
- [ ] **SNI check ports:** only 80 and 443 go through the relay in direct mode; consider making the list configurable.

## Known limitations worth revisiting

- Relayed connections (ports 80/443 with the SNI check, all TCP behind a proxy) end when the daemon stops; forwarded flows survive. A graceful drain or handing the listeners to the new daemon would fix that.
- `no_proxy` destinations bypass the relay, so they get no SNI/Host check.
- A destination that refuses the relay's connection appears to the sandbox as an accepted connection that is then reset.
- No IPv6.
