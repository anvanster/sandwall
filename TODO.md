# TODO

Open work and verification that is still owed. Design decisions and their reasons live in [DECISIONS.md](DECISIONS.md).

## Needs a host with direct internet access

The bare-metal M3 host reaches the internet only through an HTTP proxy, so everything below has only been run there behind that proxy (`REAL_PROXY=...`) or against the local attacker endpoint.
Run these on a host with direct egress, without `REAL_PROXY`.

- [x] **M1 in direct mode** (`make e2e-m1`): real-site fetches through the direct-mode relay, including the in-flight download across a reload. Green on a direct-egress host, 2026-10-01.
- [x] **M3 in direct mode** (`make e2e-m3 CLONE_STAGGER=0 FETCH_CONCURRENCY=20`): guest fetches through the direct-mode relay. Green on a direct-egress host, 2026-10-01.
- [x] **S1 against real CDNs** (`make e2e-s1-real HTTP3_CURL=<curl with HTTP/3>`): TLS 1.3, HTTP/2 and a 55 MiB sha256-verified download via Fastly-hosted pypi.org/files.pythonhosted.org; fronting www.python.org through pypi.org's address refused as `sni_mismatch` (and `host_mismatch` over HTTP); `curl --http3` falls back to HTTP/2 in under 0.1s after `quic_blocked`; `pip install requests rich numpy` succeeds. Green on a direct-egress host, 2026-10-05.
- [x] **Relay cost** (`make e2e-relay-cost`): +0.3 to 0.5 ms per TLS handshake, 83 to 86% of uncapped throughput (8.2 to 8.5 vs 9.9 Gbit/s), no measurable cost under a 200 Mbit cap or on a real download. Numbers in DECISIONS.md, "Relay cost". 2026-10-05.
- [x] **Demos:** `demo/exfil.sh` gained act (c), escalation caught by the SNI check and a DNS-bypass drop, auto-quarantine and a signed webhook; `demo/clones.sh` quarantines one clone mid-run. README output refreshed (run behind an HTTP proxy, 2026-10-02).
- [ ] **Demos in direct mode:** run `demo/exfil.sh` and `demo/clones.sh` once without `REAL_PROXY`; act (c)'s fronting attempt then goes through the direct-mode relay.

## Incident response (ahead of S2/S3)

Detection without a working kill switch is half a control: today nothing acts on a deny, `policy apply` deliberately keeps established flows, and `sandbox destroy` throws away the evidence.

- [x] **`sandbox quarantine <id>` / `sandbox release <id>`:** cut all network access at once, including established flows and relayed connections, refuse all DNS, keep the netns, VM and logs for forensics; optionally freeze the sandbox's processes or pause its VM. Survives a daemon restart.
- [x] **Automatic quarantine:** per-policy trigger rules, e.g. N `dns_bypass` / `sni_mismatch` / `not_allowed` denies within T seconds, that quarantine the sandbox themselves (not only notify).
- [x] **Allowlist linting:** warn about, or require an explicit opt-in for, wildcards over multi-tenant platforms (`*.vercel.app`, `*.herokuapp.com`, `*.cloudfront.net`, ...), where anyone can host an endpoint that passes the SNI check. The private section of the Public Suffix List covers most of them.

## Features

- [x] **S2:** per-sandbox policy-violation webhooks.
- [x] **S3:** OTel log export.
- [ ] **Synthetic DNS** for proxy-only networks whose resolver answers internal names only (design in DECISIONS.md, "Upstream proxy" / DNS).
- [ ] **SNI check ports:** only 80 and 443 go through the relay in direct mode; consider making the list configurable.

## Known limitations worth revisiting

- DNS answers take about 15 ms through the sandbox's proxy (measured by the relay cost benchmark, against the local fake upstream), which dwarfs the relay's cost. Much of it is likely the allow-set insert, one `nft` process per answer; measure the split, and consider inserting over netlink.

- Relayed connections (ports 80/443 with the SNI check, all TCP behind a proxy) end when the daemon stops; forwarded flows survive. A graceful drain or handing the listeners to the new daemon would fix that.
- `no_proxy` destinations bypass the relay, so they get no SNI/Host check.
- A destination that refuses the relay's connection appears to the sandbox as an accepted connection that is then reset.
- No IPv6.
