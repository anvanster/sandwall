# TODO

Open work and verification that is still owed. Design decisions and their reasons live in [DECISIONS.md](DECISIONS.md).

## Needs a host with direct internet access

The bare-metal M3 host reaches the internet only through an HTTP proxy, so everything below has only been run there behind that proxy (`REAL_PROXY=...`) or against the local attacker endpoint.
Run these on a host with direct egress, without `REAL_PROXY`.

- [ ] **M1 in direct mode:** `make e2e-m1`.
  Not run since the SNI check (S1) became the default, so `curl https://pypi.org`, the hot-reload `example.com` fetch and the in-flight download across a reload have never gone through the relay in direct mode against real sites.
- [ ] **M3 in direct mode on bare metal:** `make e2e-m3 CLONE_STAGGER=0 FETCH_CONCURRENCY=20` (with `FC_ASSETS`, `CHROOT_BASE`, `E2E_TMP` on one reflink-capable filesystem).
  Guest fetches of pypi.org and example.com through the direct-mode relay.
- [ ] **S1 against real CDNs:**
  - an allowlisted name on a shared CDN works: TLS 1.3, HTTP/2, large downloads;
  - `curl --resolve <unlisted name>:443:<address of an allowlisted name>` is refused as `sni_mismatch`;
  - `curl --http3` to an allowlisted name falls back to TCP after `quic_blocked`;
  - `pip install` (many connections to pypi.org and files.pythonhosted.org) succeeds.
- [ ] **Relay cost:** throughput and latency of a large HTTPS download through the relay compared with `--sni-check=false`, with and without a `max_ingress_bw` cap (the M2 bandwidth checks use port 5201, which the relay does not see).
- [ ] **Demos:** re-run `demo/exfil.sh` and `demo/clones.sh` and refresh the README output; they predate the SNI check and the `relay` event.

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
