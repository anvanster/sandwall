# egressd

**An egress firewall for AI agent sandboxes: default-deny, domain allowlists that work behind CDNs, and a record of every connection, without touching the sandbox.**

## The problem

Agent sandboxes isolate CPU and filesystem but usually leave the network wide open, or offer only on/off.
A prompt-injected agent can read a `.env` and POST it anywhere, or leak it a few bytes at a time through DNS query names.
And when something goes wrong, nobody can answer "what did sandbox X connect to?"

egressd gives every sandbox its own network namespace and enforces policy from the host side, where root inside the sandbox cannot reach it:

- **Default-deny egress** with domain allowlists that keep working behind CDNs.
- **DNS that cannot be used for exfiltration**: queries for names that are not allowlisted are refused locally and never forwarded.
- **Hard blocks** on private, link-local and cloud metadata ranges (`169.254.169.254`), the host itself and other sandboxes.
- **Per-sandbox limits** on bandwidth, concurrent connections and new connections per second.
- **Per-sandbox logs** of every DNS query, allowed flow (with byte counts and domain) and denied packet, plus Prometheus metrics.
- **Clone-safe Firecracker networking**: 20 microVMs restored from one snapshot share the same guest IP and MAC and still work side by side, each with its own policy and logs.

The sandbox needs no cooperation and no code changes.

```
$ sudo demo/exfil.sh
== (a) open sandbox: own netns, NAT to anywhere
agent: HTTP POST http://10.99.0.1:8080/collect -> 200 'received'
agent: DNS lookup of 4f50454e41495f4150...exfil.attacker.test -> 10.99.0.1
=> secrets exfiltrated

== (b) egressd sandbox: default deny, allowlist 4 domains
agent: HTTP POST http://10.99.0.1:8080/collect failed: <urlopen error timed out>
agent: DNS lookup of 4f50454e41495f4150...exfil.attacker.test failed: [Errno -3] Temporary failure in name resolution
=> nothing left the sandbox
egressd logs agent --deny-only:
    10:10:41.874  deny  deny/not_allowed  tcp 10.99.0.1:8080
    10:10:46.886  dns  refused/not_allowlisted  A 4f50454e41495f4150...exfil.attacker.test.
```

## How it works

```
[exec mode]  process ───────────────────────────┐
[vm mode]    guest eth0 → tap0 → (netns NAT/DNAT) ┤
                                                  ▼
                              veth-s<k>  ⇄  veth-h<k>   (host netns)
                                                │
                     host nftables: table inet egressd
                       prerouting → sb_<k>  (policy for traffic leaving the host)
                       input   → sbin_<k>   (only DNS to this sandbox's proxy)
                       postrouting: masquerade to the uplink
                                                ▼
                                             uplink
```

Sandbox *k* lives in netns `sb<k>`, connected to the host by a veth pair on `10.200.k.0/30`.
Its resolver is `10.200.k.1`, where egressd runs a DNS proxy for that sandbox alone.

When the sandbox asks for an allowlisted name, the proxy resolves it upstream, puts the A records into the sandbox's nftables set `allow_<k>` with a timeout, and only then answers.
Connections are allowed to IPs in that set, so allowlists keep working behind CDNs and rotating IPs.
Names that are not allowlisted get `REFUSED` without any upstream query, so the query name never leaves the host.
DNS to any other server, including DNS-over-TLS on port 853, is dropped and logged as a bypass attempt.

Everything is keyed by sandbox, never by IP address.
That is what lets Firecracker clones share one guest identity: each clone's `tap0` and `172.16.0.2` live in its own netns, which masquerades the guest to `10.200.k.2` before the host sees it.

Rulesets are generated as text and applied atomically with `nft -f`.
egressd only ever touches its own `inet egressd` table (and `ip egressd_vm` inside VM-mode namespaces).

## Quickstart

Requirements: Linux 5.10+, root, `nftables`, `iproute2`, `util-linux` (`setpriv`), and Go 1.26 to build.
VM mode also needs `/dev/kvm` and the Firecracker `firecracker` and `jailer` binaries.
Try it in a disposable VM: egressd changes host firewall rules and sysctls (it restores the sysctls on `nuke`).

```sh
make build                              # bin/egressd
sudo bin/egressd daemon &               # DNS proxies, log collectors, metrics on :9464, API on /run/egressd.sock

sudo bin/egressd sandbox create agent --policy demo/policy.yaml
sudo bin/egressd sandbox exec agent -- curl -sI https://pypi.org/    # allowed
sudo bin/egressd sandbox exec agent -- curl -sI https://example.com/ # refused at DNS
sudo bin/egressd logs agent -f --deny-only

sudo bin/egressd policy apply agent new-policy.yaml   # hot reload; established flows survive
sudo bin/egressd sandbox destroy agent
sudo bin/egressd nuke                                  # remove everything egressd created
```

`sandbox exec` runs the command inside the sandbox's netns as `nobody`, with every capability dropped, so nothing in it can change its own network configuration.

### VM mode

```sh
sudo test/e2e/fc-assets.sh /var/lib/egressd-fc      # firecracker, jailer, a guest kernel and rootfs, fc.json
sudo bin/egressd daemon --firecracker /var/lib/egressd-fc/firecracker --jailer /var/lib/egressd-fc/jailer &

sudo bin/egressd sandbox create vm1 --mode vm --vm-config /var/lib/egressd-fc/fc.json --policy demo/policy.yaml
sudo bin/egressd vm snapshot vm1 --out /srv/snapshots/base
sudo bin/egressd vm clone /srv/snapshots/base --count 20 --policy demo/policy.yaml
```

`--vm-config` is a regular Firecracker config file without `network-interfaces`; egressd owns the network.
Each VM runs as `jailer --netns /var/run/netns/sb<k>` under its own unprivileged uid, and the guest network comes from the kernel command line (`ip=172.16.0.2::172.16.0.1:255.255.255.252::eth0:off`).
Bandwidth limits are applied both by tc on the host and by Firecracker's own rate limiters.

### Behind an HTTP proxy

On networks where only an HTTP proxy reaches the internet, start the daemon with `--upstream-proxy http://[user:pass@]host:port`, or `--upstream-proxy-from-env` to take it from `https_proxy`/`http_proxy` (`sudo` drops those unless preserved, e.g. `sudo --preserve-env=https_proxy,http_proxy`).
The proxy is a next hop, not a destination: the sandbox needs no proxy settings and still connects to real addresses, and egressd still applies the policy to them.
Allowed TCP is then redirected to a per-sandbox relay on `10.200.k.1:15001`, which tunnels it through the proxy:

- TLS: `CONNECT <SNI>:<port>`. The SNI must be allowlisted (or the address inside `allow_cidrs`), otherwise the connection is reset and logged as `sni_mismatch`.
- Plain HTTP: each request is forwarded in absolute form, and every request's `Host` is checked (`host_mismatch`, answered with 403).
- Other TCP: `CONNECT` with the name the sandbox resolved for that address.
- UDP to an allowed address is rejected (`no_proxy_route`), so HTTP/3 clients fall back to TCP.

The sandbox cannot reach the proxy itself, and proxy credentials never enter it.
Connections through the relay end when the daemon stops, unlike forwarded flows.
`no_proxy` is not supported yet: every allowed destination goes through the proxy.

## Policy reference

```yaml
egress:
  default: deny                  # the only supported value
  allow_domains:
    - pypi.org                   # exactly this name
    - "*.githubusercontent.com"  # any subdomain, not the apex itself
  allow_cidrs:                   # escape hatch for literal IPv4 addresses or ranges
    - 203.0.113.0/24
limits:
  max_egress_bw: 50mbit          # sandbox -> world; bit, kbit, mbit, gbit; omit for no limit
  max_ingress_bw: 200mbit        # world -> sandbox
  max_conns: 64                  # concurrent connections (default 64)
  new_conns_per_sec: 20          # default 20
  dns_qps: 50                    # DNS queries per second (default 50)
upstream_dns: 1.1.1.1:53         # optional; default is the host's first resolver
```

Unknown keys are rejected, so a typo fails loudly instead of silently allowing nothing or everything.
`policy apply` re-renders the sandbox's chain and repopulates its allow set atomically, updates tc and Firecracker limits, and leaves established connections alone.

Rule order for traffic leaving the host:

1. Established and related traffic is accepted.
2. DNS or DNS-over-TLS to anything but the sandbox's proxy is dropped (`dns_bypass`).
3. IPv6 is dropped; it is disabled inside sandboxes.
4. Private, link-local, metadata, multicast, reserved and sandbox transfer ranges are dropped (`blocked_range`).
5. New connections above `new_conns_per_sec` are dropped (`rate_limit`).
6. New connections above `max_conns` are rejected with a TCP reset (`conn_limit`).
7. Addresses learned from allowlisted DNS answers, and `allow_cidrs`, are accepted.
8. Everything else is dropped (`not_allowed`).

Traffic to the host itself is dropped (`host_access`), except DNS to the sandbox's own proxy.
With an upstream proxy, step 7 accepts only TCP, which goes on to the relay; anything else to an allowed address is rejected (`no_proxy_route`).

## Observability

Each sandbox has a JSONL log at `/var/log/egressd/<id>.jsonl`; `egressd logs <id> [-f] [--deny-only]` prints it.
Logs outlive the sandbox.

| `type` | Fields |
|---|---|
| `dns` | `qname`, `qtype`, `verdict` (`allow`, `refused`, `ratelimited`, `error`), `answers` |
| `flow` | `proto`, `dst_ip`, `dst_port`, `dst_domain`, `bytes_out`, `bytes_in`, `ts_start`, `ts_end` |
| `deny` | `reason`, `proto`, `dst_ip`, `dst_port` |
| `proxy` | upstream proxy mode: `src_port`, `dst_ip`, `dst_port`, `dst_domain`, `target`, `sni`, `http_host`, `proxy_status`, `connect_ms`; on `deny`, `reason` (`sni_mismatch`, `host_mismatch`, `bad_client_hello`, `proxy_refused`, `proxy_error`, `conn_limit`) |

Every line also has `ts`, `sandbox_id` and `verdict`.
Flow byte counts come from conntrack and are layer 3 (they include IP and TCP headers).
Identical deny events are logged at most once per second per sandbox; metrics still count every packet.

Prometheus metrics on `:9464/metrics`, all labeled `sandbox`:

| Metric | Extra label |
|---|---|
| `egressd_flows_total` | `verdict` |
| `egressd_bytes_total` | `direction` (`out` = sandbox to world) |
| `egressd_dns_queries_total` | `verdict` |
| `egressd_denied_total` | `reason` |
| `egressd_proxy_connects_total` | `result` (`ok`, `denied`, `refused`, `error`) |

## Threat model

**In scope:** code running inside a sandbox, including as root inside a VM guest, that wants to send data somewhere it should not, or reach the host, its network, cloud metadata or other sandboxes.

**What egressd assumes:**

- The host and the egressd daemon are trusted, and only root can reach the API socket (`/run/egressd.sock`, mode 0600).
- Exec-mode processes run as `nobody` without capabilities, so they cannot change addresses, routes or firewall rules in their netns.
- In VM mode the guest is fully untrusted. It only controls its own kernel; everything that enforces policy lives in the netns or on the host.

**What it guarantees:**

- No connection leaves the host unless its destination was returned by an allowlisted DNS answer or is in `allow_cidrs`.
  Behind an upstream proxy, the proxy is only ever asked for allowlisted names, addresses in `allow_cidrs`, or addresses the firewall already admitted.
- No DNS query for a name that is not allowlisted reaches any resolver.
- Policy is enforced fail-closed. A sandbox interface without rules is dropped, and while the daemon is down nothing answers the sandbox's DNS.

**Out of scope:** payload inspection, TLS interception, ingress, IPv6 and multi-host deployment.

## Known gaps

- **Shared CDN addresses.** If a non-allowlisted domain is served from the same IP as an allowlisted one, it is reachable by IP until that address's set entry expires (at most 300s after the last allowlisted lookup). Behind an upstream proxy, the relay's SNI/Host check closes this for TLS and HTTP; direct mode still has the gap. Neither mode sees an HTTP `Host` inside TLS, so fronting through an allowlisted SNI remains possible.
- **Allowlisted names are an exfiltration channel if their owner is hostile.** A wildcard such as `*.example.com` lets the sandbox query any subdomain, and those queries do reach `example.com`'s nameservers. Only allowlist zones you trust.
- **Connection-limit recovery is lazy.** The kernel's `ct count` prunes closed and rejected connections only when new ones are attempted. Right after a burst, the limit can be stricter than configured for a few seconds. It never lets more connections through.
- **No IPv6.** It is disabled inside sandboxes. AAAA, HTTPS and SVCB queries get empty answers, so clients fall back to IPv4.
- **Single host.** There is no fleet management, central UI or API authentication.

Design decisions and deviations from the original plan, with the measurements behind them, are in [DECISIONS.md](DECISIONS.md).

## Development

```sh
make test         # unit tests: policy parsing, allowlist matching, DNS proxy, golden nftables rulesets
make vet fmt-check
make e2e          # root-only acceptance tests for M1-M3 and proxy mode (M3 needs /dev/kvm); run in a disposable VM
make e2e-proxy REAL_PROXY=http://host:port   # also fetch real sites through a site proxy
```

Every e2e script starts and ends with `egressd nuke`, uses its own state and log directories, and checks that nothing egressd created is left behind.
The "attacker" endpoint is a local listener in its own netns at `10.99.0.1`, so only the allowlist checks need the internet; the proxy test runs a fake upstream proxy there too.
VM-mode paths are configurable for keeping snapshots and jails on one (reflink-capable) filesystem: `make e2e-m3 FC_ASSETS=… CHROOT_BASE=… E2E_TMP=…`.

The demos are `demo/exfil.sh` (the comparison above) and `demo/clones.sh` (20 Firecracker clones with a live, merged `egressd logs -f`).
On nested-virtualization hosts, such as a Lima VM on Apple silicon, start many VMs with `vm clone --stagger 1s`; see DECISIONS.md.
