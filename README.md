# sandwall

**An egress firewall for AI agent sandboxes: default-deny, domain allowlists that work behind CDNs, and a record of every connection, without touching the sandbox.**

## The problem

Agent sandboxes isolate CPU and filesystem but usually leave the network wide open, or offer only on/off.
A prompt-injected agent can read a `.env` and POST it anywhere, or leak it a few bytes at a time through DNS query names.
And when something goes wrong, nobody can answer "what did sandbox X connect to?"

sandwall gives every sandbox its own network namespace and enforces policy from the host side, where root inside the sandbox cannot reach it:

- **Default-deny egress** with domain allowlists that keep working behind CDNs, and a TLS SNI / HTTP Host check so a shared CDN address does not open other sites.
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

== (b) sandwall sandbox: default deny, allowlist 5 domains
agent: HTTP POST http://10.99.0.1:8080/collect failed: <urlopen error timed out>
agent: DNS lookup of 4f50454e41495f4150...exfil.attacker.test failed: [Errno -3] Temporary failure in name resolution
=> nothing left the sandbox
sandwall logs agent --deny-only:
    16:39:53.593  deny  deny/not_allowed  tcp 10.99.0.1:8080
    16:39:58.598  dns  refused/not_allowlisted  A 4f50454e41495f4150...exfil.attacker.test.

== the agent can still do its job
    curl https://pypi.org/simple/requests/ -> 200

== (c) the agent escalates
agent: DNS query straight to 8.8.8.8 failed: timed out
agent: TLS to pypi.org's address with SNI exfil.attacker.test failed: [Errno 104] Connection reset by peer
sandwall logs agent --deny-only (new lines):
    16:39:59.734  deny  deny/dns_bypass  udp 8.8.8.8:53
    16:40:02.771  relay  deny/sni_mismatch  tcp 151.101.192.223:443 sni=exfil.attacker.test
    16:40:02.803  quarantine  quarantined/auto: 2 x dns_bypass|sni_mismatch|host_mismatch within 1m0s (last: sni_mismatch exfil.attacker.test)
webhook soc received (signature checked):
    signature ok   deny/dns_bypass x1
    signature ok   quarantine/quarantined x1, relay/sni_mismatch x1
the same allowlisted fetch, now from the quarantined sandbox:
    curl https://pypi.org/simple/requests/ -> 000
=> quarantined: cut off, kept for forensics (sandwall sandbox release agent)
```

## How it works

```
[exec mode]  process ───────────────────────────┐
[vm mode]    guest eth0 → tap0 → (netns NAT/DNAT) ┤
                                                  ▼
                              veth-s<k>  ⇄  veth-h<k>   (host netns)
                                                │
                     host nftables: table inet sandwall
                       prerouting → sb_<k>  (policy for traffic leaving the host)
                       input   → sbin_<k>   (only DNS to this sandbox's proxy)
                       postrouting: masquerade to the uplink
                                                ▼
                                             uplink
```

Sandbox *k* lives in netns `sb<k>`, connected to the host by a veth pair on `10.200.k.0/30`.
Its resolver is `10.200.k.1`, where sandwall runs a DNS proxy for that sandbox alone.

When the sandbox asks for an allowlisted name, the proxy resolves it upstream, puts the A records into the sandbox's nftables set `allow_<k>` with a timeout, and only then answers.
Connections are allowed to IPs in that set, so allowlists keep working behind CDNs and rotating IPs.
Names that are not allowlisted get `REFUSED` without any upstream query, so the query name never leaves the host.
DNS to any other server, including DNS-over-TLS on port 853, is dropped and logged as a bypass attempt.

Everything is keyed by sandbox, never by IP address.
That is what lets Firecracker clones share one guest identity: each clone's `tap0` and `172.16.0.2` live in its own netns, which masquerades the guest to `10.200.k.2` before the host sees it.

Rulesets are generated as text and applied atomically with `nft -f`.
sandwall only ever touches its own `inet sandwall` table (and `ip sandwall_vm` inside VM-mode namespaces).

## Quickstart

Requirements: Linux 5.10+, root, `nftables`, `iproute2`, `util-linux` (`setpriv`), and Go 1.26 to build.
VM mode also needs `/dev/kvm` and the Firecracker `firecracker` and `jailer` binaries.
Try it in a disposable VM: sandwall changes host firewall rules and sysctls (it restores the sysctls on `nuke`).

```sh
make build                              # bin/sandwall
sudo bin/sandwall daemon &               # DNS proxies, log collectors, metrics on :9464, API on /run/sandwall.sock

sudo bin/sandwall sandbox create agent --policy demo/policy.yaml
sudo bin/sandwall sandbox exec agent -- curl -sI https://pypi.org/    # allowed
sudo bin/sandwall sandbox exec agent -- curl -sI https://example.com/ # refused at DNS
sudo bin/sandwall logs agent -f --deny-only

sudo bin/sandwall policy apply agent new-policy.yaml   # hot reload; established flows survive
sudo bin/sandwall sandbox destroy agent
sudo bin/sandwall nuke                                  # remove everything sandwall created
```

### SNI/Host check

Allowed TCP connections to ports 80 and 443 (`--sni-check-ports` changes the list) go through a per-sandbox relay on `10.200.k.1:15001`.
It reads the TLS ClientHello SNI or the HTTP `Host` of every request and, if the name is allowlisted (or the address is inside `allow_cidrs`), connects to the original destination and splices the connection; otherwise it resets the connection (`sni_mismatch`) or answers 403 (`host_mismatch`).
There is no TLS termination.
QUIC (UDP to the same ports) to DNS-learned addresses is rejected (`quic_blocked`) because its server name cannot be checked; clients fall back to TCP.
Other ports are forwarded unchecked.
Add a port only if its clients speak first with TLS or HTTP (`--sni-check-ports 80,443,8443`, say); for a server-first protocol the relay waits 1s for a name before it connects.
Each sandbox's DNS proxy and relay run in a data plane process of their own, which outlives the daemon: relayed connections and DNS keep working through a daemon restart or crash.
Turn it off with `daemon --sni-check=false`.

`sandbox exec` runs the command inside the sandbox's netns as `nobody`, with every capability dropped, so nothing in it can change its own network configuration.

### VM mode

```sh
sudo test/e2e/fc-assets.sh /var/lib/sandwall-fc      # firecracker, jailer, a guest kernel and rootfs, fc.json
sudo bin/sandwall daemon --firecracker /var/lib/sandwall-fc/firecracker --jailer /var/lib/sandwall-fc/jailer &

sudo bin/sandwall sandbox create vm1 --mode vm --vm-config /var/lib/sandwall-fc/fc.json --policy demo/policy.yaml
sudo bin/sandwall vm snapshot vm1 --out /srv/snapshots/base
sudo bin/sandwall vm clone /srv/snapshots/base --count 20 --policy demo/policy.yaml
```

`--vm-config` is a regular Firecracker config file without `network-interfaces`; sandwall owns the network.
Each VM runs as `jailer --netns /var/run/netns/sb<k>` under its own unprivileged uid (`--vm-uid-base`+k, default 2000000000+k; the daemon checks that nothing else on the host uses those ids), and the guest network comes from the kernel command line (`ip=172.16.0.2::172.16.0.1:255.255.255.252::eth0:off`).
Bandwidth limits are applied both by tc on the host and by Firecracker's own rate limiters.

### Behind an HTTP proxy

On networks where only an HTTP proxy reaches the internet, start the daemon with `--upstream-proxy http://[user:pass@]host:port`, or `--upstream-proxy-from-env` to take it from `https_proxy`/`http_proxy` and `no_proxy` (`sudo` drops those unless preserved, e.g. `sudo --preserve-env=https_proxy,http_proxy,no_proxy`).
The proxy is a next hop, not a destination: the sandbox needs no proxy settings and still connects to real addresses, and sandwall still applies the policy to them.
Allowed TCP, on every port, then goes to the relay (see above), which tunnels it through the proxy:

- TLS: `CONNECT <SNI>:<port>`. The SNI must be allowlisted (or the address inside `allow_cidrs`), otherwise the connection is reset and logged as `sni_mismatch`.
- Plain HTTP: each request is forwarded in absolute form, and every request's `Host` is checked (`host_mismatch`, answered with 403).
- Other TCP: `CONNECT` with the name the sandbox resolved for that address.
- UDP to an allowed address is rejected (`no_proxy_route`), so HTTP/3 clients fall back to TCP, unless the address is a `no_proxy` destination.

The sandbox cannot reach the proxy itself, and proxy credentials never enter it.
`--no-proxy` (or `no_proxy`) lists names, IPv4 addresses and CIDRs that bypass the proxy, with Go's `no_proxy` rules: `example.com` covers its subdomains too, `.example.com` only the subdomains, and ports are ignored.
Allowed traffic to them, UDP included, is handled as without a proxy: forwarded directly, with the SNI/Host check on `--sni-check-ports` (and QUIC to their DNS-learned addresses rejected); the policy still applies first, so a `no_proxy` entry never allows anything.
Names work through their DNS answers, so a `no_proxy` name that shares an address with other allowlisted names (a CDN, say) takes them direct too.

If the site resolver answers internal names only, add `--synthetic-dns`.
Allowlisted names (other than `no_proxy` ones) are then answered from a reserved address pool (`--synthetic-dns-pool`, default `198.18.0.0/15`) without asking the resolver, and the relay asks the proxy for the name behind each pool address, so the proxy does the real resolution.
Mappings are kept in the state directory and survive daemon restarts; connections to a pool address that carry no allowlisted name and no longer map to one (the mapping expired) are refused as `synthetic_unmapped`.

## Policy reference

```yaml
egress:
  default: deny                  # the only supported value
  allow_domains:
    - pypi.org                   # exactly this name
    - "*.pythonhosted.org"       # any subdomain, not the apex itself
  allow_cidrs:                   # escape hatch for literal IPv4 addresses or ranges
    - 203.0.113.0/24
  allow_multitenant: []          # acknowledged wildcards over shared hosting (see below)
limits:
  max_egress_bw: 50mbit          # sandbox -> world; bit, kbit, mbit, gbit; omit for no limit
  max_ingress_bw: 200mbit        # world -> sandbox
  max_conns: 64                  # concurrent connections (default 64)
  new_conns_per_sec: 20          # default 20
  dns_qps: 50                    # DNS queries per second (default 50)
upstream_dns: 1.1.1.1:53         # optional; default is the host's first resolver
quarantine:                      # optional: quarantine automatically (see Quarantine)
  freeze: true                   # also stop the processes or pause the VM
  triggers:                      # any one firing quarantines the sandbox
    - reasons: [dns_bypass, sni_mismatch, host_mismatch]
      count: 3                   # 3 such events ...
      window: 60s                # ... within 60s
    - reasons: [dns_refused]     # lookups of names that are not allowlisted
      count: 20
      window: 60s
```

Unknown keys are rejected, so a typo fails loudly instead of silently allowing nothing or everything.

### Wildcards over shared hosting

A wildcard such as `*.vercel.app`, `*.github.io`, `*.herokuapp.com` or `*.amazonaws.com` matches sites that anyone can set up, so a sandbox allowed one can reach an endpoint its attacker controls, and the SNI/Host check passes because the name really is allowlisted.
`sandbox create`, `vm clone` and `policy apply` therefore reject any wildcard that covers a public suffix from the [Public Suffix List](https://publicsuffix.org) (its ICANN section, such as `co.uk`, and its private section of hosting platforms), unless the policy acknowledges it:

```yaml
egress:
  allow_domains: ["*.vercel.app"]
  allow_multitenant: ["*.vercel.app"]   # allows nothing by itself; must repeat an allow_domains entry
```

`sandwall policy lint policy.yaml` runs the same check offline.
Prefer exact names (`my-app.vercel.app`) or a wildcard under one tenant (`*.my-app.vercel.app`).
The list is embedded in the binary; `make psl-update` refreshes it.
A policy already stored when the list changes keeps loading, with a warning in the daemon log.
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
With the SNI check, step 7 first rejects QUIC to DNS-learned addresses (`quic_blocked`), and accepted TCP to the SNI check ports (80 and 443 by default) goes on to the relay.
With an upstream proxy, step 7 accepts anything to a `no_proxy` destination (forwarded directly, its check-port TCP through a relay that dials it directly) and otherwise only TCP, which goes on to the relay; anything else to an allowed address is rejected (`no_proxy_route`).

## Quarantine

```sh
sudo bin/sandwall sandbox quarantine agent --reason "DNS tunnel attempt" [--freeze]
sudo bin/sandwall sandbox release agent
```

`quarantine` cuts a sandbox off at once and keeps it for forensics:

- every packet from or to it is dropped, established connections included, and relayed connections are closed;
- its conntrack entries are deleted, so each cut flow is logged with the bytes it moved, and none can resume after a release;
- its DNS proxy refuses every query without forwarding it, and logs each one (`reason: quarantined`), without the usual rate limit on log lines;
- with `--freeze`, its processes are stopped with SIGSTOP (exec mode) or its VM is paused;
- its netns, VM, policy and logs stay in place, and `vm snapshot` of a frozen VM keeps it paused.

The quarantine is persisted and survives a daemon restart, and `policy apply` does not lift it.
`release` restores the policy with empty allow sets, so names must be resolved again, and thaws a frozen sandbox.
`destroy` works on a quarantined sandbox as usual.

### Automatic quarantine

A policy's `quarantine.triggers` quarantine the sandbox without an operator: when `count` events with any of a trigger's `reasons` are logged within `window`, the daemon quarantines it, freezing it too if `freeze` is set.
The quarantine event's reason says which trigger fired and the last event that counted, e.g. `auto: 3 x dns_bypass|sni_mismatch within 1m0s (last: dns_bypass 1.0.0.1:53)`.

Reasons a trigger can count:

- firewall denies: `dns_bypass`, `blocked_range`, `not_allowed`, `host_access`, `rate_limit`, `conn_limit`, `ipv6`, `quic_blocked`, `no_proxy_route`;
- relay refusals: `sni_mismatch`, `host_mismatch`, `bad_client_hello`, `proxy_refused`;
- DNS: `dns_refused` (a name that is not allowlisted) and `dns_ratelimited` (over `dns_qps`).

Events are counted as logged, so identical denied packets (same reason, protocol, destination and port) count at most once per second: counts measure attempts, not retransmits.
A trigger fires once; a release re-arms the triggers with counts from zero, and so does `policy apply`.
Triggers are off unless the policy has a `quarantine` block.
`dns_bypass`, `sni_mismatch` and `host_mismatch` rarely come from well-behaved software, so low counts suit them; `not_allowed` and `dns_refused` also come from ordinary misconfiguration, such as a missing allowlist entry, and want higher counts.

## Alerts (webhooks)

Webhook endpoints are configured on the daemon, so their URLs and signing keys never appear in policies:

```sh
sudo bin/sandwall daemon --webhook ops=https://hooks.example.com/sandwall --webhook-secret ops=/etc/sandwall/ops.key
```

A sandbox's policy then chooses which endpoints receive its violations, and which violations:

```yaml
alerts:
  webhooks: [ops]
  reasons: [dns_bypass, sni_mismatch, quarantine]   # optional; default: every violation and quarantine
```

`reasons` takes the same names as quarantine triggers, plus `quarantine` for quarantine and release events.
A policy that names a webhook the daemon does not have is rejected.

Each delivery is a JSON `POST` of up to 100 events, sent at most every 2 seconds; a quarantine event is sent at once:

```json
{"source": "sandwall", "sent_at": "2026-10-02T09:15:02Z", "dropped": 0,
 "events": [{"ts": "...", "type": "deny", "sandbox_id": "agent", "verdict": "deny",
             "reason": "dns_bypass", "proto": "udp", "dst_ip": "8.8.8.8", "dst_port": 53}]}
```

The events are the same objects as in the sandbox's log.
With `--webhook-secret`, requests carry `X-Sandwall-Timestamp` and `X-Sandwall-Signature: sha256=<hex>`, the HMAC-SHA256 of `<timestamp>.<body>` keyed with the file's contents (at least 16 bytes). Receivers should check it, and reject old timestamps:

```python
want = "sha256=" + hmac.new(key, ts.encode() + b"." + body, hashlib.sha256).hexdigest()
ok = hmac.compare_digest(want, request.headers["X-Sandwall-Signature"])
```

Delivery never slows the sandbox down: each endpoint has a bounded queue of 1000 events, and events that do not fit are counted and reported as `dropped` in the next payload.
A failed delivery is retried twice, 1 and 2 seconds apart, then counted as an error; the events stay in the sandbox's log either way.
With an upstream proxy, webhooks go through it, except to loopback and `no_proxy` destinations.
Queued events are delivered when the daemon stops, for up to 10 seconds.

## Observability

Each sandbox has a JSONL log at `/var/log/sandwall/<id>.jsonl`; `sandwall logs <id> [-f] [--deny-only]` prints it.
Logs outlive the sandbox.

| `type` | Fields |
|---|---|
| `dns` | `qname`, `qtype`, `verdict` (`allow`, `refused`, `ratelimited`, `error`), `answers` |
| `flow` | `proto`, `dst_ip`, `dst_port`, `dst_domain`, `bytes_out`, `bytes_in`, `ts_start`, `ts_end` |
| `deny` | `reason`, `proto`, `dst_ip`, `dst_port` |
| `quarantine` | `verdict` (`quarantined`, `released`), `reason` (the operator's) |
| `relay` | connections through the relay: `src_port`, `dst_ip`, `dst_port`, `dst_domain`, `target` (dialed address, or the proxy's CONNECT/request target), `sni`, `http_host`, `proxy_status` (with a proxy), `connect_ms`; on `deny`, `reason` (`sni_mismatch`, `host_mismatch`, `bad_client_hello`, `dial_error`, `proxy_refused`, `proxy_error`, `conn_limit`) |

Every line also has `ts`, `sandbox_id` and `verdict`.
Flow byte counts come from conntrack and are layer 3 (they include IP and TCP headers).
Identical deny events are logged at most once per second per sandbox; metrics still count every packet.

Prometheus metrics on `:9464/metrics`, all labeled `sandbox`:

| Metric | Extra label |
|---|---|
| `sandwall_flows_total` | `verdict` |
| `sandwall_bytes_total` | `direction` (`out` = sandbox to world) |
| `sandwall_dns_queries_total` | `verdict` |
| `sandwall_denied_total` | `reason` |
| `sandwall_relay_connections_total` | `result` (`ok`, `denied`, `refused`, `error`) |
| `sandwall_quarantined` (gauge) | |
| `sandwall_auto_quarantines_total` | |
| `sandwall_webhook_deliveries_total` | `webhook`, `result` (`ok`, `error`, `dropped`); no `sandbox` label |

### OpenTelemetry

The same events can be exported as OpenTelemetry log records over OTLP/HTTP (protobuf, gzip), to a collector or any OTLP backend:

```sh
sudo bin/sandwall daemon --otlp-endpoint https://otel-collector:4318 \
    --otlp-header "Authorization=Bearer $TOKEN" [--otlp-events violations]
```

`--otlp-endpoint` is a base URL to which `/v1/logs` is appended, or a full URL with a path; the standard `OTEL_EXPORTER_OTLP_*` variables for headers, TLS and timeouts also apply.
`--otlp-events violations` exports only what a quarantine trigger or alert could count, plus quarantines; the default is every event.

Each record has the event type as its event name (`sandwall.dns`, `sandwall.flow`, `sandwall.deny`, `sandwall.relay`, `sandwall.quarantine`), the event's time, a one-line body, severity `INFO` (allowed), `WARN` (denied or refused) or `ERROR` (quarantined), and the event's fields as attributes: semantic-convention names where they exist (`destination.address`, `destination.port`, `network.transport`, `dns.question.name`, `tls.client.server_name`, `source.port`) and `sandwall.*` otherwise (`sandwall.sandbox.id`, `sandwall.reason`, `sandwall.verdict`, `sandwall.bytes_in`, ...).
The resource has `service.name=sandwall` and `host.name`.
Export is batched by the OpenTelemetry SDK and never blocks the data path: when the collector is slow or down, records are dropped (and the drop is logged), while the JSONL logs are unaffected.
With an upstream proxy, export goes through it, except to loopback and `no_proxy` destinations.

## Threat model

**In scope:** code running inside a sandbox, including as root inside a VM guest, that wants to send data somewhere it should not, or reach the host, its network, cloud metadata or other sandboxes.

**What sandwall assumes:**

- The host and the sandwall daemon are trusted, and only root can reach the API socket (`/run/sandwall.sock`, mode 0600).
- Exec-mode processes run as `nobody` without capabilities, so they cannot change addresses, routes or firewall rules in their netns.
- In VM mode the guest is fully untrusted. It only controls its own kernel; everything that enforces policy lives in the netns or on the host.

**What it guarantees:**

- No connection leaves the host unless its destination was returned by an allowlisted DNS answer or is in `allow_cidrs`.
  Behind an upstream proxy, the proxy is only ever asked for allowlisted names, addresses in `allow_cidrs`, or addresses the firewall already admitted.
- No DNS query for a name that is not allowlisted reaches any resolver.
- Policy is enforced fail-closed. A sandbox interface without rules is dropped. While the daemon is down, each sandbox's data plane keeps enforcing the last policy applied; if it dies too, nothing answers the sandbox's DNS until the daemon restarts it.

**Out of scope:** payload inspection, TLS interception, ingress, IPv6 and multi-host deployment.

## Known gaps

- **Shared CDN addresses.** If a non-allowlisted domain is served from the same IP as an allowlisted one, the SNI/Host check stops TLS and HTTP to it on ports 80 and 443 (any port behind an upstream proxy). Other ports (outside `--sni-check-ports` without a proxy, or to `no_proxy` destinations) and `--sni-check=false` leave it reachable by IP until that address's set entry expires (at most 300s after the last allowlisted lookup).
- **Domain fronting.** Without TLS interception, the HTTP `Host` inside TLS is invisible, so a CDN that routes by that header can be reached through an allowlisted SNI. TLS Encrypted Client Hello would hide the SNI too; sandwall suppresses the HTTPS/SVCB records that carry ECH configs, and a client without them sends a cleartext SNI.
- **Shared platforms behind exact names.** The wildcard lint cannot help with exact names that serve many users' content, such as `raw.githubusercontent.com` or `gist.github.com`; allowlisting them lets the sandbox fetch anything hosted there.
- **Allowlisted names are an exfiltration channel if their owner is hostile.** A wildcard such as `*.example.com` lets the sandbox query any subdomain, and those queries do reach `example.com`'s nameservers. Only allowlist zones you trust.
- **Connection-limit recovery is lazy.** The kernel's `ct count` prunes closed and rejected connections only when new ones are attempted. Right after a burst, the limit can be stricter than configured for a few seconds. It never lets more connections through.
- **No IPv6.** It is disabled inside sandboxes. AAAA, HTTPS and SVCB queries get empty answers, so clients fall back to IPv4.
- **Single host.** There is no fleet management, central UI or API authentication.

Design decisions and deviations from the original plan, with the measurements behind them, are in [DECISIONS.md](DECISIONS.md).
Open work and verification still owed are tracked in [TODO.md](TODO.md).

## Development

```sh
make test         # unit tests: policy parsing, allowlist matching, DNS proxy, golden nftables rulesets
make vet fmt-check
make e2e          # root-only acceptance tests for M1-M3, the SNI check (S1), quarantine, alerts (S2), OTel export (S3) and proxy mode (M3 needs /dev/kvm); run in a disposable VM
make e2e REAL_PROXY=http://host:port         # on a host without direct internet: every daemon uses the site proxy,
                                             # and e2e-proxy also fetches real sites through it
```

Every e2e script starts and ends with `sandwall nuke`, uses its own state and log directories, and checks that nothing sandwall created is left behind.
The "attacker" endpoint is a local listener in its own netns at `10.99.0.1`, so only the allowlist checks need the internet; the proxy test runs a fake upstream proxy there too.
VM-mode paths are configurable for keeping snapshots and jails on one (reflink-capable) filesystem: `make e2e-m3 FC_ASSETS=… CHROOT_BASE=… E2E_TMP=…`.

The demos are `demo/exfil.sh` (the comparison above) and `demo/clones.sh` (20 Firecracker clones with a live, merged `sandwall logs -f`, one of which is quarantined halfway through while the others carry on).
Behind an HTTP proxy, run them with `REAL_PROXY=http://host:port`.
On nested-virtualization hosts, such as a Lima VM on Apple silicon, start many VMs with `vm clone --stagger 1s`; see DECISIONS.md.

## License

Copyright 2026 Andrey Vasilevsky.
Licensed under the [Apache License, Version 2.0](LICENSE).
The embedded Public Suffix List (`internal/policy/psl/public_suffix_list.dat`) is from [publicsuffix.org](https://publicsuffix.org) and is subject to the Mozilla Public License 2.0, as stated in its header.
