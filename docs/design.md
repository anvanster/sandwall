# sandwall design

This document explains how sandwall works and why it is built the way it is, including the alternatives that were measured and rejected.
The [README](../README.md) covers usage, the policy format and the threat model.

## Contents

- [Architecture](#architecture)
- [Firewall](#firewall)
- [DNS proxy](#dns-proxy)
- [Relay and the SNI/Host check](#relay-and-the-snihost-check)
- [Upstream proxy mode](#upstream-proxy-mode)
- [Data plane processes](#data-plane-processes)
- [Bandwidth shaping](#bandwidth-shaping)
- [Exec mode](#exec-mode)
- [VM mode](#vm-mode)
- [Quarantine](#quarantine)
- [Allowlist lint](#allowlist-lint)
- [Observability](#observability)
- [Testing](#testing)

## Architecture

### Processes

sandwall is one binary with three roles:

- **The daemon** (`sandwall daemon`) owns sandbox lifecycle: network namespaces, nftables, tc, Firecracker VMs, the flow and deny collectors, metrics, webhooks and OpenTelemetry export.
  It serves a JSON API on a root-only unix socket (`/run/sandwall.sock`, mode 0600).
- **One data plane per sandbox** (`sandwall dataplane`, a hidden command started by the daemon) runs that sandbox's DNS proxy and relay.
  It is a separate process so that sandbox DNS and relayed connections outlive a daemon restart or crash (see [Data plane processes](#data-plane-processes)).
- **The CLI** (every other command) talks to the daemon over the socket.
  `nuke` also works without a daemon.

Enforcement itself lives in the kernel: nftables decides what may leave, conntrack tracks it, and tc shapes it.
A sandbox whose interface has no rules is dropped, so every component fails closed.

### Addressing

Sandbox *k* (1 to 254) lives in netns `sb<k>`, connected to the host by the veth pair `veth-h<k>` (host side) and `veth-s<k>` (sandbox side) on `10.200.k.0/30`.
The host side is `10.200.k.1`, the sandbox side `10.200.k.2`.
The sandbox's DNS proxy listens on `10.200.k.1:53`, its relay on `10.200.k.1:15001`, and, behind an upstream proxy with `no_proxy` destinations, its direct relay on `10.200.k.1:15002`.
`internal/addressing` derives every name and address from *k*, so all packages agree on one layout.

Everything is keyed by sandbox, never by address inside the sandbox.
The listening address identifies the sandbox for DNS and the relay, and the veth interface identifies it for the firewall.
This is what lets Firecracker clones share one guest identity (see [VM mode](#vm-mode)).

### Packages

| Package | Role |
|---|---|
| `internal/daemon` | Sandbox lifecycle; the only package that composes the others. |
| `internal/api` | JSON-over-HTTP transport between CLI and daemon; no logic of its own. |
| `internal/dataplane` | The data plane process, its config file and its control API. |
| `internal/addressing` | Per-sandbox names and addresses derived from the index. |
| `internal/netns` | Network namespace, veth pair, routes and sysctls. |
| `internal/nft` | Ruleset rendering, `nft -f` application, netlink allow-set inserts. |
| `internal/dnsproxy` | Per-sandbox DNS proxy, its cache and synthetic DNS. |
| `internal/relay` | SNI/Host check and onward connection, direct or through an upstream proxy. |
| `internal/shaper` | tc bandwidth limits. |
| `internal/fc` | Firecracker jails, API, snapshots and clones. |
| `internal/flowlog` | Per-sandbox JSONL logs, the NFLOG deny collector and the conntrack flow collector. |
| `internal/metrics` | Prometheus metrics. |
| `internal/watchdog` | Automatic quarantine triggers. |
| `internal/alert` | Webhook delivery. |
| `internal/otelexport` | OpenTelemetry log export. |
| `internal/policy`, `internal/policy/psl` | Policy parsing, validation and the allowlist lint. |

### State

The daemon keeps its state under `--state-dir` (default `/var/lib/sandwall`):

- `sandboxes/<id>.json`: one record per sandbox (policy, mode, quarantine).
- `dataplane/<k>.json`, `<k>.pid`, `<k>.sock`: each data plane's config (mode 0600, as it can hold upstream proxy credentials), pid file and control socket.
  Files are named by index, not ID, because a unix socket path is limited to about 108 bytes and IDs can be 63.
- `dns/<id>.json`: each sandbox's DNS cache (see [The DNS cache](#the-dns-cache)).
- `no-proxy.json`: the effective `no_proxy` list of the previous run.
- `sysctl-orig.json`: the host sysctl values from before the first daemon start.

Logs live under `--log-dir` (default `/var/log/sandwall`) and outlive their sandbox.

### Restarts and `nuke`

A restarted daemon re-applies every sandbox idempotently, adopts its running data plane and Firecracker VM, and keeps the existing contents of its allow sets, so established clients keep working.
`net.ipv4.ip_forward`, `net.netfilter.nf_conntrack_acct` and `net.netfilter.nf_conntrack_events` are set at daemon start; their original values are recorded once, never overwritten by a restart, and restored by `nuke`.

`nuke` removes everything sandwall created, with or without a running daemon.
It asks a live daemon to drop its state, then sweeps the host directly: it kills every data plane, SIGKILLs any process still inside an `sb<k>` netns, and removes namespaces, interfaces, nftables tables, jails and state.

### Go version

`go.mod` requires Go 1.26, because the current `golang.org/x/{net,sys,sync,time}` releases require Go 1.25 to 1.26, and pinning older versions to support an older toolchain would mean shipping stale security fixes.

## Firewall

### One table, dispatched by interface

sandwall only ever touches `table inet sandwall` on the host, and `table ip sandwall_vm` inside VM-mode namespaces.
Rulesets are rendered as text and applied atomically with `nft -f`.

The base chains dispatch on the input interface through verdict maps (`iifname vmap @pre_vmap`, `@in_vmap`, `@nat_vmap`) instead of one `jump` rule per sandbox.
Creating, reloading or removing a sandbox is then one `nft -f` transaction that touches only that sandbox's chains, sets and map entries.
Re-rendering the whole table on every change would also wipe the DNS-learned allow sets of every other sandbox.
Any `veth-h*` interface without a map entry is dropped (`unknown_iface`), so a sandbox is fail-closed while it is being created.

Per sandbox *k* there are:

- `sb_<k>`: the policy for traffic leaving the host, jumped from the `prerouting` filter chain.
- `sbin_<k>`: traffic to the host itself, jumped from the `input` chain.
- `sbnat_<k>`: redirects to the relay, jumped from the `relay_redirect` nat chain (only when the relay is on).
- `allow_<k>`: DNS-learned addresses, with per-element timeouts.
- `allow_cidr_<k>`: the policy's `allow_cidrs`.
- `direct_<k>`: DNS-learned addresses of `no_proxy` names (upstream proxy mode only).

Global sets hold the blocked ranges, the `--blocked-exempt` ranges, `no_proxy` addresses and CIDRs (`direct_cidrs`), and the interfaces of quarantined sandboxes.
The README lists the rule order of `sb_<k>`.

### Policy runs in prerouting

`sb_<k>` is jumped from a filter chain on the `prerouting` hook (priority -150, after conntrack and before dstnat), not from `forward`.
The relay works by REDIRECT, which happens in prerouting and turns a packet into INPUT traffic, so a policy chain on the forward hook would never see relayed connections.
Running the policy in prerouting gives every sandbox one code path, relayed or not.

The `prerouting` chain first accepts host-bound traffic (`fib daddr type { local, broadcast, multicast }`) and leaves it to `input`, then dispatches through `pre_vmap`, then drops unknown `veth-h*` interfaces.
The `forward` chain only admits replies into sandboxes.

Over-limit connections are rejected from prerouting.
The kernel allows `reject` there (`nft_reject_validate` accepts `NF_INET_PRE_ROUTING`, and `nf_reject_ipv4` looks up the route for resets and ICMP sent from prerouting).

### Host-local destinations

Traffic from a sandbox to an address owned by the host (the DNS proxy at `10.200.k.1`, the host's LAN address, any other local address) never traverses the forward path.
`sbin_<k>` therefore accepts only established traffic, DNS to the sandbox's own proxy, and relay ports reached through a redirect (`ct status dnat`), and logs and drops everything else as `host_access`.
This also stops sandbox A from querying sandbox B's proxy, which would let A borrow B's allowlist, and from connecting to any relay directly.

### Blocked ranges

Private, loopback, link-local (including cloud metadata at `169.254.169.254`), CGNAT, multicast and reserved ranges, including `240.0.0.0/4` with limited broadcast, are dropped as `blocked_range`.
The transfer supernet `10.200.0.0/16` is blocked by its own rule, ahead of the blocked-range set, so no exemption can open sandbox-to-sandbox traffic.
`--blocked-exempt` carves ranges out of the set; it exists for testing and logs a warning.

### Connection limits

`max_conns` is one anonymous `ct count` per sandbox chain, so TCP and UDP share one budget and the count is per sandbox (`sb_<k>` only sees sandbox *k*'s packets).
Connections that are only half closed (CLOSE_WAIT) still count, as they should.

Over-limit connections jump to a shared `conn_reject` chain that answers TCP with a reset and everything else with `icmpx admin-prohibited`.
A plain `reject` would send ICMP port-unreachable, which the kernel rate-limits per destination (`net.ipv4.icmp_ratelimit`): in a burst, most rejects became silent drops and the client timed out (16 refused and 20 timed out of 36 attempts).

`ct count` uses the kernel's `nf_conncount`, shared with iptables `connlimit`, which prunes its list lazily.
Closed connections and rejected attempts stay in the list until a later connection attempt prunes them, at most once per jiffy and about 8 entries at a time.
So right after a burst of rejects or closes, the limit is temporarily stricter than configured.
Measured after 136 rejects and 64 closes, a fast burst of 64 new connections got 11 through immediately, 43 after 1s, and all 64 after 3s; connections opened 20ms apart were unaffected.
The limit never under-enforces.

### Idempotent removal

`nft destroy`, which deletes an object only if it exists, needs kernel 6.3.
Removal scripts instead first `add` every object (a no-op if it exists) and then `delete` it, in one transaction, so they succeed from any partial state on older kernels too.

### Allow-set inserts over netlink

The DNS proxy inserts every allowed answer into `allow_<k>` before it answers, so the insert is on the path of every allowed lookup.
Applying a rendered `nft -f` script there made an allowed answer take 12 to 15 ms in the nested-virtualization test VM, against about 0 ms for refused names.
Two costs, measured separately:

- Starting the `nft` process: about 13 ms in the nested VM, 2 to 3 ms on bare metal.
- Refreshing an existing element: re-adding an element does not extend its timeout, so a refresh is add, delete and add, and a commit that deletes elements waits for an RCU grace period, about 7 ms, against 0.04 ms for a plain add.

`nft.InsertAllow` therefore talks nf_tables netlink directly, using `mdlayher/netlink`, which go-nflog and the conntrack library already depend on.
It looks each address up first (`GETSETELEM`) and adds only absent ones.
An address with at least its new timeout left is left alone, and only one with less is refreshed by add, delete and add.
Elements are written with 10s on top of their timeout, because the upstream resolver's TTL and the set's timeout count down together: without the margin, every re-query within the TTL would find slightly too little time left and refresh.
An insert never shortens an element; removals go through a policy reload, which flushes and refills the sets.
Allowed answers take 1 to 2 ms on the same VM.

Only this hot path uses netlink.
Rulesets are still rendered as text, which keeps them readable and testable as golden files, and `RenderAllow` remains as the text equivalent of an insert.

### Deny logging

Dropped packets are logged to one NFLOG group, with the sandbox and reason in the log prefix, and written to the sandbox log as `deny` events.
Identical deny events (same sandbox, reason, protocol, destination and port) are logged at most once per second, so retransmits or a flood of dropped packets cannot flood the log.
`sandwall_denied_total` still counts every packet.

## DNS proxy

Each sandbox's resolver is its own DNS proxy on `10.200.k.1:53`, set through `/etc/netns/sb<k>/resolv.conf`.
DNS to any other server, and DNS-over-TLS on port 853, is dropped and logged as `dns_bypass`.

### Answers

- A query for a name that is not allowlisted gets `REFUSED` without any upstream query, so the name never leaves the host.
- For an allowlisted name, the proxy resolves it upstream, inserts the A records into `allow_<k>`, and only then answers.
  If the insert fails, the client gets `SERVFAIL` rather than an answer it cannot use.
- Each element's timeout is `max(min(TTL, 300), 60)` seconds, so it always outlives the TTL the client caches.
- AAAA, HTTPS and SVCB queries for allowlisted names get an empty `NOERROR`.
  sandwall has no IPv6, HTTPS and SVCB address hints would point clients at addresses that never entered the allow set, and their ECH configs would defeat the SNI check.
  Clients fall back to A lookups.
- Queries over `dns_qps` get `REFUSED`.
  Their log lines are themselves rate-limited, but metrics count every query.

### The DNS cache

The proxy keeps a cache of which allowlisted name resolved to which address, until when.
It is what attributes flows to names (`dst_domain` in flow logs), what refills the allow sets on a policy reload (keeping only names that are still allowlisted), and what maps synthetic addresses to names.

The cache is saved to `<state-dir>/dns/<id>.json` (mode 0600) and loaded when the sandbox's data plane starts.
Without it, a restarted data plane would keep the allow sets but lose what they mean: synthetic addresses would map to no name, flow logs would lose `dst_domain`, and a policy reload would refill the sets from an empty cache, cutting off clients whose cached answers are still valid.
Saving stays off the answer path: changes are flushed every 2s and when the proxy stops.
A newly allocated synthetic address is the exception and is written before it is handed out, because a lost mapping could later be given to another name while a client still connects to the address for the first.
Expired entries are dropped on load; an unreadable file is renamed `*.unreadable` and the sandbox starts with an empty cache.
A newly created sandbox starts empty whatever an earlier one of the same ID left; `destroy` deletes the file and `nuke` the directory.

### Synthetic DNS

Some networks only reach the internet through an HTTP proxy and have a resolver that answers internal names only.
With `--synthetic-dns` (upstream proxy mode only), the proxy answers A queries for allowlisted names from `--synthetic-dns-pool`, default `198.18.0.0/15`, and never asks the site resolver; the upstream proxy does the real resolution.
That range is reserved for benchmarking (RFC 2544), so it is never a real destination, and it lies outside every blocked range.
The daemon refuses a pool smaller than a /24, or one that overlaps a blocked range (the firewall would drop it), a `no_proxy` CIDR (that traffic would go out directly, to nowhere) or a `--blocked-exempt` range.

- Each name keeps one address while its mapping lives (300s, refreshed by every query), and the address goes into `allow_<k>` with the same lifetime, so the firewall admits it like any DNS-learned address.
- Addresses are handed out round-robin, skipping the pool's first and last address and every address still mapped; an exhausted pool answers `SERVFAIL`.
- The mapping lives in the DNS cache, so flow attribution, reload refills and the reset on quarantine release work as for real answers.
- Other record types for allowlisted names get an empty answer.
- Names that match `no_proxy` are still resolved by the site resolver, since they go out directly and are typically internal.

The relay treats a pool address only as a stand-in for its name and never sends it to the proxy (see [Upstream proxy mode](#upstream-proxy-mode)).

## Relay and the SNI/Host check

### The gap it closes

The firewall allows addresses, and a CDN serves many sites from one address.
Once an allowlisted name resolves to a shared address, a connection to that address could ask for any site on it.
The relay closes that gap: it reads the name the client asks for and refuses names that are not allowlisted.
It is on by default (`--sni-check`), because this is the most practical way around a domain allowlist.

### REDIRECT to a per-sandbox relay

`sbnat_<k>` redirects allowed TCP to the SNI check ports (`--sni-check-ports`, default `80,443`) to the sandbox's relay on `10.200.k.1:15001`.
The relay reads the original destination with `SO_ORIGINAL_DST`.

REDIRECT rather than TPROXY, because it needs neither policy routing nor `IP_TRANSPARENT` sockets.
The conntrack entry keeps the original tuple, sandbox to destination, so flow attribution by source address and the byte counts of the sandbox leg work unchanged.
The relay's own outbound connection comes from the host, not from `10.200.k.2`, and is never attributed to a sandbox.

Each sandbox has its own relay listener, next to its DNS proxy.
The listening address identifies the sandbox, so attribution never depends on looking up an address, and the `ct status dnat` match in `sbin_<k>` stops a sandbox from connecting to its relay, or another sandbox's, directly.

### Decision rules

- An allowlisted TLS SNI or HTTP `Host` passes.
- One that is not allowlisted is refused (`sni_mismatch`, or `host_mismatch` with a 403 for HTTP), unless the original destination is inside `allow_cidrs`.
- A connection with no name (no SNI, an IP-literal Host, a protocol that is neither TLS nor HTTP) passes, since the firewall already admitted its address.
  For a client that sends nothing, the relay waits 1s before deciding.

There is no TLS termination.
The ClientHello is parsed by `crypto/tls` (a server handshake aborted from `GetConfigForClient`), so hellos split across records or segments are read as a TLS server would read them.
Bytes that start like TLS but hold no parsable ClientHello are refused (`bad_client_hello`).
The consumed bytes are replayed to the destination before the relay splices the two connections.
For plain HTTP, the relay checks the `Host` of every request on a keep-alive connection.

The relay recognizes TLS and HTTP by content, not by port.
A port whose protocol is server-first (SMTP, SSH) still works through it but waits 1s for a name, so such ports should not be in `--sni-check-ports`.

### QUIC

QUIC carries its server name in an encrypted Initial packet, so the relay cannot check it.
UDP to an SNI check port on a DNS-learned address (not one inside `allow_cidrs`) is rejected with `icmpx admin-prohibited` and logged as `quic_blocked`, and HTTP/3 clients fall back to TCP.
The same rule covers every check port, since HTTP/3 can be advertised on any port; this also rejects UDP to port 80, which no legitimate client uses, and is simpler to reason about than a QUIC-only exception for 443.

Measured with curl 8.22 `--http3` against pypi.org, the reject reaches curl as `EHOSTUNREACH` and it falls back to HTTP/2 at once, adding about 0.01s.
When the kernel's per-destination ICMP rate limit swallows the reject, curl's 200ms happy-eyeballs timer starts TCP instead, adding about 0.2s.

### Configuration

`--sni-check` and `--sni-check-ports` are daemon settings that apply to every sandbox; a restarted daemon re-renders each sandbox with the current values.
`--sni-check=false` restores plain forwarding.
Behind an upstream proxy, `--sni-check-ports` has no effect on proxied destinations, since all their TCP goes through the relay.

### What it does not cover

Ports outside `--sni-check-ports` are forwarded unchecked.
The HTTP `Host` inside TLS is not visible without TLS interception, so domain fronting through an allowlisted SNI remains possible.
A destination that refuses the relay's connection appears to the sandbox as an accepted connection that is then reset, logged as `dial_error`.

### Cost

`make e2e-relay-cost` compares the relay with `--sni-check=false`, downloading from a local HTTPS server (so internet variance does not hide the relay) and from files.pythonhosted.org.
Medians on a 10-CPU nested-virtualization VM, two runs:

| | TLS handshake | First byte | Local 512 MiB | Real 55 MiB |
|---|---|---|---|---|
| relay | 2.5 ms | 2.7 ms | 8.2 to 8.5 Gbit/s | 96 Mbit/s |
| `--sni-check=false` | 2.1 ms | 2.2 ms | 9.9 Gbit/s | 91 to 96 Mbit/s |
| relay, 200 Mbit cap | 2.6 ms | 2.8 ms | 191 Mbit/s | |
| `--sni-check=false`, 200 Mbit cap | 2.1 ms | 2.2 ms | 191 Mbit/s | |

The relay adds 0.3 to 0.5 ms to a TLS handshake and keeps 83 to 86% of uncapped throughput at loopback speeds.
Once a `max_ingress_bw` cap or the internet path is the bottleneck, it costs nothing measurable.
Handshake and first-byte times are counted from the end of DNS.
The benchmark asserts that the relay sustains over 1 Gbit/s uncapped, adds under 5 ms to the handshake, and that both modes reach 85 to 105% of the cap.

## Upstream proxy mode

Many networks allow no direct egress: only an HTTP proxy reaches the internet.
On such a host every allowed flow that leaves the uplink directly is dropped by the network, so sandwall's allow verdicts would have no effect.

### The proxy is a next hop, not a destination

The sandbox keeps connecting to the real destination, for example `151.101.0.223:443` learned from an allowlisted DNS answer, and sandwall keeps enforcing policy on that destination.
Only after a connection is allowed does sandwall carry it onward, as a `CONNECT` through the upstream proxy instead of a masqueraded packet.
The sandbox needs no proxy settings and cannot see or reach the proxy.

Setting `https_proxy` inside the sandbox is the obvious alternative and is deliberately not used.
sandwall would then only see connections to the proxy, so allowing the proxy would allow everything the proxy can reach, and domain allowlists would stop meaning anything.
It would also need the sandbox's cooperation.

```
sandbox/guest: connect 151.101.0.223:443
  ▼
veth-h<k> ─► prerouting filter: iifname vmap → sb_<k>
               policy as in direct mode; deny → log + drop
               allow ▼
             relay_redirect (dstnat) → sbnat_<k>: tcp, not a no_proxy destination
               → redirect to 10.200.k.1:15001 (conntrack keeps the original destination)
               ▼
             input: sbin_<k> accepts the relay port only with ct status dnat
               ▼
             the sandbox's relay, in its data plane process
               1. original destination from SO_ORIGINAL_DST
               2. name from the TLS SNI or HTTP Host, else the DNS cache, else the address
               3. a name must be allowlisted, else deny sni_mismatch / host_mismatch
               4. dial the upstream proxy (host traffic) and send CONNECT <name>:<port>
               5. on 200, replay the peeked bytes and splice; otherwise reset the
                  sandbox connection and log proxy_refused or proxy_error
```

### CONNECT by name

The relay sends `CONNECT pypi.org:443`, not `CONNECT 151.101.0.223:443`.
Proxies often refuse CONNECT to addresses, apply their own policy and logging by name, and may be the only component that can resolve external names.
The name must be allowlisted, by the same rules as in direct mode; a connection to an `allow_cidrs` address with no allowlisted name uses the address as the CONNECT target.
A connection with no name gets the name the sandbox last resolved for the address, else the address, which the firewall already admitted.

The relay does not require the name to resolve, in the sandbox's DNS cache, to the original destination.
The proxy resolves the name itself and never uses the original address, so that binding would add nothing once the name is checked.

### Plain HTTP, other ports, UDP

- Proxies commonly allow CONNECT only to port 443.
  For port 80 the relay parses HTTP/1.1 and forwards each request in absolute form (`GET http://host/path`), checking `Host` on every request.
  The absolute-form request line and the forwarded `Host` are both set to the target the relay decided on, never taken from the sandbox's header, so an IP-literal `Host` cannot make the proxy fetch from another address.
- Other TCP ports use CONNECT; a refusal is logged as `proxy_refused`.
- An HTTP proxy cannot carry UDP.
  Allowed UDP is rejected with `icmpx admin-prohibited` and logged as `no_proxy_route`, so HTTP/3 clients fall back to TCP at once instead of timing out.
- The relay caps concurrent connections at the policy's `max_conns`.

### Synthetic addresses

With synthetic DNS, the relay never sends a pool address to the proxy.
An allowlisted SNI or Host is used as always, and an IP-literal Host falls back to the address's mapped name.
A pool address with no allowlisted name and no live mapping is refused as `synthetic_unmapped` (HTTP gets 403), and a pool address is never forwarded by address, even if `allow_cidrs` covers it.

### `no_proxy`

Destinations matching `no_proxy` get what they would get without a proxy: they go out through the masquerade path, TCP to the check ports goes through a direct relay on `10.200.k.1:15002` that dials them itself, and QUIC to their DNS-learned addresses is rejected.
The policy is applied first, so `no_proxy` only changes the route of traffic that is already allowed, never what is checked.

- Addresses and CIDRs go into the global set `direct_cidrs`, since `no_proxy` is a daemon setting.
- For an allowlisted name that also matches `no_proxy`, the DNS proxy inserts its answers into `direct_<k>` as well as `allow_<k>`, in one transaction and with the same timeout.
  A policy reload refills `direct_<k>` from the DNS cache like `allow_<k>`.
- `sb_<k>` accepts allowed traffic to either set before the TCP-only rules, and `sbnat_<k>` redirects its check-port TCP to the direct relay and leaves the rest alone.
  The redirect needs a per-sandbox chain because `direct_<k>` is per sandbox.
- The direct relay is a second listener of the sandbox's data plane with no upstream proxy.
  The firewall's redirect decides which listener a connection reaches, so the relay never has to work out whether an address is a `no_proxy` destination.

Matching follows Go's `net/http` proxy rules: `example.com` matches the name and its subdomains, `.example.com` or `*.example.com` only subdomains.
Unlike allowlist patterns, single-label suffixes such as `.corp` are accepted, because a `no_proxy` entry cannot widen access.
Ports are ignored (`host:8080` applies to every port, which only widens the entry), IPv6 and unparsable entries are skipped with a warning, and a lone `*` is an error, as it would turn the proxy off.

Like the allow set, the direct set is keyed by address: once a `no_proxy` name resolves to an address, every allowed connection to that address goes directly, including other allowlisted names served from it.
On the check ports those connections still go through the SNI/Host check.

A restarted daemon keeps the DNS-learned `direct_<k>` entries, so clients with cached answers keep their direct route.
If `no_proxy` changed since the previous run (recorded in `no-proxy.json`), the daemon empties `direct_<k>` instead, so a removed entry cannot keep sending traffic directly until its timeout.

### Configuration

The proxy is a property of the host network, so it is configured on the daemon, not in sandbox policies: `--upstream-proxy http://[user:pass@]host:port` with `--no-proxy`, or `--upstream-proxy-from-env`.
Only `http://` proxies are supported.
The mode applies to every sandbox of the daemon; restarting the daemon with or without it re-renders every sandbox.
The proxy's address stays subject to `blocked_range` for sandbox traffic, and proxy credentials stay on the host.
Where the site resolver answers external names, DNS is unchanged: the DNS proxy's upstream queries are host traffic.

## Data plane processes

### Why

With the DNS proxy and relay inside the daemon, stopping or restarting it would end every relayed connection (all SNI-checked HTTP and HTTPS, and all TCP behind an upstream proxy) and leave sandboxes without DNS until it was back.
A graceful drain would only cover planned restarts and delay them, and handing listening sockets to a new daemon would only cover planned upgrades.
A process per sandbox covers restarts and daemon crashes alike, the way Firecracker VMs already outlive the daemon.

### Shape

`sandwall dataplane --config <state-dir>/dataplane/<k>.json` runs one sandbox's DNS proxy and relay, in its own session, writes its pid file and serves a root-only control socket next to its config.
The config file holds everything the data plane needs, including the upstream proxy URL with its credentials.
The control API (JSON over the socket) has `status` (protocol version, pid, config hash), `policy` (a hot reload), `quarantine`, `domain` (the name behind an address, for flow logs) and `counters`.

A policy reload is atomic: the data plane swaps the DNS settings and re-renders the sandbox's ruleset, with the allow sets refilled from its DNS cache, while no DNS answer can insert.
The daemon only renders the rule template.

### Adopting, restarting, supervising

A restarted daemon adopts a running data plane whose protocol version and structural config hash match (listeners, files, whether there is a relay, its upstream proxy, the synthetic pool) and reapplies policy and quarantine to it.
Settings changes alone never restart it.
A structural change (adding or removing an upstream proxy, `--sni-check=false`, a new protocol version) restarts it, which ends its relayed connections; the daemon logs that.
Every 2s the daemon checks each data plane and restarts one that died; its DNS cache comes back from the state file.
The pid in a pid file is only trusted if `/proc/<pid>/cmdline` is that sandbox's data plane, so a reused pid is never signalled.
Destroy stops the data plane (SIGTERM, then SIGKILL after 5s).

While the daemon is down, each data plane keeps enforcing the last policy applied.
If a data plane dies too, nothing answers that sandbox's DNS and relayed ports until the daemon restarts it, so the sandbox fails closed.

### Events and metrics

The data plane appends its own events (`dns`, `relay`) to the sandbox's JSONL log; the daemon appends the rest (`deny`, `flow`, `quarantine`) to the same file, each line one `O_APPEND` write.
The daemon tails each sandbox log for the data plane's events and feeds them to the watchdog, webhooks and OpenTelemetry export, and counts relay refusals in `sandwall_denied_total`.
It reads from the end of the file when it starts, so events written while the daemon was down are in the log but trigger no alert, quarantine or metric.
`sandwall_dns_queries_total` and `sandwall_relay_connections_total` are kept by the data planes and read at scrape time, so they survive daemon restarts; they start over when a data plane restarts, which Prometheus treats as a counter reset.

## Bandwidth shaping

`max_ingress_bw` (world to sandbox) is a `tbf` root qdisc on `veth-h<k>`, whose egress carries traffic toward the sandbox.

`max_egress_bw` (sandbox to world) uses an IFB device: an ingress u32 match-all filter on `veth-h<k>` redirects packets to `eg-ifb<k>`, whose `tbf` root qdisc queues and shapes them.
An ingress policer is the simpler alternative and does not work here.
A policer drops instead of queueing, and on a sub-millisecond veth path TCP keeps backing off: a 10 Mbit cap measured 2 Mbit/s, and a 200 Mbit cap 48 Mbit/s.
With the IFB, the same caps measure 9 and 191 Mbit/s.
A u32 filter is used because `cls_matchall` is not built into every kernel.
`eg-ifb<k>` exists only while an egress cap is set.

## Exec mode

`sandbox exec` runs `ip netns exec sb<k> setpriv --reuid=65534 --regid=65534 --clear-groups --inh-caps=-all --bounding-set=-all --no-new-privs -- <command>`.
`ip netns exec` provides the `/etc/netns/sb<k>/resolv.conf` bind mount.
Clearing the bounding set means not even a setuid binary can regain `CAP_NET_ADMIN`, so nothing in the sandbox can change its addresses, routes or firewall.
Exec mode isolates the network only; it is meant to be combined with whatever process and filesystem isolation the sandbox already has.

## VM mode

### Netns plumbing

A Firecracker guest is `172.16.0.2` on `tap0`, inside the sandbox's netns.
There, sandwall owns `table ip sandwall_vm`: guest DNS to `172.16.0.1:53` is DNATed to `10.200.k.1:53`, and guest traffic leaving `veth-s<k>` is masqueraded to `10.200.k.2`.
From then on the host enforces policy and attributes logs exactly as for exec mode.

- DNS DNAT is limited to destination `172.16.0.1`.
  DNATing every port-53 packet would silently answer `dig @8.8.8.8` from the proxy, and the host would never see or log the bypass attempt.
- The netns's forward policy is `drop`: only `172.16.0.2` may be forwarded out (no spoofing), and the guest cannot open connections to the netns itself.

Because every guest has the same address inside its own netns, and the host only sees `10.200.k.2`, clones restored from one snapshot work side by side without any change to the guest.

### Jails and identity

Each VM runs as `jailer --id sandwall-sb<k> --netns /var/run/netns/sb<k>`, under uid and gid `base+k`, in its own chroot under `--chroot-base` (default `/srv/jailer`).
The base defaults to 2000000000 (ids stay below 2^31) and is set with `daemon --vm-uid-base`.
It is deliberately far from 100000, where distributions start the subordinate ranges in `/etc/subuid` and `/etc/subgid`: a rootless container of a regular user would otherwise run with the same ids as a VMM and could open its jail files.
The daemon refuses to start in VM mode if any id in `base+1..base+254` belongs to a user or group, or lies in a subordinate range.

Every jail uses the same names: `vmlinux`, `drive-<id>`, `tap0`, guest MAC `06:00:AC:10:00:02` and guest IP `172.16.0.2`, so a snapshot from any sandbox restores unchanged in any other.
`--vm-config` is a Firecracker config file without `network-interfaces`, which sandwall owns.
sandwall rewrites paths to jail-relative names and appends `ipv6.disable=1 ip=172.16.0.2::172.16.0.1:255.255.255.252::eth0:off` to the boot arguments.

### Snapshots and clones

`vm snapshot` pauses the VM, writes a full snapshot, copies the drives while still paused (so memory and disk agree), and resumes it.
Clones hard-link the memory file (Firecracker maps it privately, so clones share clean pages) and get their own copy of each drive, made with `cp --reflink=auto`, which is free on XFS or btrfs.
Clones are restored paused, get their rate limiters from their own policy through `PATCH /network-interfaces`, and are then resumed.
A restarted daemon adopts VMs that are still running and restarts dead ones from their original source (config or snapshot).

`vm clone --stagger <duration>` spaces out the starts.
On bare-metal KVM, `--stagger 0` works: 20 clones started back to back on a 96-CPU host and then all fetched at once.
Under nested virtualization, starting many guests back to back, or keeping many busy at once, can leave guests with a vCPU spinning and unresponsive for minutes (see [Testing notes](#testing-notes)).
sandwall does not hide a delay for this; the stagger is explicit, and also useful on bare metal to spread out the memory faulting of many clones.

### Rate limiters

Bandwidth limits are applied twice: by tc on the host and by Firecracker's own rate limiters.
The host `tbf` does the fine-grained shaping; the Firecracker limiter is a coarser second boundary that holds even if host shaping is misconfigured.
Its token buckets refill every 1s and hold one second of traffic.
With a 100ms bucket, a 10 Mbit cap measured 5 Mbit/s for a guest TCP upload; with 1s it measures 9 Mbit/s.

### Long requests

CLI requests get a 60s timeout only when the command sets no deadline of its own.
`vm clone` allows the count times (stagger plus 2 minutes) plus 60s, `vm snapshot` 15 minutes, and a VM-mode `sandbox create` 5 minutes.
The daemon cancels a request whose client disconnects, so a CLI timeout shorter than the operation would stop a clone part way.
Ctrl-C still cancels them.

## Quarantine

### Why

Detection alone does not stop an agent that is already exfiltrating.
`policy apply` deliberately keeps established flows, so tightening a policy cannot cut a tunnel that is already open, and `sandbox destroy` cuts it but throws away the sandbox.
`sandbox quarantine` is the kill switch that keeps the evidence.

### Firewall

A quarantined sandbox's `sb_<k>` is a single logged drop (`quarantined`) that comes before the `established` rule, so open flows stop in both directions at the next packet.
Its `sbin_<k>` admits only DNS to its own proxy, so attempted lookups are still answered (`REFUSED`) and logged; the relay ports are not admitted.
Replies on forwarded flows would still reach the sandbox through the forward chain's `established` rule, so the forward chain first drops anything leaving through an interface in the global set `quarantined`.
`allow_<k>` and `direct_<k>` are emptied.
The policy itself is kept, and `policy apply` during a quarantine stores and renders the new policy behind the quarantine.

### Conntrack entries are deleted

Dropping packets alone would leave the conntrack entries of cut flows in place (established TCP times out after five days by default), and a release would let them continue as established.
Quarantine therefore deletes every entry whose original source is the sandbox's address.
The flow collector logs each one from its DESTROY event, so the log shows exactly how much every cut flow had moved.

### DNS proxy and relay

The DNS proxy refuses every query before the allowlist and rate limiter, without forwarding, and logs each refusal: during an incident, every attempted name is evidence.
The relay resets all of its connections and refuses new ones.
On release, the proxy forgets every address it learned and the allow sets start empty, so nothing learned before the quarantine is reachable until it is resolved again.

### Freeze

`--freeze` pauses a VM through the Firecracker API, or sends SIGSTOP to every process in an exec sandbox's netns.
SIGSTOP is repeated until a pass finds no new process, to catch forks during the first pass.
An exec sandbox has no cgroup of its own, so SIGSTOP is the available freezer; another process running as `nobody` on the host could send SIGCONT, but a stopped process cannot reach the network while the quarantine holds.
`vm snapshot` of a frozen VM leaves it paused, so a memory image can be taken for analysis without letting the guest run.

The quarantine (time, reason, frozen) is stored in the sandbox record, so a restarted daemon re-applies it before the sandbox's data plane starts, and a VM restarted from its source is paused again if it was frozen.

### Automatic quarantine

Triggers live in the sandbox policy, not in daemon flags: what is suspicious depends on the workload, and `policy apply` changes them like any other part of the policy.
They are opt-in, because a quarantine stops the sandbox's work and an unexpected one is an outage.

The watchdog sees every event written to a sandbox log, maps it to a trigger reason (firewall deny reasons, relay refusals, and `dns_refused` and `dns_ratelimited` for DNS), and keeps, per trigger, the times of the last `count` matching events.
When `count` of them fall within `window`, the trigger fires once and calls the same quarantine as the CLI, with a reason naming the trigger and the last event.
The watchdog is disarmed while the sandbox is quarantined and re-armed with empty counts on release or policy apply.

Counting logged events rather than packets is deliberate.
The deny log already collapses identical drops to one per second, so a single blocked connection's retransmits count once, and a trigger counts attempts.
`count` is capped at 10000 and `window` at 24h, so a policy cannot make the daemon keep unbounded history.
Events of a quarantined sandbox, including its own `quarantined` drops and DNS refusals, never count.
The policy accepts only reasons that something produces; a unit test keeps that list in step with the firewall, relay and DNS constants.
A daemon restart resets the counts, which only delays a trigger.

## Allowlist lint

### What counts as multi-tenant

A wildcard `*.X` is multi-tenant when `X` is a public suffix, or when a public suffix lies below `X` (`*.amazonaws.com` covers `s3.amazonaws.com`), according to the ICANN and private sections of the Public Suffix List.
The private section is maintained by the platforms themselves to say exactly this: names below the suffix belong to different, unrelated parties.
A wildcard below a tenant (`*.my-app.vercel.app`) and exact names are not flagged.
The policy parser already requires a wildcard to cover at least a second-level domain, which stops `*.com`; the list also stops `*.co.uk`.

### Reject with acknowledgement, not warn

A warning in a daemon log is easy to miss, and the cost of the mistake is an exfiltration path, so `sandbox create`, `vm clone` and `policy apply` reject an unacknowledged multi-tenant wildcard.
The acknowledgement lives in the policy (`egress.allow_multitenant`, which must repeat an `allow_domains` entry and allows nothing by itself), not in a CLI flag, so it is reviewed and stored with the policy and survives restarts.

`policy.Parse` stays structural, and `Lint` applies only to newly submitted policies.
A daemon restoring a sandbox whose stored policy fails the lint, for instance after a list update adds a suffix, logs a warning and restores it, rather than leaving a running sandbox unmanaged.

### The list is embedded

`golang.org/x/net/publicsuffix` can tell whether a name is a suffix but cannot list the suffixes below a name, which `*.amazonaws.com` needs.
The list file is therefore embedded (`internal/policy/psl`, about 330 KB) and parsed once on first use.
It is MPL-2.0 and kept unmodified with its license header; `make psl-update` refreshes it, and lint errors name the list version.

Exact names that serve many users' content (`raw.githubusercontent.com`, `gist.github.com`) are single names to the lint; the README lists them as a known gap.

## Observability

### Flow logs

Flows come from conntrack events.
Conntrack only sends DESTROY, the one event with byte counters, after a closed TCP connection leaves TIME_WAIT (120s by default).
To log flows promptly, the collector also listens to UPDATE events: when a TCP flow reaches TIME_WAIT or CLOSE, it fetches the entry's counters with a conntrack query, logs the flow then, and skips the later DESTROY.
Other protocols are logged at DESTROY.

`ts_start` comes from `nf_conntrack_timestamp` where the kernel has it (enabled as an optional sysctl), otherwise from the time the collector saw the flow's NEW event.
`dst_domain` comes from the sandbox's DNS cache.
Byte counts are layer 3, so they include IP and TCP headers; on a 10 MiB download they come out 1.4 to 1.7% above the payload size.
Relayed connections are logged from the sandbox leg, whose conntrack entry keeps the original destination.

### Metrics

Denied traffic never becomes a confirmed conntrack flow, so there is no denied flow to count.
`sandwall_flows_total{verdict="deny"}` counts logged deny events, which are de-duplicated per second, as an approximation of denied flow attempts, while `sandwall_denied_total{reason}` counts every dropped or rejected packet and every relay refusal.

### Webhooks

Webhook URLs and signing keys are daemon flags (`--webhook name=URL`, `--webhook-secret name=file`), and policies refer to endpoints by name.
Policies are stored in the state directory and returned by `sandbox list --json`, so they are the wrong place for credentials, and an operator who may change a policy should not be able to point alerts at an arbitrary URL.
A policy naming an endpoint the daemon lacks is rejected at create and apply; at restore it is a warning, like the allowlist lint.

Events use the same vocabulary as quarantine triggers, plus `quarantine` for quarantine and release events, and are the log's own JSON objects, so a receiver sees exactly what `sandwall logs` shows, after the same de-duplication.

Delivery never blocks the data path.
Each endpoint has a 1000-event queue; overflow is counted (`dropped`) and reported in the next payload.
One goroutine per endpoint batches up to 100 events or 2 seconds, and flushes at once on a quarantine event, which is the one an operator must see immediately.
A delivery is tried three times (1s, then 2s apart); after that it is counted as an error and dropped, as the events remain in the sandbox log.
On daemon stop, queued events get up to 10 seconds to go out.

Requests are signed with `X-Sandwall-Signature: sha256=HMAC(key, "<X-Sandwall-Timestamp>.<body>")`, the scheme common webhook providers use, so a receiver can authenticate the sender and reject replays by timestamp.
Keys come from files so they stay out of process listings, and keys shorter than 16 bytes are rejected.
Endpoints without a key are allowed, for local receivers, and are simply unsigned.

On a host behind an HTTP proxy, the daemon itself cannot reach external receivers directly either, so webhooks use the upstream proxy when one is configured, except to loopback addresses and `no_proxy` destinations.
The same applies to OpenTelemetry export.

### OpenTelemetry

Events are exported with the OpenTelemetry Go SDK's log provider and its OTLP/HTTP exporter (protobuf, gzip) rather than a hand-written encoder.
The SDK brings batching, retries, and the standard `OTEL_EXPORTER_OTLP_*` configuration (headers, TLS, timeouts) that collector operators expect.
OTLP/HTTP rather than gRPC, because it goes through HTTP proxies like the daemon's other requests.
The cost is about 5 MB of binary size, partly because the OTLP protobuf package that the HTTP exporter needs also carries the generated gRPC service definitions.

The event type becomes the record's event name (`sandwall.deny`), its time the record time, and its fields attributes.
Fields with an OpenTelemetry semantic convention use it (`destination.address`, `destination.port`, `network.transport`, `dns.question.name`, `tls.client.server_name`, `source.port`); the rest are namespaced `sandwall.*`, so they cannot collide with conventions added later.
Severity is `INFO` for allowed events, `WARN` for denials and refusals, and `ERROR` for a quarantine.
The body is a one-line summary for log viewers that show only bodies.

The SDK's batch processor drops records rather than block when its queue is full; the JSONL log stays the record of truth.
On shutdown the provider gets 10 seconds to export what is queued.

## Testing

### Unit tests

`make test` covers policy parsing and validation, allowlist matching and the lint, the DNS proxy's decisions, cache and synthetic pool, the relay's name decisions against fake upstreams, golden nftables rulesets, the data plane's control API, the watchdog, webhook delivery and signing, and OpenTelemetry attribute mapping.
Tests that need root (netlink set inserts in a throwaway netns) skip without it.

### End-to-end tests

The e2e suites (`make e2e` and the targets listed in the README) are root-only shell scripts that run the real binary against a real kernel, in a disposable Linux VM.
Every script starts and ends with `sandwall nuke`, uses its own state and log directories, and checks that nothing sandwall created is left behind.

The "attacker" endpoint is a listener in its own netns `egattacker`, at `10.99.0.1`, reached through a veth.
A dummy interface on the host would be simpler, but its address would be host-local, so sandbox traffic to it would hit the input path (`host_access`) instead of the path real internet destinations take.
`10.99.0.0/24` lies in `10.0.0.0/8`, so the tests start the daemon with `--blocked-exempt` for it.
The upstream proxy tests run a fake proxy (`proxy.py`) there that logs every request line, and the OpenTelemetry tests a small Go OTLP receiver (`test/e2e/otlpsink`).

With `REAL_PROXY=http://host:port`, every e2e daemon runs behind that proxy, with the attacker net as `no_proxy`, so the suites also pass on hosts without direct internet access.

### Testing notes

The suites have passed on Ubuntu 24.04 (kernel 6.8, nftables 1.0.9) in a 10-CPU Lima VM with nested virtualization on Apple silicon, and on a bare-metal host with kernel 6.19 behind an HTTP proxy.

Nested virtualization limits how many Firecracker guests can start or work at once.
In the Lima VM, starting many KVM guests about 0.6s apart left most of them with a vCPU spinning in the guest, unresponsive for minutes; the KVM counters showed constant exits but almost no WFI.
Starts paced 1s apart worked on some days, while on others even 3s left early clones unreachable with 20 clones; 10 clones always worked.
Twenty clones fetching at once, or twenty simultaneous SSH handshakes into them, also stalled guests.
The M3 test therefore defaults to `--stagger 1s` (`CLONE_STAGGER`) and fetches from its clones in overlapping waves of `FETCH_CONCURRENCY` (default 8), checking from conntrack timestamps that each wave's fetches overlapped.
On the bare-metal host, `CLONE_STAGGER=0 FETCH_CONCURRENCY=20` passes.
