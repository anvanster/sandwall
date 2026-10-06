# Design decisions and deviations

Deviations from, and clarifications of, the original design (an internal design document, not part of this repository).
Each entry states what the original design said where that matters.
Newest last.

## M1

### Host-local destinations need an INPUT chain (`sbin_<k>`)
Traffic from a sandbox to an address owned by the host (the DNS proxy at `10.200.k.1`, the host's LAN IP, any other local address) never traverses the FORWARD hook, so the per-sandbox `sb_<k>` chain cannot see it.
Each sandbox therefore also gets `sbin_<k>`, hooked from an `input` base chain, which accepts only established traffic and DNS to its own proxy and logs and drops everything else with reason `host_access`.
The original rule admitting DNS to the proxy is still rendered into `sb_<k>` for parity, but in practice it is `sbin_<k>` that admits proxy traffic.
This is also what stops sandbox A from querying sandbox B's proxy, which would otherwise let A borrow B's allowlist.

### Dispatch via verdict maps, per-sandbox transactions
The base chains dispatch with `iifname vmap @fwd_vmap` / `@in_vmap` instead of one `jump` rule per sandbox.
Creating, reloading or removing a sandbox is one `nft -f` transaction touching only that sandbox's chains, sets and map entries.
Re-rendering the whole table on every change would wipe the DNS-learned `allow_<k>` sets of every other sandbox.
Rulesets are still generated as text and applied atomically, as originally designed.
Any `veth-h*` interface without a map entry is dropped (`unknown_iface`), so a sandbox is fail-closed while it is being created.

### Idempotent removal without `destroy`
`nft destroy` needs kernel 6.3+, while the supported floor is Linux 5.10.
Removal scripts first `add` every object (a no-op if it exists) and then `delete` it, all in one transaction, so they succeed from any partial state on any supported kernel.
Refreshing a DNS-learned set element uses the same add/delete/add pattern, because re-adding an existing element does not extend its timeout.

### Blocked ranges
In addition to the originally specified list, `240.0.0.0/4` (reserved, includes limited broadcast) is blocked.
The transfer supernet `10.200.0.0/16` is blocked by its own rule, ahead of the blocked-range set, so no exemption can open sandbox-to-sandbox traffic.

### Test endpoint: routed netns instead of a dummy link
The original test plan suggested an HTTP listener on a dummy interface `egtest0` with `10.99.0.1`.
An address on a host dummy link is host-local, so sandbox traffic to it would hit INPUT (`host_access`) rather than the FORWARD path that real internet destinations take.
The e2e harness instead puts the listener in its own netns `egattacker`, reached through a veth `egtest0`, so the test exercises the same path as real egress.
`10.99.0.0/24` falls in `10.0.0.0/8`, so the daemon has a `--blocked-exempt` flag (testing only; it logs a warning) to carve it out.

### DNS proxy details
- Set entry timeout is `max(min(TTL, 300), 60)` seconds per A record, so it always outlives the TTL the client caches.
- HTTPS and SVCB queries for allowlisted names get an empty NOERROR, like AAAA.
  Their address hints would point clients at IPs that never entered the allow set, and ECH configs would defeat the SNI check (S1).
  Clients fall back to A lookups.
- If inserting into the allow set fails, the client gets SERVFAIL rather than an answer it cannot use.
- Over-limit queries get REFUSED. Their log lines are themselves rate-limited, but metrics count every query.

### Deny log de-duplication
Identical deny events (same sandbox, reason, protocol, destination and port) are logged at most once per second, so retransmits or a flood of dropped packets cannot flood the log.
`sandwall_denied_total` still counts every packet.

### Exec mode
`sandbox exec` runs `ip netns exec sb<k> setpriv --reuid=65534 --regid=65534 --clear-groups --inh-caps=-all --bounding-set=-all --no-new-privs -- cmd`.
`ip netns exec` provides the `/etc/netns/sb<k>/resolv.conf` bind mount.
Clearing the bounding set means not even a setuid binary can regain `CAP_NET_ADMIN`.

### Daemon restart and state
Sandbox records are persisted under `--state-dir` (default `/var/lib/sandwall/sandboxes/`).
A restarted daemon re-applies each sandbox idempotently and rebinds its DNS proxy, keeping the existing `allow_<k>` contents so established clients keep working.
While the daemon is down, sandbox DNS fails closed: nothing listens on `10.200.k.1:53`.
`nuke` works with or without a running daemon.
It asks a live daemon to drop its state, then sweeps the host directly.
It also SIGKILLs any process still inside an `sb<k>` netns.

### Host sysctls
`net.ipv4.ip_forward`, `net.netfilter.nf_conntrack_acct` and `net.netfilter.nf_conntrack_events` are set at daemon start.
Their original values are recorded once, never overwritten by a restart, and restored by `nuke`.

### Package layout
`internal/daemon` is added to the originally planned package layout.
It owns sandbox lifecycle and is the only package that composes netns, nft, dnsproxy, flowlog and metrics; `internal/api` is only the HTTP transport in front of it.
`internal/addressing` holds the index-to-names/addresses derivation that every package shares.

### Go version
`go.mod` requires Go 1.26 rather than 1.22.
The current `golang.org/x/{net,sys,sync,time}` releases require Go 1.25 to 1.26, and pinning older versions to meet the originally planned Go 1.22 floor would mean shipping stale security fixes.

## M2

### Sandbox-to-world shaping uses IFB + tbf, not a policer
The original design used an ingress policer on `veth-h<k>` for `max_egress_bw`.
Measured on the e2e host, a policer with a 10 Mbit cap let TCP reach only 2 Mbit/s, and a 200 Mbit cap only 48 Mbit/s.
A policer drops instead of queueing, and on a sub-millisecond veth path TCP keeps backing off.
Instead, an ingress u32 match-all filter on `veth-h<k>` redirects packets to an IFB device `eg-ifb<k>`, whose `tbf` root qdisc queues and shapes them.
With that, the same caps measure 9 and 191 Mbit/s.
`max_ingress_bw` uses the originally designed `tbf` on `veth-h<k>` egress.
A u32 filter is used because `cls_matchall` is not built into every kernel.
`eg-ifb<k>` is created only while an egress cap is set, and `destroy`/`nuke` remove it.

### Connection-limit rejects use TCP reset
The originally designed `ct count over N reject` sends ICMP port-unreachable.
The kernel rate-limits ICMP errors per destination (`net.ipv4.icmp_ratelimit`), so in a burst most rejects became silent drops and the client timed out (observed: 16 refused, 20 timed out of 36).
Over-limit connections now jump to a shared `conn_reject` chain that answers TCP with a reset and everything else with `icmpx admin-prohibited`.
The count stays one anonymous `ct count` per sandbox chain, so TCP and UDP share one budget.

### Connection-limit semantics verified per sandbox
The anonymous `ct count` in `sb_<k>` only sees sandbox k's packets, so its count is per sandbox.
The M2 e2e test holds sandbox t3 at its 64-connection limit while t1 opens 20 connections without any rejects.
Connections that are only half closed (CLOSE_WAIT) still count, as they should.

Known gap: `ct count` (the kernel's `nf_conncount`, shared with iptables `connlimit`) prunes its list lazily.
Closed connections and rejected attempts stay in the list until a later connection attempt prunes them, at most once per jiffy and about 8 entries at a time.
So right after a burst of rejects or closes, the limit is temporarily stricter than configured.
Measured after 136 rejects and 64 closes: a fast burst of 64 new connections got 11 through immediately, 43 after 1s, and all 64 after 3s.
Connections opened 20ms apart were unaffected.
The limit never under-enforces.

### Flow log timing
Conntrack only sends DESTROY, the one event with byte counters, after a closed TCP connection leaves TIME_WAIT (120s by default).
To log flows promptly, the collector also listens to UPDATE events.
When a TCP flow reaches TIME_WAIT or CLOSE, it fetches the entry's counters with a conntrack query, logs the flow then, and skips the later DESTROY.
Other protocols are logged at DESTROY.
`ts_start` comes from `nf_conntrack_timestamp` where the kernel has it (enabled as an optional sysctl).
Otherwise it comes from the time the collector saw the flow's NEW event.
Byte counts are layer 3, so they include IP and TCP headers.
On the 10 MiB e2e download they come out 1.4 to 1.7% above the payload size.

### `sandwall_flows_total{verdict="deny"}`
Denied traffic never becomes a confirmed conntrack flow, so there is no denied "flow" to count.
This series counts logged deny events, which are de-duplicated per second, as an approximation of denied flow attempts.
`sandwall_denied_total{reason}` counts every dropped or rejected packet.

## M3

### VM-mode netns plumbing
Inside a VM-mode netns, sandwall owns `table ip sandwall_vm`.
Guest DNS to `172.16.0.1:53` is DNATed to `10.200.k.1:53`, and guest traffic leaving `veth-s<k>` is masqueraded to `10.200.k.2`.
From then on the host enforces policy and attributes logs exactly as for exec mode.
Two deviations from the original design:
- **DNS DNAT is limited to destination `172.16.0.1`.** The original design DNATed every port-53 packet. That would silently answer `dig @8.8.8.8` from the proxy, and the host would never see or log the bypass attempt. With the narrower DNAT, the M1 bypass check behaves the same from inside a guest.
- **The forward policy is `drop`.** Only `172.16.0.2` may be forwarded out (no spoofing), and the guest cannot open connections to the netns itself.

The host reaches a guest over SSH from inside its netns (the e2e harness's control channel).
Replies come back through the `established` rule.

### Jail layout and identity
Each VM runs as `jailer --id sandwall-sb<k> --netns /var/run/netns/sb<k>`, under uid/gid `base+k`, in its own chroot under `--chroot-base` (default `/srv/jailer`).

The base was originally 100000, which is where distributions start the subordinate ranges in `/etc/subuid` and `/etc/subgid`.
A rootless container of the first regular user would run with the same ids as a VMM and could open its jail files.
The default base is now 2000000000 (ids stay below 2^31), configurable with `daemon --vm-uid-base`, and the daemon refuses to start in VM mode if any id in `base+1..base+254` belongs to a user or group, or lies in a subordinate range.
A VM that was already running when the daemon is upgraded keeps its old uid until it is restarted.
Every jail uses the same names: `vmlinux`, `drive-<id>`, `tap0`, guest MAC `06:00:AC:10:00:02` and guest IP `172.16.0.2`.
So a snapshot from any sandbox restores unchanged in any other.
`--vm-config` is a Firecracker config file without `network-interfaces`, which sandwall owns.
sandwall rewrites paths to jail-relative names and appends `ipv6.disable=1 ip=172.16.0.2::172.16.0.1:255.255.255.252::eth0:off` to the boot args.

### Snapshots and clones
`vm snapshot` pauses the VM, writes a full snapshot, copies the drives while still paused (so memory and disk agree), and resumes it.
Clones hard-link the memory file (Firecracker maps it privately, so clones share clean pages) and get their own copy of each drive.
The copy uses `cp --reflink=auto`, which is free on XFS or btrfs.
Clones are restored paused, get their rate limiters from their own policy via `PATCH /network-interfaces`, and are then resumed.
A restarted daemon adopts VMs that are still running and restarts dead ones from their original source (config or snapshot).

### Firecracker rate limiter sizing
The Firecracker token buckets refill every 1s and hold one second of traffic.
With a 100ms bucket, a 10 Mbit cap measured 5 Mbit/s for a guest TCP upload.
With 1s it measures 9 Mbit/s.
The host `tbf` on the IFB still does the fine-grained shaping; the Firecracker limiter is a second, coarser boundary that holds even if host shaping is misconfigured.

### M3 acceptance on a host without direct internet
The bare-metal M3 host reaches the internet only through an HTTP proxy, so the guest checks that fetch real sites could not pass with direct egress.
With `REAL_PROXY` set, every e2e daemon runs with that proxy as its upstream proxy and the local attacker net as `no_proxy`.
Internet checks then go through the relay, and attacker-based checks (bandwidth, clone fetches, denies) take the same direct path as before.
On that host M1 (77), M2 (54) and M3 (59, with `--stagger 0` and all 20 clones fetching at once) pass in full.

The M1 "LAN gateway" check used to expect `blocked_range`, assuming the default gateway is on a private address.
It now asks the live `blocked_ranges` set: a gateway on a public address, as on that host, is denied as `not_allowed` like any other unlisted destination.

### `vm clone --stagger` and nested virtualization
M3 was developed in a Lima VM (vz backend) with nested virtualization on Apple silicon.
There, starting many KVM guests back to back (about 0.6s apart) left most of them with a vCPU spinning in the guest, unresponsive for minutes.
The KVM counters showed constant exits but almost no WFI.
This happened with freshly booted VMs as well as restored clones, and never with one VM, or with starts paced 1s apart (20 of 20 healthy, idle at ~0% CPU).
sandwall does not hide a delay for this.
`vm clone --stagger <duration>` is an explicit option, also useful on bare metal to spread out the memory faulting of many clones.
The M3 e2e test uses `--stagger 1s` (override with `CLONE_STAGGER`).
On bare-metal KVM `--stagger 0` works: on a 96-CPU host, 20 clones started back to back, then all 20 fetched at once (`FETCH_CONCURRENCY=20`), in two separate runs.

The same host limit applies to guests that are busy at the same time, not only to starts.
With 20 clones fetching at once, or 20 simultaneous SSH handshakes into them, on a 10-CPU Lima VM, several guests stalled for minutes.
So the M3 test keeps all 20 clones running simultaneously, but runs their allowlisted fetches concurrently in waves of `FETCH_CONCURRENCY` (default 8).
It checks, from the host's conntrack timestamps, that the fetches within each wave overlapped.
On bare metal, set `FETCH_CONCURRENCY=20` to fetch from all clones at once.

On 2026-10-05 the same Lima VM was less forgiving: with 20 clones, 1s and even 3s spacing left early clones (usually `c-1`) unreachable while the later ones were restored, although `c-1` stayed healthy through 8 single-clone restores and the base VM was idle when snapshotted.
`demo/clones.sh` passed there with 10 clones.
20 clones remain verified only on bare metal, as above.

### Long CLI requests
The CLI used one HTTP client timeout of 60s for every request.
`vm clone --count 20 --stagger 3s` takes about 70s, so the CLI gave up, and because the daemon cancels a request whose client disconnects, the clone stopped part way (17 of 20).
Requests now get the 60s default only when the caller sets no deadline; `vm clone` allows the count times (stagger plus 2 minutes) plus 60s, `vm snapshot` 15 minutes, and a VM-mode `sandbox create` 5 minutes.
Ctrl-C still cancels them.

## Upstream proxy

Many networks allow no direct egress: only an HTTP proxy reaches the internet, while the site resolver still resolves external names.
On such a host every allowed sandbox flow leaves the uplink and is dropped by the network, so sandwall's allow verdicts have no effect.
Seen on an M3 bare-metal host: the two guest checks that fetch real internet sites got no connection, while all 57 others passed.

### The proxy is a next hop, not a destination
The sandbox keeps connecting to the real destination, for example `151.101.0.223:443` learned from an allowlisted DNS answer, and sandwall keeps enforcing policy on that destination.
Only after a flow is allowed does sandwall carry it onward, as a `CONNECT` through the upstream proxy instead of a masqueraded packet.
The sandbox needs no proxy settings and cannot see or reach the proxy.

Setting `https_proxy` inside the sandbox was rejected.
sandwall would then only see connections to the proxy, so allowing the proxy would allow everything the proxy can reach, and domain allowlists would stop meaning anything.
It would also need the sandbox's cooperation.

### Packet flow (TCP)
```
sandbox/guest: connect 151.101.0.223:443
  ▼
veth-h<k> ─► prerouting filter (priority -150): iifname vmap → jump sb_<k>
               same rules as today; deny → log + drop
               allow ▼
             prerouting nat (dstnat): proxied sandbox, tcp, daddr not local, not @direct_<k>
               → redirect to 10.200.k.1:15001 (conntrack keeps the original destination)
               ▼
             input: sbin_<k> accepts tcp dport 15001 only with ct status dnat
               ▼
             relay_<k> in sandwall, one listener per sandbox
               1. original destination from SO_ORIGINAL_DST
               2. name from the TLS SNI or HTTP Host (peeked), else the DNS cache, else the IP
               3. the name must match the allowlist and map to that IP, else deny sni_mismatch
               4. dial the upstream proxy (host traffic) and send CONNECT <name>:<port>
               5. on 200, replay the peeked bytes and splice; otherwise reset the sandbox
                  connection and log proxy_refused or proxy_error
```

### Policy moves from forward to prerouting
`redirect` happens in prerouting and turns the packet into INPUT traffic, so a policy chain on the forward hook never sees proxied flows.
`sb_<k>` is therefore jumped from a prerouting filter chain for every sandbox, proxied or not, keeping one code path.
As built, the base `prerouting` chain (priority -150, after conntrack and before dstnat) first accepts host-bound traffic (`fib daddr type { local, broadcast, multicast }`), leaving it to input and `sbin_<k>` so `host_access` behaves as before, then dispatches through `pre_vmap`, then drops unknown `veth-h*` interfaces.
`fwd_vmap` is gone; the forward chain only admits replies into sandboxes. Applying the new base ruleset deletes a `fwd_vmap` left by an older daemon.

`conn_reject` needs `reject` in prerouting. Linux 5.10 already allows it: `nft_reject_validate` accepts `NF_INET_PRE_ROUTING`, and `nf_reject_ipv4` looks up the route for resets and ICMP sent from prerouting.
The M2 connection-limit tests pass unchanged with the chain moved.

### REDIRECT, not TPROXY
REDIRECT gives the relay the original destination through `SO_ORIGINAL_DST`, and needs neither policy routing nor `IP_TRANSPARENT` sockets.
The conntrack entry keeps the original tuple, sandbox to destination, so flow attribution by source address and the byte counts of the sandbox leg work unchanged.
The relay's own connection to the proxy comes from the host address and is never attributed to a sandbox.

### One relay listener per sandbox
Each sandbox gets a relay on `10.200.k.1:15001`, next to its DNS proxy.
The listening address identifies the sandbox, as it does for DNS, so attribution never depends on looking up an IP.
The `ct status dnat` match in `sbin_<k>` stops a sandbox from connecting to its relay, or another sandbox's, directly.

### CONNECT by name, checked against the allowlist
The relay sends `CONNECT pypi.org:443`, not `CONNECT 151.101.0.223:443`.
Proxies often refuse IP CONNECTs, apply their own policy and logging by name, and may be the only component that can resolve external names.
The name comes from the TLS SNI or HTTP `Host` and must be allowlisted; otherwise the connection is refused (`sni_mismatch`, or `host_mismatch` with a 403 for HTTP), unless the original destination is inside `allow_cidrs`, in which case the address itself is the CONNECT target.
The design also required the name to resolve, in this sandbox's DNS cache, to the original destination. That was dropped: the proxy resolves the name itself and never uses the original address, so the binding added nothing once the name is checked.
A client that sends no SNI or Host (or a server-first protocol, after 1s of silence) gets the name the sandbox last resolved for the address, else the address, which the firewall already admitted.
The ClientHello is parsed by `crypto/tls` (a server handshake aborted from `GetConfigForClient`), so hellos split across records or segments are read as a TLS server would read them; bytes that start like TLS but hold no parsable ClientHello are refused (`bad_client_hello`). The consumed bytes are replayed into the tunnel.
This also closes a gap that direct mode has today: an IP learned for one allowlisted name on a shared CDN admits any SNI to that IP.
The same relay enforces the SNI check (S1) in direct mode; see below.

### The proxy stays out of the sandbox's reach
The proxy's address stays subject to `blocked_range` for sandbox traffic; only the sandwall process talks to it.
Proxy credentials (`Proxy-Authorization`) stay on the host.

### Plain HTTP, other ports, UDP
- Proxies commonly allow CONNECT only to port 443. For port 80 the relay parses HTTP/1.1 and forwards each request in absolute form (`GET http://host/path`), checking `Host` on every request of a keep-alive connection.
- Other TCP ports use CONNECT; a refusal is logged as `proxy_refused`.
- An HTTP proxy cannot carry UDP. Allowed UDP from a proxied sandbox is rejected with `icmpx admin-prohibited` and logged as `no_proxy_route`, so HTTP/3 clients fall back to TCP at once instead of timing out.

### `no_proxy`
Destinations matching `no_proxy` go out directly through the existing masquerade path, whatever the protocol.
The policy is applied first, so `no_proxy` only changes the route of traffic that is already allowed.

- Addresses and CIDRs go into a global set `direct_cidrs`, since `no_proxy` is a daemon setting.
- For an allowlisted name that also matches `no_proxy`, the DNS proxy inserts its answers into a per-sandbox set `direct_<k>` as well as `allow_<k>`, in one transaction and with the same timeout. A policy reload repopulates `direct_<k>` from the DNS cache like `allow_<k>`, keeping only names that are still allowlisted.
- `sb_<k>` accepts anything allowed whose destination is in either set before the TCP-only rules, and a per-sandbox nat chain `sbnat_<k>` (dispatched from `proxy_redirect` through `nat_vmap`) returns early for those destinations instead of redirecting. The redirect needs a per-sandbox chain because `direct_<k>` is per sandbox.

Matching follows Go's `net/http` proxy rules: `example.com` matches the name and its subdomains, `.example.com` or `*.example.com` only subdomains.
Unlike allowlist patterns, single-label suffixes such as `.corp` are accepted, because a `no_proxy` entry cannot widen access.
Ports are ignored (`host:8080` applies to every port, which only widens the entry), IPv6 and unparsable entries are skipped with a warning, and a lone `*` is an error, as it would turn the proxy off.

Like the allow set, the direct set is keyed by address: once a `no_proxy` name resolves to an address, every allowed connection to that address goes direct, including other allowlisted names served from it (and so without the relay's SNI/Host check).

A restarted daemon keeps the DNS-learned `direct_<k>` entries, as it keeps `allow_<k>`, so clients with cached answers keep their direct route.
If `no_proxy` changed since the previous run (the effective list is stored in the state directory as `no-proxy.json`), restore empties `direct_<k>` instead, so a removed entry cannot keep sending traffic direct until its timeout.

### DNS
Where the site resolver answers external names, nothing changes: the DNS proxy's upstream queries are host traffic.
Where it resolves only internal names, a later `synthetic` DNS mode (not implemented yet) would answer allowlisted names with addresses from a per-sandbox pool, and the relay would map them back to names; the proxy does the real resolution.
DNS still never carries a query for a name that is not allowlisted.

### Configuration
The proxy is a property of the host network, so it is configured on the daemon, not in sandbox policies:
`--upstream-proxy http://[user:pass@]proxy.example:3128` with `--no-proxy <list>`, or `--upstream-proxy-from-env` to read `https_proxy` (else `http_proxy`) and `no_proxy`.
Only `http://` proxies are supported. The mode applies to every sandbox of the daemon; restarting the daemon with or without it re-renders every sandbox accordingly.

### Relayed connections end with the daemon
Forwarded flows live in the kernel and survive a daemon restart; relayed connections are terminated in the sandwall process and do not.
New connections work again as soon as the restarted daemon has rebound its relays.

### Limits and observability
- tc shaping on the veth, `ct count` and the new-connection rate all act on the sandbox leg, unchanged.
- The relay also caps concurrent proxied connections at `max_conns`.
- A new `proxy` log event records `src_port`, `dst_ip`, `dst_port`, `name`, `sni`, `status` and `connect_ms`; `flow` events are unchanged.
- New metric `sandwall_proxy_connects_total{result}`.
- VM mode needs no changes: guest traffic is already masqueraded to `10.200.k.2` inside its netns.

### Testing
`test/e2e/proxy.sh` runs a fake upstream proxy (`proxy.py`) in the `egattacker` netns that logs every request line.
It checks that allowlisted HTTP arrives in absolute form and TLS as `CONNECT <name>:<port>`, both with sandwall's credentials and never the sandbox's; that a non-allowlisted SNI or Host to an allowed address is refused and never reaches the proxy; that a sandbox using the proxy address as its own proxy only reaches the relay; that a proxy refusal is logged with its status; that the relay port, UDP, blocked and non-allowlisted destinations behave as designed; that a reload applies to new connections; and that the relay comes back after a daemon restart.
With `REAL_PROXY` set it also fetches `https://pypi.org` through a real site proxy, on a host with no direct egress.
Two more daemon runs check `no_proxy` by address and by name: the fetch reaches the origin without the proxy or the relay seeing it, allowed UDP is not rejected, and the direct set survives a restart with the same `no_proxy` but is reset when it changes.
In the test the proxy shares the attacker address, which the test exempts from the blocked ranges; a real proxy on a private address stays blocked for sandboxes.

## S1: SNI/Host check

### The upstream-proxy relay, dialing directly
The original design called for a TPROXY peek proxy on ports 443 and 80.
The relay built for the upstream proxy already does the peeking (TLS ClientHello via `crypto/tls`, HTTP `Host` per request) and the allowlist decision, so S1 reuses it.
Without a proxy, the relay connects to the original destination itself instead of sending a CONNECT, and splices the connection.
It uses REDIRECT rather than TPROXY, for the reasons given under "REDIRECT, not TPROXY" above.

`sbnat_<k>` redirects allowed TCP to ports 80 and 443 to the relay; `relay_redirect` (renamed from `proxy_redirect`, which the base ruleset deletes) dispatches to it whenever the relay is on.
The `proxy` log event and `sandwall_proxy_connects_total` became `relay` and `sandwall_relay_connections_total`, since they now describe both modes.

### On by default
`daemon --sni-check` defaults to on, because the shared-CDN gap it closes is the most practical way around a domain allowlist.
`--sni-check=false` restores plain forwarding.
Costs: connections on ports 80 and 443 pass through a user-space splice, and they end when the daemon stops, while forwarded flows survive a restart.
A destination that refuses the relay's connection shows up to the sandbox as an accepted connection that is then reset, logged as `dial_error`.

### Decision rules
Unchanged from proxy mode: an allowlisted SNI or Host passes; one that is not allowlisted is refused unless the original destination is inside `allow_cidrs`; a connection with no name (no SNI, an IP literal, a non-HTTP, non-TLS protocol) passes, since the firewall already admitted the address.
The relay's outbound connection comes from the host, not from `10.200.k.2`; flow logs still come from the sandbox leg, whose conntrack entry keeps the original destination.

### QUIC
QUIC carries its server name in an encrypted Initial packet, so the relay cannot check it.
With the SNI check on, UDP 443 to a DNS-learned address (not one inside `allow_cidrs`) is rejected with `icmpx admin-prohibited` and logged as `quic_blocked`; HTTP/3 clients fall back to TCP.
Measured with curl 8.22 `--http3` against pypi.org: the reject reaches curl as `EHOSTUNREACH` and it falls back to HTTP/2 at once, adding about 0.01s.
When the kernel's per-destination ICMP rate limit swallows the reject, curl's 200ms happy-eyeballs timer starts TCP instead, adding about 0.2s.

### What it does not cover
Ports other than 80 and 443 are forwarded unchecked; behind an upstream proxy every port goes through the relay.
`no_proxy` destinations bypass the relay.
The HTTP `Host` inside TLS is not visible without TLS interception, so domain fronting through an allowlisted SNI remains possible.

### Testing
`test/e2e/s1.sh` runs an HTTP endpoint on port 80 and a TCP hold server on 443 in the attacker netns.
It checks allowed and refused Host and SNI, that flows are still logged on the sandbox leg, that QUIC to a DNS-learned address is rejected while other UDP is not, that other TCP ports are neither checked nor relayed, that the relay port is not reachable directly, and that `--sni-check=false` removes the redirect.

`test/e2e/s1-real.sh` (`make e2e-s1-real`, needs direct internet, so not part of `make e2e`) checks the same against real sites on a shared CDN.
pypi.org and files.pythonhosted.org are allowlisted; both are served from Fastly, whose addresses also serve www.python.org.
It checks TLS 1.3 and HTTP/2 through the relay, and a 55 MiB wheel download verified against PyPI's sha256 (about 4.8s).
It checks that `curl --resolve www.python.org:443:<pypi.org's address>` works outside the sandbox but is refused inside as `sni_mismatch`, and that a fronted plain-HTTP `Host` gets 403 as `host_mismatch`.
It checks that `curl --http3` falls back to HTTP/2 after a `quic_blocked` reject, and that `pip install requests rich numpy` succeeds into a venv in the sandbox.
The QUIC checks need a curl with HTTP/3 (`HTTP3_CURL=/path`; distro builds usually lack it) and are reported as skipped otherwise.
pip reuses its connections, so the install went through only two relayed TLS connections, one per name; there were no relay refusals.

### Relay cost
`test/e2e/relay-cost.sh` (`make e2e-relay-cost`, a benchmark, not part of `make e2e`) compares the SNI check with `--sni-check=false`.
It downloads from a local HTTPS server (`openssl s_server` behind `bench.attacker.test`) so internet variance does not hide the relay, and from files.pythonhosted.org for comparison.
Medians on the 10-CPU Lima VM (nested virtualization), two runs:

| | TLS handshake | First byte | Local 512 MiB | Real 55 MiB |
|---|---|---|---|---|
| relay | 2.5 ms | 2.7 ms | 8.2 to 8.5 Gbit/s | 96 Mbit/s |
| `--sni-check=false` | 2.1 ms | 2.2 ms | 9.9 Gbit/s | 91 to 96 Mbit/s |
| relay, 200 Mbit cap | 2.6 ms | 2.8 ms | 191 Mbit/s | |
| `--sni-check=false`, 200 Mbit cap | 2.1 ms | 2.2 ms | 191 Mbit/s | |

The relay adds 0.3 to 0.5 ms to a TLS handshake and keeps 83 to 86% of uncapped loopback-speed throughput.
Once a `max_ingress_bw` cap or the internet path is the bottleneck, it costs nothing measurable.
Handshake and first-byte times are counted from the end of DNS.
A DNS lookup through the sandbox's proxy took about 15 ms in both modes, far more than the relay adds; see TODO.md.
The test asserts the relay sustains over 1 Gbit/s uncapped, adds under 5 ms to the handshake, and that both modes reach 85 to 105% of the cap.

## Quarantine

### Why
Detection alone does not stop an agent that is already exfiltrating.
`policy apply` deliberately keeps established flows (M1 checks that an in-flight download survives a reload), so tightening a policy cannot cut a tunnel that is already open, and `sandbox destroy` cuts it but throws away the sandbox.
`sandbox quarantine` is the kill switch that keeps the evidence; automatic triggers are tracked in TODO.md.

### Firewall
A quarantined sandbox's `sb_<k>` is a single logged drop (`quarantined`) that comes before the `established` rule, so open flows stop in both directions at the next packet.
Its `sbin_<k>` admits only DNS to its own proxy, so attempted lookups are still answered (REFUSED) and logged; the relay port is not admitted.
Replies on forwarded flows would still reach the sandbox through the forward chain's `established` rule, so the base forward chain first drops anything leaving through an interface in the global set `quarantined`.
`allow_<k>` and `direct_<k>` are emptied; the policy itself is kept, and `policy apply` during a quarantine stores and renders the new policy behind the quarantine.

### Conntrack entries are deleted
Dropping packets alone would leave the conntrack entries of cut flows in place (established TCP times out after five days by default), and a release would let them continue as established.
Quarantine therefore deletes every entry whose original source is the sandbox's address.
The flow collector logs each one from its DESTROY event, so the log shows exactly how much every cut flow had moved.

### DNS proxy and relay
The DNS proxy refuses every query before the allowlist and rate limiter, without forwarding, and logs each refusal: during an incident, every attempted name is evidence.
The relay resets all of its connections and refuses new ones.
On release the proxy forgets every address it learned, and the allow sets start empty, so nothing learned before the quarantine is reachable until it is resolved again.

### Freeze
`--freeze` pauses a VM through the Firecracker API, or SIGSTOPs every process in an exec sandbox's netns.
SIGSTOP is repeated until a pass finds no new process, to catch forks during the first pass.
An exec sandbox has no cgroup of its own, so SIGSTOP is the available freezer; another process running as `nobody` on the host could send SIGCONT, but a stopped process cannot reach the network while the quarantine holds.
`vm snapshot` of a frozen VM leaves it paused, so a memory image can be taken for analysis without letting the guest run.

### Persistence
The quarantine (time, reason, frozen) is stored in the sandbox record, so a restarted daemon re-applies it before the sandbox's DNS proxy starts, and a VM restarted from its source is paused again if it was frozen.

### Testing
`test/e2e/quarantine.sh` cuts a forwarded and a relayed download in flight (the sandbox has a 2 Mbit ingress cap, so data is still on the wire when the cut happens; with only a client-side `--limit-rate`, a local endpoint fills the client's socket buffer within the first two seconds), and checks the logged flow bytes, refused and unforwarded DNS, dropped TCP and UDP, quarantine across `policy apply` and a daemon restart, freezing, release, and destroy while frozen.
M3 checks that a quarantined guest is cut off and that `--freeze` pauses and `release` resumes the VM.

### Automatic quarantine
Triggers live in the sandbox policy, not in daemon flags: what is suspicious depends on the workload, and `policy apply` changes them like any other part of the policy.
They are opt-in, because a quarantine stops the sandbox's work and an unexpected one is an outage.

The daemon's event sink passes every event written to a sandbox log to a watchdog, which maps it to a trigger reason (firewall deny reasons, relay refusals, and `dns_refused` / `dns_ratelimited` for DNS) and keeps, per trigger, the times of the last `count` matching events.
When `count` of them fall within `window`, the trigger fires once and calls the same `Quarantine` as the CLI, with a reason naming the trigger and the last event.
The watchdog is disarmed while the sandbox is quarantined and re-armed with empty counts on release or policy apply.

Counting logged events rather than packets is deliberate.
The deny log already collapses identical drops to one per second, so a single blocked connection's retransmits count once, and a trigger counts attempts.
`count` is capped at 10000 and `window` at 24h, so a policy cannot make the daemon keep unbounded history; events of a quarantined sandbox, its own `quarantined` drops and DNS refusals, never count.
The policy accepts only reasons something produces; a unit test keeps that list in step with the firewall, relay and DNS constants.
A daemon restart resets the counts, which only delays a trigger.

## Allowlist lint: wildcards over shared hosting

### What counts as multi-tenant
A wildcard `*.X` is multi-tenant when `X` is a public suffix, or when a public suffix lies below `X` (`*.amazonaws.com` covers `s3.amazonaws.com`), according to the Public Suffix List, ICANN and private sections.
The private section is maintained by the platforms themselves to say exactly this: names below the suffix belong to different, unrelated parties.
A wildcard below a tenant (`*.my-app.vercel.app`) and exact names are not flagged.
The policy's existing rule that a wildcard must cover at least a second-level domain already stops `*.com`; the list also stops `*.co.uk`.

### Reject with acknowledgement, not warn
A warning in a daemon log is easy to miss, and the cost of the mistake is an exfiltration path, so `sandbox create`, `vm clone` and `policy apply` reject an unacknowledged multi-tenant wildcard.
The acknowledgement lives in the policy (`egress.allow_multitenant`, which must repeat an `allow_domains` entry and allows nothing by itself), not in a CLI flag, so it is reviewed and stored with the policy and survives restarts.

### Lint is separate from parsing
`policy.Parse` stays structural; `Lint` is applied only to newly submitted policies.
A daemon restoring a sandbox whose stored policy fails the lint, for instance after a list update adds a suffix, logs a warning and restores it, rather than leaving a running sandbox unmanaged.

### The list is embedded
`golang.org/x/net/publicsuffix` can tell whether a name is a suffix but cannot list the suffixes below a name, which `*.amazonaws.com` needs, so the list file is embedded (`internal/policy/psl`, about 330 KB) and parsed once on first use.
It is MPL-2.0, kept unmodified with its license header; `make psl-update` refreshes it.
Lint errors name the list version.

### Not covered
Exact names that serve many users' content (`raw.githubusercontent.com`, `gist.github.com`) are single names to the lint; the README lists them as a known gap.
The project's own demo policy used `*.githubusercontent.com` and failed the lint; it now lists exact names.

## S2: policy-violation webhooks

### Endpoints on the daemon, selection in the policy
Webhook URLs and signing keys are daemon flags (`--webhook name=URL`, `--webhook-secret name=file`); policies refer to endpoints by name.
Policies are stored in the state directory and returned by `sandbox list --json`, so they are the wrong place for credentials, and an operator who may change a policy should not be able to point alerts at an arbitrary URL.
A policy naming an endpoint the daemon lacks is rejected at create and apply; at restore it is a warning, like the allowlist lint.

### What is sent
The same vocabulary as quarantine triggers (firewall denies, relay refusals, `dns_refused`, `dns_ratelimited`), plus `quarantine` for quarantine and release events; by default all of them.
Events are the log's own JSON objects, so a receiver sees exactly what `sandwall logs` shows, and they pass through the same de-duplication.

### Delivery
The event sink calls the dispatcher for every logged event, on the data path of the deny collector, DNS proxy and relay, so `Observe` never blocks: each endpoint has a 1000-event queue, overflow is counted (`dropped` result) and reported in the next payload.
One goroutine per endpoint batches up to 100 events or 2 seconds, and flushes at once on a quarantine event, which is the one an operator must see immediately.
A delivery is tried three times (1 s, then 2 s apart); after that it is counted as an error and dropped, as the events remain in the sandbox log.
On daemon stop, queued events get up to 10 seconds to go out.

### Signing
`X-Sandwall-Signature: sha256=HMAC(key, "<X-Sandwall-Timestamp>.<body>")`, the scheme common webhook providers use, so a receiver can authenticate the sender and reject replays by timestamp.
Keys come from files so they stay out of process listings; shorter than 16 bytes is rejected.
Endpoints without a key are allowed (for local receivers) and are simply unsigned.

### Proxy
On a host behind an HTTP proxy, the daemon itself cannot reach external receivers directly either, so webhooks use the upstream proxy when one is configured, except to loopback addresses and `no_proxy` destinations.

### Testing
`test/e2e/alerts.sh` runs a receiver on host loopback that verifies every signature, and checks delivery, reason and sandbox filtering, the immediate quarantine flush, release events, retries after two failures, an unreachable receiver counted as an error, and rejection of a policy naming an unknown endpoint.
It passes with and without an upstream proxy.

## S3: OpenTelemetry log export

### Official SDK over OTLP/HTTP
Events are exported with the OpenTelemetry Go SDK's log provider and its OTLP/HTTP exporter (protobuf, gzip), rather than a hand-written encoder: the SDK brings batching, retries, and the standard `OTEL_EXPORTER_OTLP_*` configuration (headers, TLS, timeouts) that collector operators expect.
OTLP/HTTP rather than gRPC, because it goes through HTTP proxies like the daemon's other requests.
Cost: the binary grows by about 5 MB (23 to 28 MB), partly because the OTLP protobuf package the HTTP exporter needs also carries the generated gRPC service definitions, so gRPC is linked in even though it is never used.

### What a record looks like
The event type becomes the record's event name (`sandwall.deny`, ...), its time the record time, and its fields attributes.
Fields with an OpenTelemetry semantic convention use it (`destination.address`, `destination.port`, `network.transport`, `dns.question.name`, `tls.client.server_name`, `source.port`); the rest are namespaced `sandwall.*`, so they cannot collide with conventions added later.
Severity: `INFO` for allowed events, `WARN` for denials and refusals, `ERROR` for a quarantine.
The body is a one-line summary for log viewers that show only bodies.

### Selection and back-pressure
`--otlp-events all` (default) exports every event, as the JSONL log has them; `violations` uses the alert vocabulary.
The event sink calls the exporter on the data path, and the SDK's batch processor drops records rather than block when its queue is full; the JSONL log stays the record of truth.
On shutdown the provider gets 10 seconds to export what is queued.

### Testing
`test/e2e/otel.sh` runs `test/e2e/otlpsink`, a small Go OTLP/HTTP receiver that decodes the protobuf, and checks DNS, flow, deny, refusal and quarantine records with their attributes, severities, resource and headers, `--otlp-events violations`, the flush at shutdown, and that an unreachable collector does not affect sandboxes.

## Name

The project was developed as `egressd` and renamed to `sandwall` before its first release.
An earlier, unrelated project, castai/egressd (Kubernetes-aware network traffic monitoring, archived in 2026), works in the same space of Linux egress traffic, conntrack and Prometheus metrics under that name.
Everything was renamed at once without compatibility shims: binary, Go module, nftables tables (`inet sandwall`, `ip sandwall_vm`), log prefixes, metrics (`sandwall_*`), jail ids, and the default state, log, socket and asset paths.
A host that ran the old binary needs one `egressd nuke` before switching, since `sandwall nuke` does not know the old names.
