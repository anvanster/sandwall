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
  Their address hints would point clients at IPs that never entered the allow set, and ECH configs would defeat the planned SNI check (S1).
  Clients fall back to A lookups.
- If inserting into the allow set fails, the client gets SERVFAIL rather than an answer it cannot use.
- Over-limit queries get REFUSED. Their log lines are themselves rate-limited, but metrics count every query.

### Deny log de-duplication
Identical deny events (same sandbox, reason, protocol, destination and port) are logged at most once per second, so retransmits or a flood of dropped packets cannot flood the log.
`egressd_denied_total` still counts every packet.

### Exec mode
`sandbox exec` runs `ip netns exec sb<k> setpriv --reuid=65534 --regid=65534 --clear-groups --inh-caps=-all --bounding-set=-all --no-new-privs -- cmd`.
`ip netns exec` provides the `/etc/netns/sb<k>/resolv.conf` bind mount.
Clearing the bounding set means not even a setuid binary can regain `CAP_NET_ADMIN`.

### Daemon restart and state
Sandbox records are persisted under `--state-dir` (default `/var/lib/egressd/sandboxes/`).
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

### `egressd_flows_total{verdict="deny"}`
Denied traffic never becomes a confirmed conntrack flow, so there is no denied "flow" to count.
This series counts logged deny events, which are de-duplicated per second, as an approximation of denied flow attempts.
`egressd_denied_total{reason}` counts every dropped or rejected packet.

## M3

### VM-mode netns plumbing
Inside a VM-mode netns, egressd owns `table ip egressd_vm`.
Guest DNS to `172.16.0.1:53` is DNATed to `10.200.k.1:53`, and guest traffic leaving `veth-s<k>` is masqueraded to `10.200.k.2`.
From then on the host enforces policy and attributes logs exactly as for exec mode.
Two deviations from the original design:
- **DNS DNAT is limited to destination `172.16.0.1`.** The original design DNATed every port-53 packet. That would silently answer `dig @8.8.8.8` from the proxy, and the host would never see or log the bypass attempt. With the narrower DNAT, the M1 bypass check behaves the same from inside a guest.
- **The forward policy is `drop`.** Only `172.16.0.2` may be forwarded out (no spoofing), and the guest cannot open connections to the netns itself.

The host reaches a guest over SSH from inside its netns (the e2e harness's control channel).
Replies come back through the `established` rule.

### Jail layout and identity
Each VM runs as `jailer --id egressd-sb<k> --netns /var/run/netns/sb<k>`, under uid/gid `100000+k`, in its own chroot under `--chroot-base` (default `/srv/jailer`).
Every jail uses the same names: `vmlinux`, `drive-<id>`, `tap0`, guest MAC `06:00:AC:10:00:02` and guest IP `172.16.0.2`.
So a snapshot from any sandbox restores unchanged in any other.
`--vm-config` is a Firecracker config file without `network-interfaces`, which egressd owns.
egressd rewrites paths to jail-relative names and appends `ipv6.disable=1 ip=172.16.0.2::172.16.0.1:255.255.255.252::eth0:off` to the boot args.

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

### `vm clone --stagger` and nested virtualization
M3 was developed in a Lima VM (vz backend) with nested virtualization on Apple silicon.
There, starting many KVM guests back to back (about 0.6s apart) left most of them with a vCPU spinning in the guest, unresponsive for minutes.
The KVM counters showed constant exits but almost no WFI.
This happened with freshly booted VMs as well as restored clones, and never with one VM, or with starts paced 1s apart (20 of 20 healthy, idle at ~0% CPU).
egressd does not hide a delay for this.
`vm clone --stagger <duration>` is an explicit option, also useful on bare metal to spread out the memory faulting of many clones.
The M3 e2e test uses `--stagger 1s` (override with `CLONE_STAGGER`).
On bare-metal KVM `--stagger 0` is expected to work, but this was not verified here.

The same host limit applies to guests that are busy at the same time, not only to starts.
With 20 clones fetching at once, or 20 simultaneous SSH handshakes into them, on a 10-CPU Lima VM, several guests stalled for minutes.
So the M3 test keeps all 20 clones running simultaneously, but runs their allowlisted fetches concurrently in waves of `FETCH_CONCURRENCY` (default 8).
It checks, from the host's conntrack timestamps, that the fetches within each wave overlapped.
On bare metal, set `FETCH_CONCURRENCY=20` to fetch from all clones at once.
