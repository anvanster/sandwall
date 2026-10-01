# Design decisions and deviations

Deviations from, and clarifications of, the design in PRD §6.
Newest last.

## M1

### Host-local destinations need an INPUT chain (`sbin_<k>`)
Traffic from a sandbox to an address owned by the host (the DNS proxy at `10.200.k.1`, the host's LAN IP, any other local address) never traverses the FORWARD hook, so the per-sandbox `sb_<k>` chain cannot see it.
Each sandbox therefore also gets `sbin_<k>`, hooked from an `input` base chain, which accepts only established traffic and DNS to its own proxy and logs and drops everything else with reason `host_access`.
PRD rule 2 is still rendered into `sb_<k>` for parity, but in practice it is `sbin_<k>` that admits proxy traffic.
This is also what stops sandbox A from querying sandbox B's proxy, which would otherwise let A borrow B's allowlist.

### Dispatch via verdict maps, per-sandbox transactions
The base chains dispatch with `iifname vmap @fwd_vmap` / `@in_vmap` instead of one `jump` rule per sandbox.
Creating, reloading or removing a sandbox is one `nft -f` transaction touching only that sandbox's chains, sets and map entries.
Re-rendering the whole table on every change would wipe the DNS-learned `allow_<k>` sets of every other sandbox.
Rulesets are still generated as text and applied atomically, per PRD principle 5.
Any `veth-h*` interface without a map entry is dropped (`unknown_iface`), so a sandbox is fail-closed while it is being created.

### Idempotent removal without `destroy`
`nft destroy` needs kernel 6.3+, while the PRD floor is 5.10.
Removal scripts first `add` every object (a no-op if it exists) and then `delete` it, all in one transaction, so they succeed from any partial state on any supported kernel.
Refreshing a DNS-learned set element uses the same add/delete/add pattern, because re-adding an existing element does not extend its timeout.

### Blocked ranges
In addition to the PRD list, `240.0.0.0/4` (reserved, includes limited broadcast) is blocked.
The transfer supernet `10.200.0.0/16` is blocked by its own rule, ahead of the blocked-range set, so no exemption can open sandbox-to-sandbox traffic.

### Test endpoint: routed netns instead of a dummy link
PRD §11 suggests an HTTP listener on a dummy interface `egtest0` with `10.99.0.1`.
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
`internal/daemon` is added to the PRD §9 layout.
It owns sandbox lifecycle and is the only package that composes netns, nft, dnsproxy, flowlog and metrics; `internal/api` is only the HTTP transport in front of it.
`internal/addressing` holds the index-to-names/addresses derivation that every package shares.

### Go version
`go.mod` requires Go 1.26 rather than 1.22.
The current `golang.org/x/{net,sys,sync,time}` releases require Go 1.25 to 1.26, and pinning older versions to meet the PRD floor would mean shipping stale security fixes.
