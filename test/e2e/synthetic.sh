#!/usr/bin/env bash
# Synthetic DNS (--synthetic-dns): behind an upstream proxy on a network
# whose resolver answers internal names only. Allowlisted names are answered
# from a pool without asking the resolver; traffic to pool addresses reaches
# the proxy by name, and the proxy resolves it.
#
# The fake proxy (proxy.py) resolves *.attacker.test to the attacker
# endpoint. The policy's resolver is the attacker's nameserver, which records
# every query it gets, so the test can show it is never asked.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
trap 'pkill -f "proxy.py --bind $ATTACKER_IP" 2>/dev/null; finish' EXIT

P="$E2E_DIR/policies"
A="$ATTACKER_IP"
PROXY_PORT=3128
PLOG="$T/proxy.log"
FLAGS=(--upstream-proxy "http://sandwall:secret@$A:$PROXY_PORT" --synthetic-dns)
POOL_RE='^198\.1[89]\.[0-9]+\.[0-9]+$' # the default pool, 198.18.0.0/15

resolver_asked() { grep -c "^dns query: $1\$" "$ATTACKER_LOOT"; }
proxy_lines() { grep -c "$1" "$PLOG"; }

log "setup"
sandwall nuke >/dev/null
setup_attacker || exit 1
: >"$PLOG"
ip netns exec "$ATTACKER_NS" python3 "$E2E_DIR/proxy.py" --bind "$A" --port "$PROXY_PORT" --origin "$A" \
	--log "$PLOG" >"$T/proxy-stderr.log" 2>&1 &
for _ in $(seq 50); do (exec 3<>"/dev/tcp/$A/$PROXY_PORT") 2>/dev/null && break; sleep 0.1; done
expect_fail "--synthetic-dns needs an upstream proxy" sandwall daemon --synthetic-dns --metrics-addr ""
start_daemon "${FLAGS[@]}" || exit 1
expect_ok "create sandbox t1" sandwall sandbox create t1 --policy "$P/proxy.yaml"

log "answers come from the pool"
addr=$(sbx t1 dig +short a.attacker.test)
if [[ "$addr" =~ $POOL_RE ]]; then pass "a.attacker.test -> $addr, a pool address"; else fail "a.attacker.test -> '$addr'"; fi
expect_eq "the same name keeps its address" "$(sbx t1 dig +short a.attacker.test)" "$addr"
other=$(sbx t1 dig +short b.attacker.test)
if [[ "$other" =~ $POOL_RE && "$other" != "$addr" ]]; then pass "another name gets another address ($other)"; else fail "b.attacker.test -> '$other'"; fi
expect_eq "the site resolver was never asked" "$(resolver_asked a.attacker.test)$(resolver_asked b.attacker.test)" 00
wait_log t1 "answer logged as synthetic" \
	".type==\"dns\" and .qname==\"a.attacker.test.\" and .reason==\"synthetic\" and .answers==[\"$addr\"]"
expect_eq "non-allowlisted names are still refused" "$(dns_status t1 evil.test)" REFUSED
expect_eq "no AAAA either" "$(sbx t1 dig +short AAAA a.attacker.test | wc -l)" 0

log "traffic to pool addresses reaches the proxy by name"
expect_eq "curl http://a.attacker.test succeeds" \
	"$(sbx t1 curl -sS -m 10 -o /dev/null -w '%{http_code}' "http://a.attacker.test:$ATTACKER_PORT/")" 200
expect_ok "proxy got the name, not the pool address" grep -q "^GET http://a.attacker.test:$ATTACKER_PORT/ HTTP/1.1 auth=yes" "$PLOG"
wait_log t1 "flow logged with the pool address and the name" \
	".type==\"flow\" and .dst_ip==\"$addr\" and .dst_port==$ATTACKER_PORT and .dst_domain==\"a.attacker.test\""
sbx t1 curl -sk -m 3 "https://a.attacker.test:$ATTACKER_HOLD_PORT/" >/dev/null 2>&1
expect_ok "TLS: proxy got CONNECT by name" grep -q "^CONNECT a.attacker.test:$ATTACKER_HOLD_PORT HTTP/1.1 auth=yes" "$PLOG"
before=$(proxy_lines "^GET http://a.attacker.test:$ATTACKER_PORT/ ")
expect_eq "a request by address (IP literal Host) uses the mapped name" \
	"$(sbx t1 curl -sS -m 10 -o /dev/null -w '%{http_code}' "http://$addr:$ATTACKER_PORT/")" 200
expect_eq "and reaches the proxy as a.attacker.test" "$(proxy_lines "^GET http://a.attacker.test:$ATTACKER_PORT/ ")" $((before + 1))
expect_eq "Host not allowlisted gets 403" \
	"$(sbx t1 curl -sS -m 10 -o /dev/null -w '%{http_code}' -H 'Host: evil.test' "http://a.attacker.test:$ATTACKER_PORT/")" 403
wait_log t1 "host_mismatch logged" '.type=="relay" and .reason=="host_mismatch" and .http_host=="evil.test"'
expect_fail "proxy never saw a pool address" grep -qE "198\.1[89]\." "$PLOG"
udp_not_delivered t1 "UDP to the attacker is not delivered"
sbx t1 bash -c "echo x >/dev/udp/$addr/9999"
wait_log t1 "UDP to a pool address rejected as no_proxy_route" \
	".type==\"deny\" and .proto==\"udp\" and .dst_ip==\"$addr\" and .reason==\"no_proxy_route\""
expect_fail "an address outside the allow set is still dropped" sbx t1 curl -sS -m 3 "http://198.18.250.250:$ATTACKER_PORT/"
wait_log t1 "not_allowed logged" '.type=="deny" and .dst_ip=="198.18.250.250" and .reason=="not_allowed"'

log "no_proxy names are resolved for real"
stop_daemon
start_daemon "${FLAGS[@]}" --no-proxy "direct.attacker.test" || exit 1
expect_eq "direct.attacker.test gets its real address" "$(sbx t1 dig +short direct.attacker.test)" "$A"
expect_eq "from the site resolver" "$(resolver_asked direct.attacker.test)" 1
expect_eq "and is fetched without the proxy" \
	"$(sbx t1 curl -sS -m 10 -o /dev/null -w '%{http_code}' "http://direct.attacker.test:$ATTACKER_PORT/")" 200
expect_fail "proxy never saw direct.attacker.test" grep -q direct.attacker.test "$PLOG"
expect_eq "other names still come from the pool" "$(resolver_asked c.attacker.test)" 0
c=$(sbx t1 dig +short c.attacker.test)
if [[ "$c" =~ $POOL_RE ]]; then pass "c.attacker.test -> $c"; else fail "c.attacker.test -> '$c'"; fi

log "after a daemon restart"
# The DNS cache, pool mappings included, is kept in the state directory, so
# a restarted daemon still knows what its pool addresses stand for.
stop_daemon
DNS_STATE="$STATE/dns/t1.json"
expect_eq "DNS state saved, readable by root only" "$(stat -c %a "$DNS_STATE" 2>/dev/null)" 600
expect_ok "and holds the mapping" jq -e --arg a "$addr" '.entries[] | select(.name=="a.attacker.test" and .addr==$a)' "$DNS_STATE"
start_daemon "${FLAGS[@]}" || exit 1
before=$(proxy_lines "^GET http://a.attacker.test:$ATTACKER_PORT/ ")
flows_before=$(jq -c "select(.type==\"flow\" and .dst_ip==\"$addr\" and .dst_domain==\"a.attacker.test\")" "$LOGS/t1.jsonl" | wc -l)
expect_eq "a request by address alone still works" \
	"$(sbx t1 curl -sS -m 10 -o /dev/null -w '%{http_code}' "http://$addr:$ATTACKER_PORT/")" 200
expect_eq "and reaches the proxy as a.attacker.test" "$(proxy_lines "^GET http://a.attacker.test:$ATTACKER_PORT/ ")" $((before + 1))
expect_eq "the name keeps its address" "$(sbx t1 dig +short a.attacker.test)" "$addr"
for _ in $(seq 50); do
	(($(jq -c "select(.type==\"flow\" and .dst_ip==\"$addr\" and .dst_domain==\"a.attacker.test\")" "$LOGS/t1.jsonl" | wc -l) > flows_before)) && break
	sleep 0.1
done
expect_ok "the new flow is still attributed to the name" \
	test "$(jq -c "select(.type==\"flow\" and .dst_ip==\"$addr\" and .dst_domain==\"a.attacker.test\")" "$LOGS/t1.jsonl" | wc -l)" -gt "$flows_before"

log "after a restart that lost the DNS state"
# The mappings also live in the sandbox's data plane process, which outlives
# the daemon; losing them takes stopping that too.
stop_daemon
kill -9 "$(cat "$STATE/dataplane/1.pid")"
rm -f "$DNS_STATE"
start_daemon "${FLAGS[@]}" || exit 1
for _ in $(seq 50); do [[ -S "$STATE/dataplane/1.sock" ]] && break; sleep 0.1; done
sbx t1 curl -sk -m 3 --resolve "a.attacker.test:$ATTACKER_HOLD_PORT:$addr" "https://a.attacker.test:$ATTACKER_HOLD_PORT/" >/dev/null 2>&1
wait_log t1 "TLS with the name still reaches the proxy by name" \
	".type==\"relay\" and .verdict==\"allow\" and .dst_ip==\"$addr\" and .target==\"a.attacker.test:$ATTACKER_HOLD_PORT\""
expect_eq "a request with no name for an unmapped pool address gets 403" \
	"$(sbx t1 curl -sS -m 10 -o /dev/null -w '%{http_code}' "http://$addr:$ATTACKER_PORT/")" 403
wait_log t1 "logged as synthetic_unmapped" \
	".type==\"relay\" and .reason==\"synthetic_unmapped\" and .dst_ip==\"$addr\""
expect_fail "proxy never saw a pool address" grep -qE "198\.1[89]\." "$PLOG"

log "destroy and nuke"
expect_ok "destroy t1" sandwall sandbox destroy t1
expect_ok "nuke" sandwall nuke
stop_daemon
expect_fail "nuke removed the DNS state" test -e "$STATE/dns"
assert_no_remnants
