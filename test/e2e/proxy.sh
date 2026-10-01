#!/usr/bin/env bash
# Upstream proxy mode: allowed sandbox TCP leaves through an HTTP proxy as a
# next hop. A fake proxy (proxy.py) runs in the attacker netns and resolves
# *.attacker.test to the attacker endpoint. Set REAL_PROXY=http://host:port
# to also fetch real internet sites through a site proxy.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
trap 'pkill -f "proxy.py --bind $ATTACKER_IP" 2>/dev/null; finish' EXIT

P="$E2E_DIR/policies"
A="$ATTACKER_IP"
PROXY_PORT=3128
PLOG="$T/proxy.log"
PROXY_FLAGS=(--upstream-proxy "http://sandwall:secret@$A:$PROXY_PORT")

log "setup"
sandwall nuke >/dev/null
setup_attacker || exit 1
: >"$PLOG"
ip netns exec "$ATTACKER_NS" python3 "$E2E_DIR/proxy.py" --bind "$A" --port "$PROXY_PORT" --origin "$A" \
	--log "$PLOG" >"$T/proxy-stderr.log" 2>&1 &
for _ in $(seq 50); do (exec 3<>"/dev/tcp/$A/$PROXY_PORT") 2>/dev/null && break; sleep 0.1; done
start_daemon "${PROXY_FLAGS[@]}" || exit 1
expect_ok "create sandbox t1" sandwall sandbox create t1 --policy "$P/proxy.yaml"
relay_addr=$(sb_field t1 .host_addr)

log "plain HTTP through the proxy"
expect_eq "curl http://a.attacker.test succeeds" \
	"$(sbx t1 curl -sS -m 10 -o /dev/null -w '%{http_code}' "http://a.attacker.test:$ATTACKER_PORT/")" 200
expect_ok "proxy got an absolute-form request with sandwall's credentials" \
	grep -q "^GET http://a.attacker.test:$ATTACKER_PORT/ HTTP/1.1 auth=yes" "$PLOG"
wait_log t1 "proxy event logged" \
	".type==\"relay\" and .verdict==\"allow\" and .http_host==\"a.attacker.test:$ATTACKER_PORT\" and .proxy_status==200"
wait_log t1 "flow attributed on the sandbox leg" \
	".type==\"flow\" and .dst_ip==\"$A\" and .dst_port==$ATTACKER_PORT and .dst_domain==\"a.attacker.test\""
expect_eq "Host not allowlisted gets 403 from the relay" \
	"$(sbx t1 curl -sS -m 10 -o /dev/null -w '%{http_code}' -H 'Host: evil.test' "http://a.attacker.test:$ATTACKER_PORT/")" 403
wait_log t1 "host_mismatch logged" '.type=="relay" and .reason=="host_mismatch" and .http_host=="evil.test"'
expect_eq "sandbox cannot use the proxy as a proxy" \
	"$(sbx t1 curl -sS -m 10 -o /dev/null -w '%{http_code}' -x "http://$A:$PROXY_PORT" http://evil.test/)" 403

log "TLS through the proxy"
# The hold server never answers TLS; the CONNECT is what is checked.
sbx t1 curl -sk -m 3 "https://a.attacker.test:$ATTACKER_HOLD_PORT/" >/dev/null 2>&1
expect_ok "proxy got CONNECT by name" grep -q "^CONNECT a.attacker.test:$ATTACKER_HOLD_PORT HTTP/1.1 auth=yes" "$PLOG"
wait_log t1 "SNI and target logged" \
	".type==\"relay\" and .verdict==\"allow\" and .sni==\"a.attacker.test\" and .target==\"a.attacker.test:$ATTACKER_HOLD_PORT\""
expect_fail "non-allowlisted SNI to an allowed address fails" \
	sbx t1 curl -sk -m 5 --resolve "evil.test:$ATTACKER_HOLD_PORT:$A" "https://evil.test:$ATTACKER_HOLD_PORT/"
wait_log t1 "sni_mismatch logged" '.type=="relay" and .reason=="sni_mismatch" and .sni=="evil.test"'
expect_fail "proxy never saw evil.test" grep -q evil.test "$PLOG"
expect_fail "proxy refusal reaches the sandbox" sbx t1 curl -sk -m 5 "https://blocked.attacker.test:$ATTACKER_HOLD_PORT/"
wait_log t1 "proxy_refused logged with the proxy's status" '.type=="relay" and .reason=="proxy_refused" and .proxy_status==403'

log "what the proxy does not change"
expect_fail "relay port not reachable directly" sbx t1 curl -sS -m 3 "http://$relay_addr:15001/"
wait_log t1 "direct relay access is host_access" '.type=="deny" and .dst_port==15001 and .reason=="host_access"'
udp_not_delivered t1 "allowed UDP not delivered"
wait_log t1 "allowed UDP rejected as no_proxy_route" \
	".type==\"deny\" and .proto==\"udp\" and .dst_ip==\"$A\" and .reason==\"no_proxy_route\""
expect_fail "non-allowlisted address still dropped" sbx t1 curl -sS -m 3 http://203.0.113.10/
wait_log t1 "not_allowed logged" '.type=="deny" and .dst_ip=="203.0.113.10" and .reason=="not_allowed"'
expect_fail "metadata still blocked" sbx t1 curl -sS -m 3 http://169.254.169.254/
wait_log t1 "blocked_range logged" '.type=="deny" and .dst_ip=="169.254.169.254" and .reason=="blocked_range"'
expect_eq "DNS still refused for other names" "$(dns_status t1 example.com)" REFUSED

log "policy reload"
expect_eq "b.attacker.test resolves before the reload" "$(dns_status t1 b.attacker.test)" NOERROR
expect_ok "reload: allow only b.attacker.test" sandwall policy apply t1 "$P/proxy-reload.yaml"
expect_fail "a.attacker.test now refused by the relay" \
	sbx t1 curl -sk -m 5 --resolve "a.attacker.test:$ATTACKER_HOLD_PORT:$A" "https://a.attacker.test:$ATTACKER_HOLD_PORT/"
wait_log t1 "sni_mismatch after reload" '.type=="relay" and .reason=="sni_mismatch" and .sni=="a.attacker.test"'
expect_eq "b.attacker.test still works" \
	"$(sbx t1 curl -sS -m 10 -o /dev/null -w '%{http_code}' "http://b.attacker.test:$ATTACKER_PORT/")" 200

log "metrics and restart"
expect_ok "relay connections counted" bash -c "curl -s http://127.0.0.1:19464/metrics | grep -q 'sandwall_relay_connections_total{result=\"ok\",sandbox=\"t1\"}'"
stop_daemon
start_daemon "${PROXY_FLAGS[@]}" || exit 1
expect_eq "relay serves again after a daemon restart" \
	"$(sbx t1 curl -sS -m 10 -o /dev/null -w '%{http_code}' "http://b.attacker.test:$ATTACKER_PORT/")" 200

# count_events <sandbox> <jq boolean expr>: matching lines in the sandbox log.
count_events() { jq -c "select($2)" "$LOGS/$1.jsonl" | wc -l; }
k=$(sb_field t1 .index)
direct_set() { nft -j list set inet sandwall "direct_$k" | jq -r '[.nftables[].set.elem // empty | .[] | (.elem.val // .)] | join(" ")'; }

# direct_ok <desc>: b.attacker.test fetched without the proxy or the relay
# seeing it, and allowed UDP delivered.
direct_ok() {
	local plines relayed
	plines=$(wc -l <"$PLOG")
	relayed=$(count_events t1 '.type=="relay"')
	expect_eq "$1: curl succeeds" \
		"$(sbx t1 curl -sS -m 10 -o /dev/null -w '%{http_code}' "http://b.attacker.test:$ATTACKER_PORT/")" 200
	expect_eq "$1: the proxy saw nothing" "$(wc -l <"$PLOG")" "$plines"
	expect_eq "$1: the relay saw nothing" "$(count_events t1 '.type=="relay"')" "$relayed"
	udp_delivered t1 "$1: allowed UDP delivered"
}

log "no_proxy by address"
stop_daemon
start_daemon "${PROXY_FLAGS[@]}" --no-proxy "$A" || exit 1
expect_eq "address is in direct_cidrs" "$(nft -j list set inet sandwall direct_cidrs | jq -r '.nftables[].set.elem // empty | .[]')" "$A"
direct_ok "no_proxy address"

log "no_proxy by name"
stop_daemon
start_daemon "${PROXY_FLAGS[@]}" --no-proxy ".attacker.test" || exit 1
expect_eq "direct_cidrs emptied" "$(nft -j list set inet sandwall direct_cidrs | jq -r '.nftables[].set.elem // empty | .[]')" ""
expect_eq "b.attacker.test resolves" "$(dns_status t1 b.attacker.test)" NOERROR
expect_eq "its address entered direct_$k" "$(direct_set)" "$A"
direct_ok "no_proxy name"
stop_daemon
start_daemon "${PROXY_FLAGS[@]}" --no-proxy ".attacker.test" || exit 1
expect_eq "direct_$k kept across a restart with the same no_proxy" "$(direct_set)" "$A"
stop_daemon
start_daemon "${PROXY_FLAGS[@]}" || exit 1
expect_eq "direct_$k reset when no_proxy changes" "$(direct_set)" ""
plines=$(wc -l <"$PLOG")
expect_eq "without no_proxy, b.attacker.test goes through the proxy again" \
	"$(sbx t1 curl -sS -m 10 -o /dev/null -w '%{http_code}' "http://b.attacker.test:$ATTACKER_PORT/")" 200
expect_eq "the proxy saw it" "$(($(wc -l <"$PLOG") - plines))" 1

if [[ -n "${REAL_PROXY:-}" ]]; then
	log "real internet through the site proxy"
	stop_daemon
	start_daemon --upstream-proxy "$REAL_PROXY" || exit 1
	expect_ok "create sandbox r1" sandwall sandbox create r1 --policy "$P/m1.yaml"
	expect_eq "curl https://pypi.org succeeds" "$(sbx r1 curl -sS -m 20 -o /dev/null -w '%{http_code}' https://pypi.org/)" 200
	wait_log r1 "CONNECT pypi.org:443 logged" '.type=="relay" and .verdict=="allow" and .target=="pypi.org:443" and .proxy_status==200'
	expect_eq "dig example.com is REFUSED" "$(dns_status r1 example.com)" REFUSED
	expect_fail "curl https://example.com fails" sbx r1 curl -sS -m 5 https://example.com/
fi

log "destroy and nuke"
expect_ok "destroy t1" sandwall sandbox destroy t1
expect_ok "nuke" sandwall nuke
stop_daemon
assert_no_remnants
