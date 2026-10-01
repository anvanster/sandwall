#!/usr/bin/env bash
# S1: SNI/Host check without an upstream proxy. Allowed TCP to ports 80 and
# 443 goes through the per-sandbox relay, which checks the TLS SNI or HTTP
# Host against the allowlist and then dials the original destination.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
trap finish EXIT

P="$E2E_DIR/policies"
A="$ATTACKER_IP"
REAL_PROXY="" # this test is about direct mode

log "setup"
egressd nuke >/dev/null
setup_attacker || exit 1
# A second endpoint on the checked ports: HTTP on 80, a TCP hold server on
# 443 (it never answers TLS, so only the relay's decision is checked).
ip netns exec "$ATTACKER_NS" python3 "$E2E_DIR/attacker.py" --bind "$A" --port 80 --hold-port 443 \
	--loot "$T/loot-80.txt" >"$T/attacker-80.log" 2>&1 &
for _ in $(seq 50); do curl -s -m 1 "http://$A/" >/dev/null && break; sleep 0.1; done
start_daemon || exit 1
expect_ok "create sandbox t1" egressd sandbox create t1 --policy "$P/proxy.yaml"
count_events() { jq -c "select($2)" "$LOGS/$1.jsonl" | wc -l; }

log "HTTP Host check"
expect_eq "curl http://a.attacker.test succeeds" "$(sbx t1 curl -sS -m 10 -o /dev/null -w '%{http_code}' http://a.attacker.test/)" 200
wait_log t1 "relay event logged" \
	".type==\"relay\" and .verdict==\"allow\" and .http_host==\"a.attacker.test\" and .target==\"$A:80\" and (.proxy_status|not)"
wait_log t1 "flow still logged on the sandbox leg" \
	".type==\"flow\" and .dst_ip==\"$A\" and .dst_port==80 and .dst_domain==\"a.attacker.test\""
expect_eq "Host not allowlisted gets 403" \
	"$(sbx t1 curl -sS -m 10 -o /dev/null -w '%{http_code}' -H 'Host: evil.test' http://a.attacker.test/)" 403
wait_log t1 "host_mismatch logged" '.type=="relay" and .reason=="host_mismatch" and .http_host=="evil.test"'

log "TLS SNI check"
sbx t1 curl -sk -m 3 https://a.attacker.test/ >/dev/null 2>&1
wait_log t1 "allowlisted SNI relayed to the original destination" \
	".type==\"relay\" and .verdict==\"allow\" and .sni==\"a.attacker.test\" and .target==\"$A:443\""
expect_fail "non-allowlisted SNI to an allowed address fails" \
	sbx t1 curl -sk -m 5 --resolve "evil.test:443:$A" https://evil.test/
wait_log t1 "sni_mismatch logged" '.type=="relay" and .reason=="sni_mismatch" and .sni=="evil.test"'

log "scope of the check"
sbx t1 bash -c "echo x >/dev/udp/$A/443"
wait_log t1 "QUIC to a DNS-learned address rejected" \
	".type==\"deny\" and .proto==\"udp\" and .dst_port==443 and .reason==\"quic_blocked\""
sbx t1 bash -c "echo x >/dev/udp/$A/9999"
sleep 1
expect_eq "other UDP to an allowed address is not rejected" "$(count_events t1 '.type=="deny" and .dst_port==9999')" 0
relayed=$(count_events t1 '.type=="relay"')
expect_eq "other TCP ports are not checked" \
	"$(sbx t1 curl -sS -m 10 -o /dev/null -w '%{http_code}' -H 'Host: evil.test' "http://a.attacker.test:$ATTACKER_PORT/")" 200
expect_eq "and do not go through the relay" "$(count_events t1 '.type=="relay"')" "$relayed"
relay_addr=$(sb_field t1 .host_addr)
expect_fail "relay port not reachable directly" sbx t1 curl -sS -m 3 "http://$relay_addr:15001/"
wait_log t1 "direct relay access is host_access" '.type=="deny" and .dst_port==15001 and .reason=="host_access"'
expect_fail "non-allowlisted address on port 443 still dropped" sbx t1 curl -sk -m 3 https://203.0.113.10/
wait_log t1 "not_allowed logged" '.type=="deny" and .dst_ip=="203.0.113.10" and .reason=="not_allowed"'
expect_ok "relay connections counted" bash -c "curl -s http://127.0.0.1:19464/metrics | grep -q 'egressd_relay_connections_total{result=\"ok\",sandbox=\"t1\"}'"

log "--sni-check=false"
stop_daemon
start_daemon --sni-check=false || exit 1
relayed=$(count_events t1 '.type=="relay"')
expect_eq "Host not allowlisted is forwarded unchecked" \
	"$(sbx t1 curl -sS -m 10 -o /dev/null -w '%{http_code}' -H 'Host: evil.test' http://a.attacker.test/)" 200
expect_eq "no relay involved" "$(count_events t1 '.type=="relay"')" "$relayed"
expect_eq "no redirect rule left" "$(nft list chain inet egressd sbnat_1 | grep -c redirect)" 0

log "destroy and nuke"
expect_ok "destroy t1" egressd sandbox destroy t1
expect_ok "nuke" egressd nuke
stop_daemon
assert_no_remnants
