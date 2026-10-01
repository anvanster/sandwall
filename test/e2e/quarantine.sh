#!/usr/bin/env bash
# Quarantine: cut a sandbox off at once, established and relayed flows
# included, keep it for forensics, survive a restart, freeze and release.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
trap finish EXIT

P="$E2E_DIR/policies"
A="$ATTACKER_IP"
REAL_PROXY="" # only local endpoints are used

log "setup"
egressd nuke >/dev/null
setup_attacker || exit 1
# Port 80 goes through the relay (SNI/Host check); 8080 is forwarded.
ip netns exec "$ATTACKER_NS" python3 "$E2E_DIR/attacker.py" --bind "$A" --port 80 \
	--loot "$T/loot-80.txt" >"$T/attacker-80.log" 2>&1 &
for _ in $(seq 50); do curl -s -m 1 "http://$A/" >/dev/null && break; sleep 0.1; done
start_daemon || exit 1
expect_ok "create sandbox t1" egressd sandbox create t1 --policy "$P/quarantine.yaml"
expect_eq "allowlisted fetch works" "$(sbx t1 curl -sS -m 10 -o /dev/null -w '%{http_code}' "http://a.attacker.test:$ATTACKER_PORT/")" 200
quarantined() { egressd sandbox list --json | jq -r '.[] | select(.id=="t1") | .quarantine != null'; }
metric() { curl -s http://127.0.0.1:19464/metrics | awk -v m="egressd_quarantined{sandbox=\"t1\"}" '$1 == m {print $2}'; }

log "quarantine cuts flows in progress"
# Two downloads sharing the 2 Mbit cap would take 40s; both are cut 2s in.
sbx t1 curl -sS -m 12 -o /dev/null -w '%{size_download}' \
	"http://a.attacker.test:$ATTACKER_PORT/bytes/5000000" >"$T/fwd.txt" 2>/dev/null &
FWD=$!
sbx t1 curl -sS -m 12 -o /dev/null -w '%{size_download}' \
	"http://b.attacker.test/bytes/5000000" >"$T/relayed.txt" 2>/dev/null &
RELAYED=$!
sleep 2
expect_ok "quarantine t1" egressd sandbox quarantine t1 --reason "e2e: suspected exfiltration"
wait "$FWD" "$RELAYED"
fwd=$(<"$T/fwd.txt"); relayed=$(<"$T/relayed.txt")
# Unquarantined, they would share about 3 MB in 12s.
if ((${fwd:-0} < 1200000)); then pass "forwarded download cut (${fwd:-0} bytes)"; else fail "forwarded download kept going (${fwd:-0} bytes)"; fi
if ((${relayed:-0} < 1200000)); then pass "relayed download cut (${relayed:-0} bytes)"; else fail "relayed download kept going (${relayed:-0} bytes)"; fi
wait_log t1 "cut flow logged with its bytes" \
	".type==\"flow\" and .dst_port==$ATTACKER_PORT and .bytes_in > 100000 and .bytes_in < 1500000"
wait_log t1 "quarantine event logged with the reason" \
	'.type=="quarantine" and .verdict=="quarantined" and .reason=="e2e: suspected exfiltration"'
expect_ok "quarantine shows in logs --deny-only" bash -c "\"$EGRESSD\" ${G[*]} logs t1 --deny-only | grep -q '\"type\":\"quarantine\"'"
expect_eq "sandbox list reports it" "$(quarantined)" true
expect_eq "egressd_quarantined is 1" "$(metric)" 1

log "nothing gets through while quarantined"
expect_eq "DNS for an allowlisted name REFUSED" "$(dns_status t1 c.attacker.test)" REFUSED
wait_log t1 "refusal logged as quarantined" '.type=="dns" and .qname=="c.attacker.test." and .reason=="quarantined"'
expect_fail "the query never reached the upstream resolver" grep -q "c.attacker.test" "$ATTACKER_LOOT"
expect_fail "allowed address unreachable by IP" sbx t1 curl -sS -m 3 "http://$A:$ATTACKER_PORT/"
wait_log t1 "drop logged as quarantined" ".type==\"deny\" and .dst_ip==\"$A\" and .reason==\"quarantined\""
udp_not_delivered t1 "UDP to an allowed address not delivered"
expect_ok "policy apply keeps the quarantine" egressd policy apply t1 "$P/quarantine.yaml"
expect_eq "still REFUSED after policy apply" "$(dns_status t1 d.attacker.test)" REFUSED

log "quarantine survives a daemon restart"
stop_daemon
start_daemon || exit 1
expect_eq "still quarantined" "$(quarantined)" true
expect_eq "DNS still REFUSED" "$(dns_status t1 e.attacker.test)" REFUSED
expect_eq "metric restored" "$(metric)" 1

log "freeze"
sbx t1 sleep 300 &
SLEEPER=$!
sleep 1
pid=$(ip netns pids "$(sb_field t1 .netns)" | while read -r p; do [[ "$(cat "/proc/$p/comm" 2>/dev/null)" == sleep ]] && echo "$p"; done | head -1)
expect_ok "quarantine --freeze" egressd sandbox quarantine t1 --freeze
expect_eq "sandbox process stopped" "$(awk '{print $3}' "/proc/$pid/stat")" T
expect_eq "list shows frozen" "$(egressd sandbox list | awk '$1=="t1" {print $4}')" QUARANTINED,frozen
expect_eq "reason kept from the first quarantine" \
	"$(egressd sandbox list --json | jq -r '.[] | select(.id=="t1") | .quarantine.reason')" "e2e: suspected exfiltration"

log "release"
expect_ok "release t1" egressd sandbox release t1
expect_eq "sandbox process running again" "$(awk '{print $3}' "/proc/$pid/stat")" S
kill "$pid" 2>/dev/null; wait "$SLEEPER" 2>/dev/null
expect_eq "no longer quarantined" "$(quarantined)" false
expect_eq "egressd_quarantined is 0" "$(metric)" 0
wait_log t1 "release logged" '.type=="quarantine" and .verdict=="released"'
expect_eq "DNS answers again" "$(dns_status t1 a.attacker.test)" NOERROR
expect_eq "allowlisted fetch works again" "$(sbx t1 curl -sS -m 10 -o /dev/null -w '%{http_code}' "http://a.attacker.test:$ATTACKER_PORT/")" 200
expect_eq "relayed fetch works again" "$(sbx t1 curl -sS -m 10 -o /dev/null -w '%{http_code}' http://a.attacker.test/)" 200
expect_fail "releasing twice is an error" egressd sandbox release t1

log "destroy while quarantined"
expect_ok "quarantine --freeze again" egressd sandbox quarantine t1 --freeze
expect_ok "destroy t1" egressd sandbox destroy t1
expect_ok "nuke" egressd nuke
stop_daemon
assert_no_remnants
expect_eq "no quarantined set entries left" "$(nft list tables | grep -c egressd)" 0
