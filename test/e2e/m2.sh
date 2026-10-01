#!/usr/bin/env bash
# M2 acceptance: limits and observability.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
trap 'pkill -f "iperf3 -s -B $ATTACKER_IP" 2>/dev/null; finish' EXIT

P="$E2E_DIR/policies"
A="$ATTACKER_IP"

log "setup"
egressd nuke >/dev/null
setup_attacker || exit 1
start_iperf 5201 5202 5203
start_daemon || exit 1
expect_ok "create t1 (10mbit up / 20mbit down)" egressd sandbox create t1 --policy "$P/m2-shaped.yaml"
expect_ok "create t2 (200mbit)" egressd sandbox create t2 --policy "$P/m2-fast.yaml"
expect_ok "create t3 (max_conns 64)" egressd sandbox create t3 --policy "$P/m2-conns.yaml"
expect_ok "veth-h1 ingress redirected to eg-ifb1" bash -c "tc filter show dev veth-h1 ingress | grep -q 'Egress Redirect to device eg-ifb1'"
expect_ok "tbf 10Mbit on eg-ifb1" bash -c "tc qdisc show dev eg-ifb1 | grep -q 'tbf.*rate 10Mbit'"
expect_ok "tbf 20Mbit on veth-h1" bash -c "tc qdisc show dev veth-h1 | grep -q 'tbf.*rate 20Mbit'"

log "bandwidth: sandbox -> world"
sbx t1 iperf3 -c "$A" -p 5201 -t 8 -O 2 -J >"$T/t1-up.json" 2>&1
t1_up=$(mbps "$T/t1-up.json")
if ((t1_up <= 11)); then pass "t1 upload ${t1_up} Mbit/s <= 11"; else fail "t1 upload ${t1_up} Mbit/s > 11"; fi
if ((t1_up >= 9)); then pass "t1 upload ${t1_up} Mbit/s >= 9 (TCP reaches the cap)"; else fail "t1 upload only ${t1_up} Mbit/s"; fi

sbx t2 iperf3 -c "$A" -p 5202 -t 8 -O 2 -J >"$T/t2-alone.json" 2>&1
t2_alone=$(mbps "$T/t2-alone.json")
if ((t2_alone >= 150 && t2_alone <= 210)); then pass "t2 alone ${t2_alone} Mbit/s near its 200mbit cap"; else fail "t2 alone ${t2_alone} Mbit/s (cap 200)"; fi
sbx t1 iperf3 -c "$A" -p 5201 -t 8 -O 2 -J >"$T/t1-conc.json" 2>&1 &
T1PID=$!
sbx t2 iperf3 -c "$A" -p 5202 -t 8 -O 2 -J >"$T/t2-conc.json" 2>&1
wait "$T1PID"
t2_conc=$(mbps "$T/t2-conc.json")
t1_conc=$(mbps "$T/t1-conc.json")
if ((t2_conc * 100 >= t2_alone * 85)); then
	pass "t2 unaffected by t1: ${t2_conc} Mbit/s concurrent vs ${t2_alone} alone"
else
	fail "t2 slowed by t1: ${t2_conc} Mbit/s concurrent vs ${t2_alone} alone"
fi
if ((t1_conc <= 11)); then pass "t1 still capped while t2 runs (${t1_conc} Mbit/s)"; else fail "t1 ${t1_conc} Mbit/s while t2 runs"; fi

log "bandwidth: world -> sandbox"
sbx t1 iperf3 -c "$A" -p 5203 -t 8 -O 2 -R -J >"$T/t1-down.json" 2>&1
t1_down=$(mbps "$T/t1-down.json")
if ((t1_down <= 22 && t1_down >= 14)); then pass "t1 download ${t1_down} Mbit/s within 20mbit cap"; else fail "t1 download ${t1_down} Mbit/s (cap 20)"; fi

log "connection limits"
out=$(sbx t3 python3 "$SBX_DIR/conns.py" "$A" "$ATTACKER_HOLD_PORT" 200 2 3)
connected=$(jq .connected <<<"$out")
refused=$(jq .refused <<<"$out")
expect_eq "t3 got exactly max_conns connections" "$connected" 64
expect_eq "remaining 136 rejected" "$refused" 136
wait_log t3 "conn_limit rejects logged" ".type==\"deny\" and .reason==\"conn_limit\" and .dst_ip==\"$A\" and .dst_port==$ATTACKER_HOLD_PORT"
# t3 sits at its limit for a while; t1 must be unaffected.
wait_closed 10.200.3.2 "$ATTACKER_HOLD_PORT"
sbx t3 python3 "$SBX_DIR/conns.py" "$A" "$ATTACKER_HOLD_PORT" 100 2 6 >"$T/t3-hold.json" &
HOLD=$!
sleep 2
out=$(sbx t1 python3 "$SBX_DIR/conns.py" "$A" "$ATTACKER_HOLD_PORT" 20 2)
expect_eq "t1 connects normally while t3 is at its limit" "$(jq .connected <<<"$out")" 20
wait "$HOLD"
held=$(jq .connected "$T/t3-hold.json")
if ((held >= 1 && held <= 64)); then pass "t3 never exceeded max_conns ($held held)"; else fail "t3 held $held connections"; fi
# nf_conncount prunes closed and rejected entries lazily, so right after a
# burst the limit is temporarily stricter (see DECISIONS.md). It must
# recover to the full 64 within a few seconds of further attempts.
wait_closed 10.200.3.2 "$ATTACKER_HOLD_PORT"
recovered=0
for try in $(seq 10); do
	out=$(sbx t3 python3 "$SBX_DIR/conns.py" "$A" "$ATTACKER_HOLD_PORT" 64 2)
	wait_closed 10.200.3.2 "$ATTACKER_HOLD_PORT"
	if [[ "$(jq .connected <<<"$out")" == 64 ]]; then recovered=$try; break; fi
	sleep 1
done
if ((recovered > 0)); then pass "t3 recovers the full 64 connections (attempt $recovered)"; else fail "t3 never recovered 64 connections: $out"; fi

log "new-connection rate limit"
expect_ok "reload t3 to 5 new conns/s" egressd policy apply t3 "$P/m2-rate.yaml"
out=$(sbx t3 python3 "$SBX_DIR/conns.py" "$A" "$ATTACKER_HOLD_PORT" 40 0.3)
connected=$(jq .connected <<<"$out")
if ((connected < 40)); then pass "burst of 40 new conns throttled ($connected connected within 0.3s each)"; else fail "no throttling: $out"; fi
wait_log t3 "rate_limit drops logged" '.type=="deny" and .reason=="rate_limit"'

log "flow log"
code=$(sbx t1 curl -sS -m 30 -o /dev/null -w '%{http_code}' "http://attacker.test:$ATTACKER_PORT/bytes/10485760")
expect_eq "10 MB download via allowlisted domain" "$code" 200
wait_log t1 "flow logged with dst_domain" ".type==\"flow\" and .dst_domain==\"attacker.test\" and .dst_port==$ATTACKER_PORT and .bytes_in > 10000000"
flow=$(jq -c "select(.type==\"flow\" and .dst_domain==\"attacker.test\" and .bytes_in > 10000000)" "$LOGS/t1.jsonl" | tail -n1)
bytes_in=$(jq .bytes_in <<<"$flow")
if ((bytes_in >= 10485760 * 95 / 100 && bytes_in <= 10485760 * 105 / 100)); then
	pass "flow bytes_in $bytes_in within 5% of 10485760"
else
	fail "flow bytes_in $bytes_in not within 5% of 10485760"
fi
expect_ok "flow has ts_start <= ts_end" jq -e '.ts_start != null and .ts_start <= .ts_end' <<<"$flow"
expect_eq "flow verdict" "$(jq -r .verdict <<<"$flow")" allow
expect_eq "flow proto" "$(jq -r .proto <<<"$flow")" tcp
expect_eq "flow sandbox" "$(jq -r .sandbox_id <<<"$flow")" t1
expect_eq "t1's flow not in t2's log" "$(jq -c 'select(.type=="flow" and .dst_domain=="attacker.test")' "$LOGS/t2.jsonl" | wc -l)" 0
expect_eq "no flow lines for DNS to the proxy" "$(jq -c 'select(.type=="flow" and (.dst_ip|startswith("10.200.")))' "$LOGS/t1.jsonl" | wc -l)" 0

log "metrics"
sbx t1 curl -sS -m 3 http://169.254.169.254/ >/dev/null 2>&1
sleep 1
for series in \
	'egressd_flows_total sandbox="t1".*verdict="allow"' \
	'egressd_flows_total sandbox="t1".*verdict="deny"' \
	'egressd_bytes_total direction="in".*sandbox="t1"' \
	'egressd_bytes_total direction="out".*sandbox="t1"' \
	'egressd_dns_queries_total sandbox="t1".*verdict="allow"' \
	'egressd_denied_total reason="blocked_range".*sandbox="t1"' \
	'egressd_denied_total reason="conn_limit".*sandbox="t3"' \
	'egressd_denied_total reason="rate_limit".*sandbox="t3"'; do
	read -r name labels <<<"$series"
	v=$(metric "$name" "$labels")
	if [[ -n "$v" && "$v" != "0" ]]; then pass "$name{$labels} = $v"; else fail "$name{$labels} missing"; fi
done
bytes_metric=$(metric egressd_bytes_total 'direction="in".*sandbox="t1"')
if awk -v b="$bytes_metric" 'BEGIN {exit !(b >= 10485760)}'; then pass "bytes_total{in} counts the download"; else fail "bytes_total{in} = $bytes_metric"; fi

log "limits hot reload and teardown"
expect_ok "reload t1 to unlimited" egressd policy apply t1 "$P/m2-unlimited.yaml"
expect_eq "egress redirect removed" "$(tc filter show dev veth-h1 ingress | grep -c redirect)" 0
expect_eq "eg-ifb1 removed" "$(ip -o link show eg-ifb1 2>/dev/null | wc -l)" 0
expect_eq "tbf removed" "$(tc qdisc show dev veth-h1 | grep -c tbf)" 0
expect_ok "destroy t3" egressd sandbox destroy t3
expect_eq "t3 metrics forgotten" "$(curl -s http://127.0.0.1:19464/metrics | grep -c 'sandbox="t3"')" 0
stop_daemon
expect_ok "nuke" egressd nuke
assert_no_remnants
