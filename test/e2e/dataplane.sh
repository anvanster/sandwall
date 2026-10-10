#!/usr/bin/env bash
# Data plane processes: each sandbox's DNS proxy and relay run apart from the
# daemon, so relayed connections and DNS outlive a daemon restart or crash.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
trap 'pkill -f "proxy.py --bind $ATTACKER_IP" 2>/dev/null; finish' EXIT

P="$E2E_DIR/policies"
A="$ATTACKER_IP"
REAL_PROXY="" # the proxied part below uses the fake proxy
PROXY_PORT=3128
BIG=8388608 # 8 MiB, fetched at 1 MiB/s: about 8s through the relay
DPDIR="$STATE/dataplane"

dp_pid() { cat "$DPDIR/1.pid" 2>/dev/null; }
# slow_fetch <out file>: a relayed download (port 80 goes through the SNI
# check relay) running in the background; prints "<bytes> <status>".
slow_fetch() {
	sbx t1 curl -sS -m 60 --limit-rate 1M -o /dev/null -w '%{size_download} %{http_code}' \
		"http://a.attacker.test/bytes/$BIG" >"$1" 2>"$1.err" &
	FETCH=$!
}
fetch_done() {
	wait "$FETCH"
	local rc=$?
	expect_eq "$1 (curl exit status)" "$rc" 0
	expect_eq "$1 (all bytes, status 200)" "$(cat "$2")" "$BIG 200"
}

log "setup"
sandwall nuke >/dev/null
setup_attacker || exit 1
# HTTP on port 80, which the SNI check relays.
ip netns exec "$ATTACKER_NS" python3 "$E2E_DIR/attacker.py" --bind "$A" --port 80 \
	--loot "$T/loot-80.txt" >"$T/attacker-80.log" 2>&1 &
for _ in $(seq 50); do curl -s -m 1 "http://$A/" >/dev/null && break; sleep 0.1; done
start_daemon || exit 1
expect_ok "create sandbox t1" sandwall sandbox create t1 --policy "$P/proxy.yaml"
pid=$(dp_pid)
expect_ok "the data plane runs as its own process" bash -c "ps -o args= -p $pid | grep -q 'dataplane --config $DPDIR/1.json'"
expect_eq "its config is readable by root only" "$(stat -c %a "$DPDIR/1.json")" 600
expect_eq "so is its control socket" "$(stat -c %a "$DPDIR/1.sock")" 600

log "a relayed download across a daemon restart"
slow_fetch "$T/f1"
wait_log t1 "the download goes through the relay" \
	".type==\"relay\" and .verdict==\"allow\" and .http_host==\"a.attacker.test\" and .target==\"$A:80\""
sleep 1
stop_daemon
expect_ok "the download is still running while the daemon is down" kill -0 "$FETCH"
start_daemon || exit 1
expect_eq "the restarted daemon adopted the data plane" "$(dp_pid)" "$pid"
fetch_done "the download completed across the restart" "$T/f1"

log "a relayed download across a daemon crash"
slow_fetch "$T/f2"
sleep 2
kill -9 "$DAEMON_PID"
wait "$DAEMON_PID" 2>/dev/null
DAEMON_PID=""
expect_eq "DNS answers while the daemon is dead" \
	"$(ip netns exec sb1 dig +tries=1 +time=3 b.attacker.test | awk '/status:/ {gsub(",", "", $6); print $6}')" NOERROR
start_daemon || exit 1
expect_eq "the restarted daemon adopted the data plane" "$(dp_pid)" "$pid"
fetch_done "the download completed across the crash" "$T/f2"

log "the daemon restarts a data plane that died"
kill -9 "$pid"
for _ in $(seq 100); do
	new=$(dp_pid)
	[[ -n "$new" && "$new" != "$pid" ]] && kill -0 "$new" 2>/dev/null && break
	sleep 0.1
done
if [[ -n "$new" && "$new" != "$pid" ]]; then pass "restarted as pid $new"; else fail "no new data plane"; fi
pid=$new
expect_eq "DNS works again" "$(dns_status t1 c.attacker.test)" NOERROR
expect_eq "and remembers what it had resolved" \
	"$(curl -s --unix-socket "$DPDIR/1.sock" "http://dp/v1/domain?ip=$A" | jq -r .domain)" c.attacker.test

log "events and metrics still reach the daemon"
expect_eq "Host not allowlisted gets 403" \
	"$(sbx t1 curl -sS -m 10 -o /dev/null -w '%{http_code}' -H 'Host: evil.test' http://a.attacker.test/)" 403
for _ in $(seq 30); do
	metric sandwall_denied_total 'reason="host_mismatch".*sandbox="t1"' | grep -q . && break
	sleep 0.2
done
expect_ok "relay refusal counted as a denial" bash -c "curl -s http://127.0.0.1:19464/metrics | grep -q 'sandwall_denied_total{reason=\"host_mismatch\",sandbox=\"t1\"}'"
expect_ok "DNS queries counted (from the data plane)" bash -c "curl -s http://127.0.0.1:19464/metrics | grep -q 'sandwall_dns_queries_total{sandbox=\"t1\",verdict=\"allow\"}'"
# The data plane restarted above, so its counters started over; the 403 is
# its only relayed connection since.
expect_ok "relay connections counted (from the data plane)" bash -c "curl -s http://127.0.0.1:19464/metrics | grep -q 'sandwall_relay_connections_total{result=\"denied\",sandbox=\"t1\"} 1'"

log "a structural change restarts the data plane"
stop_daemon
start_daemon --sni-check=false || exit 1
if [[ "$(dp_pid)" != "$pid" ]]; then pass "--sni-check=false restarted the data plane"; else fail "same data plane kept"; fi
expect_fail "and it has no relay" test -e "/proc/$(dp_pid)" -a -n "$(ss -ltnH "sport = :15001" | grep 10.200.1.1)"

log "a proxied download across a daemon restart"
ip netns exec "$ATTACKER_NS" python3 "$E2E_DIR/proxy.py" --bind "$A" --port "$PROXY_PORT" --origin "$A" \
	--log "$T/proxy.log" >"$T/proxy-stderr.log" 2>&1 &
for _ in $(seq 50); do (exec 3<>"/dev/tcp/$A/$PROXY_PORT") 2>/dev/null && break; sleep 0.1; done
stop_daemon
start_daemon --upstream-proxy "http://$A:$PROXY_PORT" || exit 1
pid=$(dp_pid)
slow_fetch "$T/f3"
sleep 2
expect_ok "the download goes through the upstream proxy" grep -q "^GET http://a.attacker.test/bytes/$BIG" "$T/proxy.log"
stop_daemon
start_daemon --upstream-proxy "http://$A:$PROXY_PORT" || exit 1
expect_eq "the data plane was adopted" "$(dp_pid)" "$pid"
fetch_done "the proxied download completed across the restart" "$T/f3"

log "destroy and nuke"
expect_ok "destroy t1" sandwall sandbox destroy t1
expect_fail "destroy stopped the data plane" kill -0 "$pid"
expect_ok "create t2" sandwall sandbox create t2 --policy "$P/proxy.yaml"
pid=$(dp_pid)
stop_daemon
expect_ok "nuke with the daemon stopped" sandwall nuke
expect_fail "nuke killed the data plane" kill -0 "$pid"
assert_no_remnants
