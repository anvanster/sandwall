# Shared helpers for egressd end-to-end tests. Source from a test script.
# Requires root, a Linux host, nft, iproute2, tcpdump, dig, curl, jq, python3.

set -uo pipefail

: "${EGRESSD:?set EGRESSD to the egressd binary}"

E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
T="$(mktemp -d /tmp/egressd-e2e.XXXXXX)"
SOCK="$T/egressd.sock"
STATE="$T/state"
LOGS="$T/logs"
G=(--socket "$SOCK" --state-dir "$STATE" --log-dir "$LOGS")
DAEMON_PID=""
PASS=0
FAIL=0

# Attacker endpoint: its own netns behind a routed veth, so sandbox traffic
# to it takes the host FORWARD path like any internet destination would.
ATTACKER_NS=egattacker
ATTACKER_IP=10.99.0.1
ATTACKER_GW=10.99.0.254
ATTACKER_PORT=8080

UPLINK="$(ip -4 route show default | awk '{for (i=1;i<NF;i++) if ($i=="dev") print $(i+1); exit}')"
HOST_IP="$(ip -4 -o addr show dev "$UPLINK" | awk '{split($4,a,"/"); print a[1]; exit}')"
GATEWAY_IP="$(ip -4 route show default | awk '{print $3; exit}')"

log()  { printf '\n== %s\n' "$*"; }
pass() { printf '  ok    %s\n' "$*"; PASS=$((PASS + 1)); }
fail() { printf '  FAIL  %s\n' "$*"; FAIL=$((FAIL + 1)); }

egressd() { "$EGRESSD" "${G[@]}" "$@"; }
sbx() { local id=$1; shift; egressd sandbox exec "$id" -- "$@"; }

# dns_status <sandbox> <dig args...>: the response status (NOERROR, REFUSED,
# ...) or empty if no answer arrived.
dns_status() {
	local id=$1; shift
	sbx "$id" dig +tries=1 +time=3 "$@" | awk '/status:/ {gsub(",", "", $6); print $6}'
}

expect_ok() {
	local desc=$1; shift
	local out
	if out=$("$@" 2>&1); then pass "$desc"; else fail "$desc"; printf '        %s\n' "${out//$'\n'/$'\n'        }"; fi
}

expect_fail() {
	local desc=$1; shift
	if "$@" >/dev/null 2>&1; then fail "$desc (unexpectedly succeeded)"; else pass "$desc"; fi
}

expect_eq() {
	local desc=$1 got=$2 want=$3
	if [[ "$got" == "$want" ]]; then pass "$desc"; else fail "$desc: got '$got', want '$want'"; fi
}

# wait_log <sandbox> <desc> <jq boolean expr>: poll the sandbox log until a
# line matches (up to 5s).
wait_log() {
	local id=$1 desc=$2 expr=$3 file="$LOGS/$1.jsonl"
	for _ in $(seq 50); do
		if [[ -f "$file" ]] && jq -c "select($expr)" "$file" 2>/dev/null | grep -q .; then
			pass "$desc"
			return
		fi
		sleep 0.1
	done
	fail "$desc (no log line matching: $expr)"
	[[ -f "$file" ]] && tail -n 5 "$file" | sed 's/^/        /'
}

start_daemon() {
	"$EGRESSD" "${G[@]}" daemon --blocked-exempt 10.99.0.0/24 --metrics-addr 127.0.0.1:19464 \
		>>"$T/daemon.log" 2>&1 &
	DAEMON_PID=$!
	for _ in $(seq 50); do
		[[ -S "$SOCK" ]] && egressd sandbox list >/dev/null 2>&1 && return 0
		sleep 0.1
	done
	echo "daemon failed to start:" >&2
	cat "$T/daemon.log" >&2
	return 1
}

stop_daemon() {
	[[ -n "$DAEMON_PID" ]] || return 0
	kill "$DAEMON_PID" 2>/dev/null
	wait "$DAEMON_PID" 2>/dev/null
	DAEMON_PID=""
}

setup_attacker() {
	teardown_attacker
	ip netns add "$ATTACKER_NS"
	ip link add egtest0 type veth peer name egtest0p
	ip link set egtest0p netns "$ATTACKER_NS"
	ip addr add "$ATTACKER_GW/24" dev egtest0
	ip link set egtest0 up
	ip -n "$ATTACKER_NS" addr add "$ATTACKER_IP/24" dev egtest0p
	ip -n "$ATTACKER_NS" link set egtest0p up
	ip -n "$ATTACKER_NS" link set lo up
	ip -n "$ATTACKER_NS" route add default via "$ATTACKER_GW"
	ATTACKER_LOOT="$T/loot.txt"
	: >"$ATTACKER_LOOT"
	ip netns exec "$ATTACKER_NS" python3 "$E2E_DIR/attacker.py" --bind "$ATTACKER_IP" \
		--port "$ATTACKER_PORT" --loot "$ATTACKER_LOOT" >"$T/attacker.log" 2>&1 &
	for _ in $(seq 50); do
		curl -s -m 1 "http://$ATTACKER_IP:$ATTACKER_PORT/" >/dev/null && return 0
		sleep 0.1
	done
	echo "attacker endpoint failed to start" >&2
	return 1
}

teardown_attacker() {
	ip netns pids "$ATTACKER_NS" 2>/dev/null | xargs -r kill 2>/dev/null
	ip link del egtest0 2>/dev/null
	ip netns del "$ATTACKER_NS" 2>/dev/null
	return 0
}

# assert_no_remnants: nothing egressd-owned is left on the host.
assert_no_remnants() {
	expect_eq "no sb<k> netns left" "$(ip netns list | grep -cE '^sb[0-9]+')" 0
	expect_eq "no veth-h<k> links left" "$(ip -o link | grep -cE ' veth-[hs][0-9]+')" 0
	expect_eq "no egressd nft table left" "$(nft list tables | grep -c egressd)" 0
	expect_eq "no tc qdiscs on sandbox veths" "$(tc qdisc show | grep -c veth-h)" 0
	expect_eq "no /etc/netns/sb<k> left" "$(find /etc/netns -maxdepth 1 -name 'sb[0-9]*' 2>/dev/null | wc -l)" 0
}

finish() {
	stop_daemon
	"$EGRESSD" "${G[@]}" nuke >/dev/null 2>&1
	teardown_attacker
	printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
	if ((FAIL > 0)); then
		echo "artifacts kept in $T"
		exit 1
	fi
	rm -rf "$T"
}
