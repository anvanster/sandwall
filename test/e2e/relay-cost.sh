#!/usr/bin/env bash
# Relay cost: what the SNI/Host check costs a large HTTPS download, compared
# with --sni-check=false, with and without a max_ingress_bw cap.
#
# The measurement uses a local HTTPS server (openssl s_server, single-threaded
# C) in the attacker netns behind bench.attacker.test, so internet variance
# does not hide the relay's own cost (sandbox t1). With direct internet access
# a second sandbox (t2, real resolver) also downloads a large wheel from
# files.pythonhosted.org in both modes, for information only.
#
# Not part of `make e2e`: it is a benchmark and takes a few minutes.
# Environment: BIG_MB (default 512), RUNS (throughput runs, default 3),
# LAT_RUNS (latency samples, default 20), CAP_MBIT (default 200).
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
trap 'pkill -f "[o]penssl s_server -accept $ATTACKER_IP:443" 2>/dev/null; finish' EXIT

P="$E2E_DIR/policies"
REAL_PROXY="" # direct mode
BIG_MB=${BIG_MB:-512}
RUNS=${RUNS:-3}
LAT_RUNS=${LAT_RUNS:-20}
CAP_MBIT=${CAP_MBIT:-200}
NAME=bench.attacker.test

log "setup"
sandwall nuke >/dev/null
setup_attacker || exit 1
WWW="$T/www"
mkdir -p "$WWW"
head -c $((BIG_MB << 20)) /dev/urandom >"$WWW/big.bin"
head -c 1024 /dev/urandom >"$WWW/small.bin"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=$NAME" \
	-keyout "$T/bench.key" -out "$T/bench.crt" 2>/dev/null
(cd "$WWW" && exec ip netns exec "$ATTACKER_NS" openssl s_server -accept "$ATTACKER_IP:443" \
	-cert "$T/bench.crt" -key "$T/bench.key" -WWW -quiet) >"$T/s_server.log" 2>&1 &
for _ in $(seq 50); do curl -sk -m 1 -o /dev/null "https://$ATTACKER_IP/small.bin" && break; sleep 0.1; done
expect_ok "local HTTPS server up" curl -sk -m 5 -o /dev/null "https://$ATTACKER_IP/small.bin"

sed "s/@CAP@//" "$P/relay-cost.yaml" >"$T/uncapped.yaml"
sed "s/@CAP@/  max_ingress_bw: ${CAP_MBIT}mbit/" "$P/relay-cost.yaml" >"$T/capped.yaml"
start_daemon || exit 1
expect_ok "create sandbox t1" sandwall sandbox create t1 --policy "$T/uncapped.yaml"

wheel_url=""
if curl -sS -m 10 -o /dev/null https://pypi.org/; then
	expect_ok "create sandbox t2 (real sites)" sandwall sandbox create t2 --policy "$P/s1-real.yaml"
	read -r wheel_url wheel_size < <(curl -sS -m 30 https://pypi.org/pypi/scipy/1.14.1/json |
		jq -r '.urls | map(select(.size < 120000000)) | max_by(.size) | "\(.url) \(.size)"')
fi

median() { sort -n | awk '{a[NR] = $1} END {print (NR % 2) ? a[(NR + 1) / 2] : (a[NR / 2] + a[NR / 2 + 1]) / 2}'; }

# latency: median DNS time, and TLS-handshake-done and first-byte times
# counted from the end of DNS (ms), for a 1 KiB file in t1. DNS is reported
# on its own: the sandbox's DNS proxy (and its allow-set insert) dominates the
# total and varies far more than the relay's cost.
latency() {
	local i dns=() hs=() ttfb=()
	for i in $(seq "$LAT_RUNS"); do
		read -r n a s < <(sbx t1 curl -sk -m 10 -o /dev/null \
			-w '%{time_namelookup} %{time_appconnect} %{time_starttransfer}\n' "https://$NAME/small.bin")
		dns+=("$n") hs+=("$(awk -v a="$a" -v n="$n" 'BEGIN {print a - n}')") ttfb+=("$(awk -v s="$s" -v n="$n" 'BEGIN {print s - n}')")
	done
	for list in dns hs ttfb; do
		local -n l=$list
		printf '%s ' "$(printf '%s\n' "${l[@]}" | median | awk '{printf "%.2f", $1 * 1000}')"
	done
	printf '\n'
}

# throughput <sandbox> <url> <curl args...>: median Mbit/s over RUNS downloads.
throughput() {
	local id=$1 url=$2 i out=(); shift 2
	for i in $(seq "$RUNS"); do
		out+=("$(sbx "$id" curl -sS -m 600 -o /dev/null -w '%{speed_download}' "$@" "$url")")
	done
	printf '%s\n' "${out[@]}" | median | awk '{printf "%.0f", $1 * 8 / 1e6}'
}

declare -A R
measure() { # measure <mode key> <label> [real]: real also downloads the wheel in t2
	local mode=$1 label=$2
	read -r R[$mode,dns] R[$mode,hs] R[$mode,ttfb] < <(latency)
	R[$mode,big]=$(throughput t1 "https://$NAME/big.bin" -k)
	if [[ -n "$wheel_url" && "${3:-}" == real ]]; then R[$mode,real]=$(throughput t2 "$wheel_url"); fi
	printf '    %-16s dns %6s ms  tls %5s ms  first byte %5s ms  local %5s Mbit/s  real %4s Mbit/s\n' \
		"$label" "${R[$mode,dns]}" "${R[$mode,hs]}" "${R[$mode,ttfb]}" "${R[$mode,big]}" "${R[$mode,real]:--}"
}

relay_events() { jq -c "select(.type==\"relay\" and .sni==\"$NAME\")" "$LOGS/t1.jsonl" | wc -l; }

log "relay (SNI check on)"
before=$(relay_events)
measure relay relay real
expect_ok "downloads went through the relay" test "$(relay_events)" -gt "$before"
sandwall policy apply t1 "$T/capped.yaml" >/dev/null
measure relay_cap "relay, ${CAP_MBIT}mbit"

log "--sni-check=false"
sandwall policy apply t1 "$T/uncapped.yaml" >/dev/null
stop_daemon
start_daemon --sni-check=false || exit 1
before=$(relay_events)
measure direct direct real
expect_eq "downloads did not go through the relay" "$(relay_events)" "$before"
sandwall policy apply t1 "$T/capped.yaml" >/dev/null
measure direct_cap "direct, ${CAP_MBIT}mbit"

log "comparison"
ratio() { awk -v a="$1" -v b="$2" 'BEGIN {printf "%.0f", 100 * a / b}'; }
pct=$(ratio "${R[relay,big]}" "${R[direct,big]}")
add_hs=$(awk -v a="${R[relay,hs]}" -v b="${R[direct,hs]}" 'BEGIN {printf "%.2f", a - b}')
add_ttfb=$(awk -v a="${R[relay,ttfb]}" -v b="${R[direct,ttfb]}" 'BEGIN {printf "%.2f", a - b}')
printf '    uncapped: relay reaches %s%% of direct throughput; adds %s ms to the TLS handshake, %s ms to the first byte\n' \
	"$pct" "$add_hs" "$add_ttfb"
if ((${R[relay,big]} >= 1000)); then
	pass "relay sustains over 1 Gbit/s uncapped (${R[relay,big]} Mbit/s, $pct% of direct)"
else
	fail "relay only ${R[relay,big]} Mbit/s uncapped"
fi
if awk -v d="$add_hs" 'BEGIN {exit !(d < 5)}'; then pass "relay adds under 5 ms to the TLS handshake ($add_hs ms)"; else fail "relay adds $add_hs ms to the handshake"; fi
for mode in relay_cap direct_cap; do
	p=$(ratio "${R[$mode,big]}" "$CAP_MBIT")
	label="${mode%_cap}, ${CAP_MBIT}mbit cap"
	if ((p >= 85 && p <= 105)); then pass "$label: ${R[$mode,big]} Mbit/s is $p% of the cap"; else fail "$label: ${R[$mode,big]} Mbit/s is $p% of the cap"; fi
done
if [[ -z "$wheel_url" ]]; then skip "real-site download (no direct internet access)"; fi

log "destroy and nuke"
expect_ok "destroy t1" sandwall sandbox destroy t1
[[ -n "$wheel_url" ]] && expect_ok "destroy t2" sandwall sandbox destroy t2
expect_ok "nuke" sandwall nuke
stop_daemon
assert_no_remnants
