#!/usr/bin/env bash
# S1 against real sites, in direct mode. Needs direct internet access (no
# REAL_PROXY); it is not part of `make e2e` for that reason.
#
# pypi.org and files.pythonhosted.org are served from a shared CDN (Fastly),
# so their addresses also serve sites the policy does not allow. Checks:
#   - TLS 1.3, HTTP/2 and a large download through the relay;
#   - domain fronting through a shared CDN address is refused as sni_mismatch;
#   - curl --http3 falls back to TCP after quic_blocked;
#   - pip install (many connections to both names) succeeds.
#
# HTTP3_CURL=/path/to/curl with HTTP/3 support enables the QUIC checks; the
# distro curl usually lacks it, and without it they are reported as skipped.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
trap finish EXIT

P="$E2E_DIR/policies"
REAL_PROXY="" # this test is about direct mode
HTTP3_CURL=${HTTP3_CURL:-}
FRONT=www.python.org # also on Fastly, not allowlisted
WHEEL_PKG=scipy
WHEEL_VER=1.14.1
WHEEL_MAX=120000000

log "preflight"
if ! curl -sS -m 10 -o /dev/null https://pypi.org/; then
	echo "this test needs direct internet access"
	exit 1
fi
# Downloads and the venv are written by the sandbox user (nobody).
DL="$SBX_DIR/dl"
mkdir -m 0777 "$DL"
sandwall nuke >/dev/null
start_daemon || exit 1
expect_ok "create sandbox t1" sandwall sandbox create t1 --policy "$P/s1-real.yaml"
count_events() { jq -c "select($2)" "$LOGS/$1.jsonl" | wc -l; }

log "allowlisted names on a shared CDN"
expect_eq "pypi.org over TLS 1.3 and HTTP/2" \
	"$(sbx t1 curl -sS -m 30 --tlsv1.3 --http2 -o /dev/null -w '%{http_version} %{http_code}' https://pypi.org/simple/requests/)" "2 200"
wait_log t1 "relayed with the allowlisted SNI" \
	'.type=="relay" and .verdict=="allow" and .sni=="pypi.org" and (.target|endswith(":443"))'
read -r wheel_url wheel_sha wheel_size < <(curl -sS -m 30 "https://pypi.org/pypi/$WHEEL_PKG/$WHEEL_VER/json" |
	jq -r --argjson max "$WHEEL_MAX" '.urls | map(select(.size < $max)) | max_by(.size) | "\(.url) \(.digests.sha256) \(.size)"')
if [[ -z "$wheel_url" ]]; then
	fail "could not look up a large $WHEEL_PKG $WHEEL_VER file on PyPI"
else
	start=$(date +%s.%N)
	code=$(sbx t1 curl -sS -m 600 -o "$DL/wheel" -w '%{http_code}' "$wheel_url")
	secs=$(awk -v s="$start" -v e="$(date +%s.%N)" 'BEGIN {printf "%.1f", e - s}')
	expect_eq "large download from files.pythonhosted.org" "$code" 200
	expect_eq "download intact ($((wheel_size / 1048576)) MiB in ${secs}s, sha256 from PyPI)" \
		"$(sha256sum "$DL/wheel" | cut -d' ' -f1)" "$wheel_sha"
	wait_log t1 "flow logged with the full size" \
		".type==\"flow\" and .dst_domain==\"files.pythonhosted.org\" and .bytes_in >= $wheel_size"
fi

log "domain fronting through a shared CDN address"
front_addr=$(sbx t1 dig +short pypi.org | grep -E '^[0-9.]+$' | head -1)
if [[ -z "$front_addr" ]]; then
	fail "pypi.org did not resolve in the sandbox"
else
	# Without sandwall the address really serves the unlisted site: that is
	# the gap the SNI check closes.
	expect_eq "outside the sandbox, $FRONT is served from pypi.org's address $front_addr" \
		"$(curl -sS -m 20 -o /dev/null -w '%{http_code}' --resolve "$FRONT:443:$front_addr" "https://$FRONT/")" 200
	expect_fail "inside, the same request is refused" \
		sbx t1 curl -sS -m 20 -o /dev/null --resolve "$FRONT:443:$front_addr" "https://$FRONT/"
	wait_log t1 "refused as sni_mismatch" \
		".type==\"relay\" and .reason==\"sni_mismatch\" and .sni==\"$FRONT\" and .dst_ip==\"$front_addr\" and .dst_port==443"
	expect_eq "plain HTTP with a fronted Host header gets 403" \
		"$(sbx t1 curl -sS -m 20 -o /dev/null -w '%{http_code}' -H "Host: $FRONT" "http://pypi.org/")" 403
	wait_log t1 "refused as host_mismatch" ".type==\"relay\" and .reason==\"host_mismatch\" and .http_host==\"$FRONT\""
fi

log "HTTP/3"
if [[ -z "$HTTP3_CURL" ]] || ! "$HTTP3_CURL" --version 2>/dev/null | grep -qw HTTP3; then
	skip "curl --http3 fallback (set HTTP3_CURL to a curl with HTTP/3 support)"
	skip "QUIC attempt logged as quic_blocked"
	skip "curl --http3-only fails"
else
	h3=$(install -m 0755 "$HTTP3_CURL" "$SBX_DIR/curl-h3" && echo "$SBX_DIR/curl-h3")
	expect_eq "outside the sandbox, pypi.org speaks HTTP/3" \
		"$("$h3" -sS -m 20 --http3-only -o /dev/null -w '%{http_version}' https://pypi.org/simple/requests/)" 3
	quic_before=$(count_events t1 '.type=="deny" and .reason=="quic_blocked"')
	read -r ver code secs < <(sbx t1 "$h3" -sS -m 30 --http3 -o /dev/null \
		-w '%{http_version} %{http_code} %{time_total}' https://pypi.org/simple/requests/)
	expect_eq "curl --http3 falls back to HTTP/2 over TCP" "$ver $code" "2 200"
	# The reject arrives as EHOSTUNREACH and curl falls back at once; when the
	# kernel rate-limits the ICMP error, curl's 200ms happy-eyeballs timer does.
	if awk -v s="$secs" 'BEGIN {exit !(s < 1)}'; then
		pass "fallback is fast (${secs}s for the whole request)"
	else
		fail "fallback took ${secs}s"
	fi
	wait_log t1 "QUIC attempt logged as quic_blocked" \
		'.type=="deny" and .reason=="quic_blocked" and .proto=="udp" and .dst_port==443'
	if (($(count_events t1 '.type=="deny" and .reason=="quic_blocked"') > quic_before)); then
		pass "the fallback followed a blocked QUIC attempt"
	else
		fail "no new quic_blocked event for the --http3 request"
	fi
	expect_fail "curl --http3-only fails" sbx t1 "$h3" -sS -m 15 --http3-only -o /dev/null https://pypi.org/simple/requests/
fi

log "pip install"
expect_ok "create a venv in the sandbox" sbx t1 python3 -m venv "$DL/venv"
relay_before=$(count_events t1 '.type=="relay" and .verdict=="allow"')
mismatch_before=$(count_events t1 '.type=="relay" and .verdict!="allow"')
expect_ok "pip install requests rich numpy" \
	sbx t1 "$DL/venv/bin/pip" install --no-cache-dir --disable-pip-version-check -q requests rich numpy
expect_ok "packages import" sbx t1 "$DL/venv/bin/python" -c "import requests, rich, numpy"
relayed=$(($(count_events t1 '.type=="relay" and .verdict=="allow"') - relay_before))
if ((relayed >= 2)); then pass "pip's connections went through the relay ($relayed allowed)"; else fail "only $relayed relayed connections"; fi
expect_eq "no relay refusals during pip install" \
	"$(($(count_events t1 '.type=="relay" and .verdict!="allow"') - mismatch_before))" 0
for host in pypi.org files.pythonhosted.org; do
	wait_log t1 "pip reached $host" ".type==\"relay\" and .verdict==\"allow\" and .sni==\"$host\""
done

log "destroy and nuke"
expect_ok "destroy t1" sandwall sandbox destroy t1
expect_ok "nuke" sandwall nuke
stop_daemon
assert_no_remnants
