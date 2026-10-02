#!/usr/bin/env bash
# S3: OpenTelemetry log export over OTLP/HTTP to a local sink.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
SINK_PID=""
stop_sink() { [[ -n "$SINK_PID" ]] && kill "$SINK_PID" 2>/dev/null && wait "$SINK_PID" 2>/dev/null; SINK_PID=""; }
trap 'stop_sink; finish' EXIT

P="$E2E_DIR/policies"
A="$ATTACKER_IP"
OUT="$T/otlp.jsonl"
OTLPSINK=${OTLPSINK:?set OTLPSINK to the otlp-sink binary}
OTEL_FLAGS=(--otlp-endpoint http://127.0.0.1:14318 --otlp-header "Authorization=Bearer e2e")

start_sink() {
	stop_sink
	"$OTLPSINK" -listen 127.0.0.1:14318 -out "$OUT" >"$T/otlpsink.log" 2>&1 &
	SINK_PID=$!
	for _ in $(seq 50); do (exec 3<>/dev/tcp/127.0.0.1/14318) 2>/dev/null && return 0; sleep 0.1; done
	return 1
}
records() { jq -c "select($1)" "$OUT" 2>/dev/null | wc -l; }
# wait_record <desc> <jq filter>: up to 5s (the SDK exports every second).
wait_record() {
	for _ in $(seq 50); do
		(($(records "$2") > 0)) && { pass "$1"; return; }
		sleep 0.1
	done
	fail "$1 (no record matching: $2)"
	tail -n 3 "$OUT" 2>/dev/null | sed 's/^/        /'
}

log "setup"
sandwall nuke >/dev/null
setup_attacker || exit 1
: >"$OUT"
start_sink || exit 1
start_daemon "${OTEL_FLAGS[@]}" || exit 1
expect_ok "create o1" sandwall sandbox create o1 --policy "$P/proxy.yaml"

log "every event is exported"
expect_eq "allowlisted fetch" "$(sbx o1 curl -sS -m 10 -o /dev/null -w '%{http_code}' "http://a.attacker.test:$ATTACKER_PORT/")" 200
sbx o1 dig +tries=1 +time=1 @8.8.8.8 example.com >/dev/null 2>&1
dns_status o1 x.evil.test >/dev/null
wait_record "DNS allow" '.event_name=="sandwall.dns" and .attrs["dns.question.name"]=="a.attacker.test." and .attrs["sandwall.verdict"]=="allow" and .severity=="INFO"'
wait_record "flow with bytes and domain" \
	".event_name==\"sandwall.flow\" and .attrs[\"destination.port\"]==\"$ATTACKER_PORT\" and .attrs[\"sandwall.destination.domain\"]==\"a.attacker.test\" and (.attrs[\"sandwall.bytes_in\"]|tonumber) > 0"
wait_record "deny with reason and destination" \
	'.event_name=="sandwall.deny" and .attrs["sandwall.reason"]=="dns_bypass" and .attrs["destination.address"]=="8.8.8.8" and .severity=="WARN"'
wait_record "DNS refusal" '.event_name=="sandwall.dns" and .attrs["sandwall.verdict"]=="refused" and .attrs["dns.question.name"]=="x.evil.test."'
expect_ok "quarantine o1" sandwall sandbox quarantine o1 --reason e2e
wait_record "quarantine as ERROR" '.event_name=="sandwall.quarantine" and .severity=="ERROR" and .attrs["sandwall.reason"]=="e2e"'
expect_eq "records carry the sandbox id" "$(records '.attrs["sandwall.sandbox.id"]!="o1"')" 0
expect_eq "resource service.name is sandwall" "$(records '.service!="sandwall"')" 0
expect_eq "--otlp-header sent" "$(records '.authorization!="Bearer e2e"')" 0
expect_ok "release o1" sandwall sandbox release o1

log "violations only"
stop_daemon
: >"$OUT"
start_daemon "${OTEL_FLAGS[@]}" --otlp-events violations || exit 1
expect_eq "allowlisted fetch" "$(sbx o1 curl -sS -m 10 -o /dev/null -w '%{http_code}' "http://b.attacker.test:$ATTACKER_PORT/")" 200
sbx o1 dig +tries=1 +time=1 @9.9.9.9 example.com >/dev/null 2>&1
wait_record "deny exported" '.event_name=="sandwall.deny" and .attrs["destination.address"]=="9.9.9.9"'
sleep 2
expect_eq "allowed DNS and flows not exported" "$(records '.attrs["sandwall.verdict"]=="allow"')" 0

log "shutdown flushes"
sbx o1 dig +tries=1 +time=1 @1.0.0.1 example.com >/dev/null 2>&1
sleep 0.3
stop_daemon
expect_eq "deny logged just before stop exported" "$(records '.attrs["destination.address"]=="1.0.0.1"')" 1

log "an unreachable collector does not affect sandboxes"
stop_sink
start_daemon "${OTEL_FLAGS[@]}" || exit 1
expect_eq "DNS works" "$(dns_status o1 c.attacker.test)" NOERROR
expect_eq "fetch works" "$(sbx o1 curl -sS -m 10 -o /dev/null -w '%{http_code}' "http://c.attacker.test:$ATTACKER_PORT/")" 200
expect_fail "invalid --otlp-events rejected" timeout 5 "$SANDWALL" daemon --otlp-endpoint http://127.0.0.1:14318 --otlp-events some

log "destroy and nuke"
expect_ok "nuke" sandwall nuke
stop_daemon
assert_no_remnants
