#!/usr/bin/env bash
# S2: policy-violation webhooks. A receiver on host loopback checks the
# HMAC signature of every delivery.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
RECEIVER=""
stop_receiver() { [[ -n "$RECEIVER" ]] && kill "$RECEIVER" 2>/dev/null && wait "$RECEIVER" 2>/dev/null; RECEIVER=""; }
trap 'stop_receiver; finish' EXIT

P="$E2E_DIR/policies"
A="$ATTACKER_IP"
HOOKS="$T/hooks.jsonl"
SECRET="e2e-$(head -c16 /dev/urandom | xxd -p)"
printf '%s\n' "$SECRET" >"$T/hook.key"
chmod 0600 "$T/hook.key"
HOOK_FLAGS=(--webhook "ops=http://127.0.0.1:18080/hook" --webhook-secret "ops=$T/hook.key")

start_receiver() {
	stop_receiver
	python3 "$E2E_DIR/webhook.py" --port 18080 --out "$HOOKS" --secret "$SECRET" "$@" >"$T/webhook.log" 2>&1 &
	RECEIVER=$!
	for _ in $(seq 50); do (exec 3<>/dev/tcp/127.0.0.1/18080) 2>/dev/null && return 0; sleep 0.1; done
	return 1
}
# hook_events <jq filter on events>: matching events delivered with a valid signature.
hook_events() { jq -c "select(.ok) | .body.events[] | select($1)" "$HOOKS" 2>/dev/null | wc -l; }
# wait_hook <desc> <jq filter>: up to 6s (batches go out every 2s).
wait_hook() {
	for _ in $(seq 60); do
		(($(hook_events "$2") > 0)) && { pass "$1"; return; }
		sleep 0.1
	done
	fail "$1 (no delivered event matching: $2)"
}
metric() { curl -s http://127.0.0.1:19464/metrics | awk -v m="$1" '$1 == m {print $2}'; }

log "setup"
sandwall nuke >/dev/null
setup_attacker || exit 1
: >"$HOOKS"
start_receiver || exit 1
start_daemon "${HOOK_FLAGS[@]}" || exit 1
expect_ok "create w1 (alerts: dns_bypass, quarantine; quarantine after 2 bypasses)" sandwall sandbox create w1 --policy "$P/alerts.yaml"
expect_ok "create w2 (no alerts)" sandwall sandbox create w2 --policy "$P/proxy.yaml"
out=$(sandwall sandbox create bad --policy "$P/alerts-unknown.yaml" 2>&1)
expect_ok "a policy naming an unconfigured webhook is rejected" grep -q 'no webhook "nosuch" is configured' <<<"$out"

log "violations are delivered, signed and filtered"
sbx w1 dig +tries=1 +time=1 @8.8.8.8 example.com >/dev/null 2>&1
wait_hook "dns_bypass delivered" '.sandbox_id=="w1" and .type=="deny" and .reason=="dns_bypass" and .dst_ip=="8.8.8.8"'
expect_eq "every delivery carried a valid signature" "$(jq -c 'select(.ok | not)' "$HOOKS" | wc -l)" 0
sbx w1 curl -sS -m 3 http://203.0.113.10/ >/dev/null 2>&1
sbx w2 dig +tries=1 +time=1 @8.8.8.8 example.com >/dev/null 2>&1
sleep 3
expect_eq "reasons the policy does not select are not sent" "$(hook_events '.reason=="not_allowed"')" 0
expect_eq "sandboxes without alerts send nothing" "$(hook_events '.sandbox_id=="w2"')" 0

log "the quarantine is delivered at once"
sbx w1 dig +tries=1 +time=1 @9.9.9.9 example.com >/dev/null 2>&1
for _ in $(seq 10); do (($(hook_events '.type=="quarantine"') > 0)) && break; sleep 0.1; done
expect_eq "auto quarantine delivered within a second" "$(hook_events '.sandbox_id=="w1" and .type=="quarantine" and .verdict=="quarantined" and (.reason|startswith("auto: 2 x dns_bypass"))')" 1
expect_ok "release w1" sandwall sandbox release w1
wait_hook "release delivered" '.sandbox_id=="w1" and .type=="quarantine" and .verdict=="released"'
expect_eq "deliveries counted" "$(( $(metric 'sandwall_webhook_deliveries_total{result="ok",webhook="ops"}') >= 3 ))" 1

log "failures are retried"
start_receiver --fail 2
sbx w1 dig +tries=1 +time=1 @1.0.0.1 example.com >/dev/null 2>&1
wait_hook "delivered after two failed attempts" '.dst_ip=="1.0.0.1"'
stop_receiver
sandwall sandbox quarantine w1 --reason "receiver down" >/dev/null
for _ in $(seq 100); do [[ -n "$(metric 'sandwall_webhook_deliveries_total{result="error",webhook="ops"}')" ]] && break; sleep 0.1; done
expect_eq "an unreachable receiver is counted as an error" "$(metric 'sandwall_webhook_deliveries_total{result="error",webhook="ops"}')" 1
expect_eq "the daemon carries on" "$(sandwall sandbox list --json | jq length)" 2

log "destroy and nuke"
expect_ok "nuke" sandwall nuke
stop_daemon
assert_no_remnants
