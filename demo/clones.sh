#!/usr/bin/env bash
# sandwall demo: 20 Firecracker clones from one snapshot, live logs.
#
# Every clone has the same guest IP (172.16.0.2), MAC and tap0, yet each
# lives in its own netns with its own policy and log. Each guest runs a small
# workload: an allowed fetch through its own name (c<N>.attacker.test) plus
# a few things the policy blocks. `sandwall logs -f` for every clone is merged
# into one live stream, and a per-clone summary follows.
#
# Needs /dev/kvm. Usage (root, Linux):
#   sudo SANDWALL=$PWD/bin/sandwall demo/clones.sh
# Environment: CLONES (default 20), DURATION seconds (default 30),
#   CLONE_STAGGER (default 1s, needed on nested-virtualization hosts).
set -uo pipefail

DEMO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$DEMO_DIR/../test/e2e/lib.sh"
CLONES=${CLONES:-20}
DURATION=${DURATION:-30}

if [[ -t 1 ]]; then BOLD=$'\e[1m' RED=$'\e[31m' GREEN=$'\e[32m' DIM=$'\e[2m' RESET=$'\e[0m'; else BOLD= RED= GREEN= DIM= RESET=; fi
step() { printf '\n%s== %s%s\n' "$BOLD" "$*" "$RESET"; }

TAILS=()
cleanup() {
	((${#TAILS[@]})) && kill "${TAILS[@]}" 2>/dev/null
	stop_daemon
	"$SANDWALL" "${G[@]}" nuke >/dev/null 2>&1
	teardown_attacker
	rm -rf "$T"
}
trap cleanup EXIT

[[ -e /dev/kvm ]] || { echo "this demo needs /dev/kvm"; exit 1; }
[[ -f "$FC_ASSETS/fc.json" ]] || bash "$DEMO_DIR/../test/e2e/fc-assets.sh" "$FC_ASSETS" || exit 1

"$SANDWALL" "${G[@]}" nuke >/dev/null
setup_attacker || exit 1
start_daemon "${FC_FLAGS[@]}" || exit 1

step "boot a base VM and snapshot it"
"$SANDWALL" "${G[@]}" sandbox create base --mode vm --vm-config "$FC_ASSETS/fc.json" --policy "$DEMO_DIR/clone-policy.yaml"
wait_guest base || exit 1
"$SANDWALL" "${G[@]}" vm snapshot base --out "$T/snap"
"$SANDWALL" "${G[@]}" sandbox destroy base >/dev/null

step "clone it $CLONES times"
start=$(date +%s)
"$SANDWALL" "${G[@]}" vm clone "$T/snap" --count "$CLONES" --prefix c --stagger "${CLONE_STAGGER:-1s}" \
	--policy "$DEMO_DIR/clone-policy.yaml" | column -t | sed 's/^/    /'
printf '    %d clones in %ds\n' "$CLONES" $(($(date +%s) - start))
for i in $(seq "$CLONES"); do wait_guest "c-$i" || exit 1; done
ids=$(for i in $(seq "$CLONES"); do vmx "c-$i" "ip -4 -o addr show eth0 | awk '{print \$4}'; cat /sys/class/net/eth0/address"; done | sort | uniq -c)
printf '    distinct guest identities across all clones:\n%s\n' "$(sed 's/^/    /' <<<"$ids")"

step "live: sandwall logs -f for every clone (${DURATION}s)"
for i in $(seq "$CLONES"); do
	# Process substitution, so $! is sandwall itself and killing it ends jq too.
	"$SANDWALL" "${G[@]}" logs "c-$i" -f > >(
		jq --unbuffered -r --arg red "$RED" --arg green "$GREEN" --arg reset "$RESET" '
			(if .verdict == "allow" then $green else $red end) as $c |
			"    \(.sandbox_id | (. + "     ")[:5]) \($c)\(.type | (. + "    ")[:4]) \(.verdict | (. + "       ")[:7])\($reset) " +
			(if .type == "dns" then "\(.qtype) \(.qname)"
			 elif .type == "flow" then "\(.dst_domain // .dst_ip):\(.dst_port) in=\(.bytes_in)B"
			 else "\(.reason) \(.proto) \(.dst_ip):\(.dst_port)" end)') &
	TAILS+=($!)
done
# Each guest: an allowed fetch through its own name, then things the policy blocks.
for i in $(seq "$CLONES"); do
	vmx "c-$i" "nohup sh -c 'sleep \$((RANDOM % 5)); while :; do
		curl -s -m 10 -o /dev/null http://c$i.attacker.test:$ATTACKER_PORT/bytes/65536
		curl -s -m 3 -o /dev/null https://example.com/
		curl -s -m 3 -o /dev/null http://169.254.169.254/latest/meta-data/
		sleep 10
	done' >/dev/null 2>&1 &"
done
sleep "$DURATION"
kill "${TAILS[@]}" 2>/dev/null
TAILS=()

step "per-clone summary (from each clone's own log)"
printf '    %-6s %6s %10s %10s %7s\n' clone flows bytes-in dns-denied denied
for i in $(seq "$CLONES"); do
	read -r flows bytes refused denied foreign < <(jq -s -r --arg id "c-$i" '[
		(map(select(.type == "flow")) | length),
		(map(select(.type == "flow") | .bytes_in) | add // 0),
		(map(select(.type == "dns" and .verdict != "allow")) | length),
		(map(select(.type == "deny")) | length),
		(map(select(.sandbox_id != $id)) | length)
	] | @tsv' "$LOGS/c-$i.jsonl")
	printf '    %-6s %6d %10d %10d %7d' "c-$i" "$flows" "$bytes" "$refused" "$denied"
	((foreign > 0)) && printf '  %sMISATTRIBUTED: %d%s' "$RED" "$foreign" "$RESET"
	printf '\n'
done
