#!/usr/bin/env bash
# Fetch and prepare everything VM mode needs into one directory (idempotent):
#
#   firecracker, jailer   release binaries
#   vmlinux               Firecracker CI guest kernel
#   rootfs.ext4           Firecracker CI Ubuntu rootfs plus dig/xxd, a
#                         resolver pointing at the sandbox proxy (172.16.0.1)
#                         and root SSH access for the generated test key
#   id_ed25519            SSH key for reaching guests from their netns
#   fc.json               a --vm-config for `sandwall sandbox create --mode vm`
#
# Usage: sudo test/e2e/fc-assets.sh [dir]   (default /var/lib/sandwall-fc)
set -euo pipefail

OUT=${1:-/var/lib/sandwall-fc}
FC_VERSION=v1.17.0
CI=v1.15 # newest Firecracker CI set with aarch64 guest artifacts
KERNEL=vmlinux-6.1.155
ARCH=$(uname -m)
CI_URL=https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/$CI/$ARCH

mkdir -p "$OUT"
cd "$OUT"

if [[ ! -x firecracker || ! -x jailer ]]; then
	echo "fetching firecracker $FC_VERSION"
	curl -fsSL "https://github.com/firecracker-microvm/firecracker/releases/download/$FC_VERSION/firecracker-$FC_VERSION-$ARCH.tgz" | tar -xz
	install -m 0755 "release-$FC_VERSION-$ARCH/firecracker-$FC_VERSION-$ARCH" firecracker
	install -m 0755 "release-$FC_VERSION-$ARCH/jailer-$FC_VERSION-$ARCH" jailer
	rm -rf "release-$FC_VERSION-$ARCH"
fi

if [[ ! -f vmlinux ]]; then
	echo "fetching guest kernel $KERNEL"
	curl -fsSL -o vmlinux.tmp "$CI_URL/$KERNEL"
	mv vmlinux.tmp vmlinux
fi

if [[ ! -f id_ed25519 ]]; then
	ssh-keygen -q -t ed25519 -N "" -C sandwall-test -f id_ed25519
fi

if [[ ! -f rootfs.ext4 ]]; then
	echo "building rootfs.ext4"
	[[ -f ubuntu.squashfs ]] || curl -fsSL -o ubuntu.squashfs "$CI_URL/ubuntu-24.04.squashfs"
	work=$(mktemp -d)
	trap 'umount "$work/rootfs/proc" "$work/rootfs/dev" "$work/rootfs/tmp" 2>/dev/null || true; rm -rf "$work"' EXIT
	unsquashfs -q -d "$work/rootfs" ubuntu.squashfs >/dev/null
	r="$work/rootfs"

	# Tools the M1 checks run inside the guest.
	rm -f "$r/etc/resolv.conf"
	cp -L /etc/resolv.conf "$r/etc/resolv.conf"
	mount -t proc proc "$r/proc"
	mount --bind /dev "$r/dev"
	mkdir -p "$r/tmp" "$r/var/cache/apt/archives/partial" "$r/var/lib/apt/lists/partial" "$r/var/log/apt"
	mount -t tmpfs tmpfs "$r/tmp"
	chroot "$r" env DEBIAN_FRONTEND=noninteractive apt-get update -qq
	chroot "$r" env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends dnsutils xxd >/dev/null
	chroot "$r" apt-get clean
	umount "$r/proc" "$r/dev" "$r/tmp"

	# Guest DNS goes to the netns side of tap0, which DNATs to the proxy.
	printf 'nameserver 172.16.0.1\n' >"$r/etc/resolv.conf"
	mkdir -p "$r/root/.ssh"
	install -m 0600 id_ed25519.pub "$r/root/.ssh/authorized_keys"
	chmod 0700 "$r/root/.ssh"

	truncate -s 2G rootfs.ext4.tmp
	mkfs.ext4 -q -F -d "$r" rootfs.ext4.tmp
	mv rootfs.ext4.tmp rootfs.ext4
fi

cat >fc.json <<EOF
{
  "boot-source": {
    "kernel_image_path": "$OUT/vmlinux",
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
  },
  "drives": [
    {
      "drive_id": "rootfs",
      "path_on_host": "$OUT/rootfs.ext4",
      "is_root_device": true,
      "is_read_only": false
    }
  ],
  "machine-config": {
    "vcpu_count": 1,
    "mem_size_mib": 256
  }
}
EOF
echo "assets ready in $OUT"
