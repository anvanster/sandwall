package fc

// Platform-neutral settings, kept out of the Linux-only vm.go so that
// CheckUIDRange (uids.go) and its tests build everywhere.

// Defaults for the Firecracker binaries and jail location.
const (
	DefaultChrootBase = "/srv/jailer"
	// DefaultUIDBase + k is the unprivileged uid/gid each sandbox's VMM
	// runs as. It sits far above the ranges distributions hand out in
	// /etc/subuid (100000 + n*65536), which rootless containers run as;
	// CheckUIDRange verifies the actual host.
	DefaultUIDBase = 2_000_000_000
)

// Paths locates the Firecracker binaries and the jailer chroot base.
type Paths struct {
	Firecracker string
	Jailer      string
	ChrootBase  string
	// UIDBase overrides DefaultUIDBase when non-zero.
	UIDBase int
}

func (p Paths) uidBase() int {
	if p.UIDBase != 0 {
		return p.UIDBase
	}
	return DefaultUIDBase
}
