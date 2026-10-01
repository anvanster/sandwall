package fc

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/anvanster/sandwall/internal/addressing"
)

// maxID keeps VMM ids below 2^31, which some tools treat as signed.
const maxID = 1<<31 - 1

// CheckUIDRange verifies that the uids and gids VMMs will run as
// (UIDBase+1 .. UIDBase+254) belong to nobody else on the host: no user or
// group in /etc/passwd or /etc/group, and no subordinate range in
// /etc/subuid or /etc/subgid. Sharing an id with another user or a rootless
// container would let it open the VM's jail files.
func (p Paths) CheckUIDRange() error {
	return checkIDRange(p.uidBase(), map[string]string{
		"/etc/passwd": "passwd", "/etc/group": "passwd",
		"/etc/subuid": "sub", "/etc/subgid": "sub",
	})
}

func checkIDRange(base int, files map[string]string) error {
	lo, hi := base+addressing.MinIndex, base+addressing.MaxIndex
	if lo < 1000 || hi > maxID {
		return fmt.Errorf("vm uid base %d: VMM ids %d-%d must lie between 1000 and %d", base, lo, hi, maxID)
	}
	var errs []error
	for path, kind := range files {
		f, err := os.Open(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Split(sc.Text(), ":")
			var start, count int
			switch {
			case kind == "passwd" && len(fields) >= 3:
				start, err = strconv.Atoi(fields[2])
				count = 1
			case kind == "sub" && len(fields) == 3:
				start, err = strconv.Atoi(fields[1])
				if err == nil {
					count, err = strconv.Atoi(fields[2])
				}
			default:
				continue
			}
			if err != nil || count <= 0 {
				continue
			}
			if start <= hi && start+count-1 >= lo {
				errs = append(errs, fmt.Errorf("%s: %q overlaps the VMM ids %d-%d", path, sc.Text(), lo, hi))
			}
		}
		f.Close()
		if err := sc.Err(); err != nil {
			return err
		}
	}
	if len(errs) > 0 {
		errs = append(errs, errors.New("choose another range with daemon --vm-uid-base"))
	}
	return errors.Join(errs...)
}
