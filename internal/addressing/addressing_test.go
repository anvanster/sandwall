package addressing

import "testing"

func TestFor(t *testing.T) {
	s, err := For(7)
	if err != nil {
		t.Fatal(err)
	}
	if s.Netns != "sb7" || s.HostVeth != "veth-h7" || s.NsVeth != "veth-s7" || s.IFB != "eg-ifb7" ||
		s.HostAddr.String() != "10.200.7.1" || s.NsAddr.String() != "10.200.7.2" || s.Transfer.String() != "10.200.7.0/30" {
		t.Errorf("got %+v", s)
	}
	for _, k := range []int{0, -1, 255} {
		if _, err := For(k); err == nil {
			t.Errorf("For(%d) accepted", k)
		}
	}
}

// Nuke deletes whatever these parsers accept, so they must reject anything
// sandwall did not create.
func TestIndexParsers(t *testing.T) {
	cases := []struct {
		name string
		fn   func(string) (int, bool)
		in   string
		k    int
		ok   bool
	}{
		{"netns", IndexFromNetns, "sb1", 1, true},
		{"netns", IndexFromNetns, "sb254", 254, true},
		{"netns", IndexFromNetns, "sb0", 0, false},
		{"netns", IndexFromNetns, "sb255", 0, false},
		{"netns", IndexFromNetns, "sb01", 0, false},
		{"netns", IndexFromNetns, "sbx", 0, false},
		{"netns", IndexFromNetns, "mysb1", 0, false},
		{"netns", IndexFromNetns, "sb1-other", 0, false},
		{"veth", IndexFromHostVeth, "veth-h12", 12, true},
		{"veth", IndexFromHostVeth, "veth-s12", 0, false},
		{"veth", IndexFromHostVeth, "veth-h", 0, false},
		{"veth", IndexFromHostVeth, "vethabc123", 0, false},
		{"ifb", IndexFromIFB, "eg-ifb3", 3, true},
		{"ifb", IndexFromIFB, "ifb0", 0, false},
	}
	for _, c := range cases {
		k, ok := c.fn(c.in)
		if k != c.k || ok != c.ok {
			t.Errorf("%s(%q) = %d, %v; want %d, %v", c.name, c.in, k, ok, c.k, c.ok)
		}
	}
}
