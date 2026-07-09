// Angie Guardian — WAF + proof-of-work bot firewall for Angie.
// Copyright (C) 2026 Melroy van den Berg
// SPDX-License-Identifier: AGPL-3.0-or-later

package intel

import (
	"bytes"
	"net/netip"
	"sort"
	"strings"
)

// rangeSet is an immutable set of IP ranges over the 16-byte address space
// (IPv4 lives in its v4-mapped block, which is also where As16 puts v4
// lookups, so the two always agree). Ranges are sorted and overlap-merged at
// build time, so membership is one binary search: reputation feeds carry
// tens of thousands of prefixes and sit on the auth hot path.
type rangeSet struct {
	ranges []ipRange
}

type ipRange struct {
	start, end [16]byte
}

func rangeOf(p netip.Prefix) ipRange {
	p = p.Masked()
	start := p.Addr().As16()
	bits := p.Bits()
	if p.Addr().Is4() {
		bits += 96
	}
	end := start
	for i := bits; i < 128; i++ {
		end[i/8] |= 1 << (7 - i%8)
	}
	return ipRange{start: start, end: end}
}

func newRangeSet(prefixes []netip.Prefix) *rangeSet {
	rs := make([]ipRange, 0, len(prefixes))
	for _, p := range prefixes {
		rs = append(rs, rangeOf(p))
	}
	sort.Slice(rs, func(i, j int) bool {
		return bytes.Compare(rs[i].start[:], rs[j].start[:]) < 0
	})
	merged := rs[:0]
	for _, r := range rs {
		if n := len(merged); n > 0 && bytes.Compare(r.start[:], merged[n-1].end[:]) <= 0 {
			if bytes.Compare(r.end[:], merged[n-1].end[:]) > 0 {
				merged[n-1].end = r.end
			}
			continue
		}
		merged = append(merged, r)
	}
	return &rangeSet{ranges: merged}
}

// Contains reports whether addr falls inside any range.
func (s *rangeSet) Contains(addr netip.Addr) bool {
	k := addr.As16()
	i := sort.Search(len(s.ranges), func(i int) bool {
		return bytes.Compare(s.ranges[i].start[:], k[:]) > 0
	}) - 1
	return i >= 0 && bytes.Compare(k[:], s.ranges[i].end[:]) <= 0
}

// ParseList parses a plain-text IP/CIDR list: one entry per line, blank lines
// skipped, '#' and ';' start a comment (whole-line or inline). This covers
// the common feed formats (FireHOL netsets/ipsets, blocklist.de, CINS,
// hand-maintained local lists). Unparseable lines are counted, not fatal:
// one garbage line must not drop an otherwise good feed.
func ParseList(raw []byte) (prefixes []netip.Prefix, invalid int) {
	for line := range strings.Lines(string(raw)) {
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, "/") {
			p, err := netip.ParsePrefix(line)
			if err != nil {
				invalid++
				continue
			}
			prefixes = append(prefixes, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(line)
		if err != nil {
			invalid++
			continue
		}
		prefixes = append(prefixes, netip.PrefixFrom(a, a.BitLen()))
	}
	return prefixes, invalid
}
