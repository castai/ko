package filter

import (
	"net"
	"net/netip"
)

func (s *Set) VerdictMask(attrs CgroupAttrs) uint64 {
	var mask uint64
	for i, a := range s.atoms {
		if atomEval(a, attrs) {
			mask |= 1 << i
		}
	}
	return mask
}

func atomEval(a Atom, attrs CgroupAttrs) bool {
	v := attrValue(a.Field, attrs)
	switch a.Op {
	case AttrEq:
		return v == a.Values[0]
	case AttrNeq:
		return v != a.Values[0]
	case AttrIn:
		for _, x := range a.Values {
			if v == x {
				return true
			}
		}
	}
	return false
}

func attrValue(field uint8, attrs CgroupAttrs) string {
	switch field {
	case AttrNamespace:
		return attrs.Namespace
	case AttrContainer:
		return attrs.Container
	case AttrPod:
		return attrs.Pod
	}
	return ""
}

func (s *Set) RunPreds(ev Event, verdict *uint64) uint16 {
	res := uint8(TriTrue)
	for _, p := range s.flat {
		switch p.Kind {
		case PredCmp:
			if !cmpField(p.B, eventField(p.A, ev), p.Val) {
				res = TriFalse
			}
		case PredIPSet:
			m := evIPInSet(ev, p)
			if m != (p.B == 0) {
				res = TriFalse
			}
		case PredAttr:
			if verdict == nil {
				if res == TriTrue {
					res = TriUnknown
				}
				continue
			}
			bit := (*verdict>>p.A)&1 == 1
			if bit != (p.B == 0) {
				res = TriFalse
			}
		case PredEnd:
			if p.B == 1 {
				return FilterUndecided
			}
			switch res {
			case TriTrue:
				return uint16(p.A)
			case TriUnknown:
				return FilterUndecided
			}
			res = TriTrue
		default:
			return FilterUndecided
		}
	}
	return FilterDrop
}

func eventField(f uint8, ev Event) uint64 {
	switch f {
	case FldRTT:
		return uint64(ev.RTTUS)
	case FldLife:
		return ev.LifeUS
	case FldRetrans:
		return uint64(ev.Retransmits)
	case FldSegs:
		return uint64(ev.SegsOut)
	case FldType:
		return 1 << uint64(ev.Type)
	}
	return 0
}

func cmpField(kind uint8, a, b uint64) bool {
	switch kind {
	case CmpEq:
		return a == b
	case CmpNeq:
		return a != b
	case CmpLt:
		return a < b
	case CmpLe:
		return a <= b
	case CmpGt:
		return a > b
	case CmpGe:
		return a >= b
	case CmpIn:
		return a&b != 0
	case CmpNotIn:
		return a&b == 0
	}
	return false
}

func evIPInSet(ev Event, p Pred) bool {
	ip := ev.LocalIP
	if p.A == 1 {
		ip = ev.RemoteIP
	}
	if len(ip) == 0 {
		return false
	}
	is4 := ip.To4() != nil
	for i := 0; i < int(p.N); i++ {
		if p.Fam[i] == 4 {
			if !is4 {
				continue
			}
			if prefixMatch4(p.Addr[i], ip.To4(), int(p.Plen[i])) {
				return true
			}
		} else {
			if is4 {
				continue
			}
			if prefixMatch(p.Addr[i], ip.To16(), int(p.Plen[i])) {
				return true
			}
		}
	}
	return false
}

func prefixMatch4(a [16]uint8, b []byte, plen int) bool {
	if plen > 32 {
		return false
	}
	full := plen / 8
	rem := plen % 8
	for i := 0; i < full; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	if rem > 0 {
		m := byte(0xff) << (8 - rem)
		if a[full]&m != b[full]&m {
			return false
		}
	}
	return true
}

func prefixMatch(a [16]uint8, b []byte, plen int) bool {
	if plen > 128 {
		return false
	}
	full := plen / 8
	rem := plen % 8
	for i := 0; i < full; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	if rem > 0 {
		m := byte(0xff) << (8 - rem)
		if a[full]&m != b[full]&m {
			return false
		}
	}
	return true
}

func ipInCIDR(ip net.IP, cidr string) bool {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return false
	}
	prefix := p
	if p.Addr().Is4In6() {
		prefix = netip.PrefixFrom(p.Addr().Unmap(), p.Bits())
	}
	a, err := netip.ParseAddr(ip.String())
	if err != nil {
		return false
	}
	return prefix.Contains(a.Unmap())
}
