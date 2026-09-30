package filter

import (
	"fmt"
	"net"
	"strconv"

	"cel.dev/cel-go/cel"
)

type EventType uint16

const (
	EvtConnFailed EventType = iota + 1
	EvtConnClosed
	EvtRetransmit
	EvtProbe
)

func (t EventType) String() string {
	switch t {
	case EvtConnFailed:
		return "conn_failed"
	case EvtConnClosed:
		return "conn_closed"
	case EvtRetransmit:
		return "retransmit"
	case EvtProbe:
		return "probe"
	default:
		return fmt.Sprintf("unknown(%d)", uint16(t))
	}
}

const (
	PredCmp   = 1
	PredIPSet = 2
	PredAttr  = 4
	PredEnd   = 5

	FldRTT     = 0
	FldLife    = 1
	FldRetrans = 2
	FldSegs    = 3
	FldType    = 4

	AttrNamespace = 0
	AttrContainer = 1
	AttrPod       = 2

	AttrEq  = 0
	AttrNeq = 1
	AttrIn  = 2

	CmpEq    = 0
	CmpNeq   = 1
	CmpLt    = 2
	CmpLe    = 3
	CmpGt    = 4
	CmpGe    = 5
	CmpIn    = 6
	CmpNotIn = 7

	TriFalse   = 0
	TriTrue    = 1
	TriUnknown = 2

	FilterDrop       = 0xfffd
	FilterUndecided  = 0xfffe
	FilterUnfiltered = 0xffff

	MaxIPSet   = 4
	MaxFilters = 32
	MaxPreds   = 64
)

type Pred struct {
	Val  uint64
	Kind uint8
	A    uint8
	B    uint8
	N    uint8
	Plen [MaxIPSet]uint16
	Fam  [MaxIPSet]uint8
	Addr [MaxIPSet][16]uint8
}

type Prog struct {
	NFilters uint32
	NPreds   uint32
	Preds    [MaxPreds]Pred
}

type Atom struct {
	Field  uint8
	Op     uint8
	Values []string
}

type Config struct {
	Name string
	Expr string
}

type CgroupAttrs struct {
	Namespace string
	Container string
	Pod       string
}

type AttrSource interface {
	Attrs(cgroupID uint64) (CgroupAttrs, bool)
	AttrsSnapshot() map[uint64]CgroupAttrs
}

type Event struct {
	Type        EventType
	Namespace   string
	Container   string
	Pod         string
	RTTUS       uint32
	LifeUS      uint64
	Retransmits uint32
	SegsOut     uint32
	LocalIP     net.IP
	LocalPort   uint16
	RemoteIP    net.IP
	RemotePort  uint16
}

type Set struct {
	names     []string
	asts      []*cel.Ast
	progs     []cel.Program
	atoms     []Atom
	preds     [][]Pred
	flat      []Pred
	userspace []bool
}

func Compile(cfg []Config) (*Set, error) {
	if len(cfg) == 0 {
		return nil, fmt.Errorf("no filters")
	}
	if len(cfg) > MaxFilters {
		return nil, fmt.Errorf("too many filters: %d, max %d", len(cfg), MaxFilters)
	}
	env, err := newEnv()
	if err != nil {
		return nil, fmt.Errorf("cel env: %w", err)
	}
	c := &compiler{atomIdx: map[atomKey]int{}}
	s := &Set{}
	seen := map[string]bool{}
	npreds := 0
	for _, f := range cfg {
		if f.Name == "" {
			return nil, fmt.Errorf("filter with empty name")
		}
		if seen[f.Name] {
			return nil, fmt.Errorf("duplicate filter name %q", f.Name)
		}
		seen[f.Name] = true
		parsed, err := parseCheck(env, f.Expr)
		if err != nil {
			return nil, fmt.Errorf("filter %q: %w", f.Name, err)
		}
		preds, ok := c.conj(parsed.NativeRep().Expr())
		if ok {
			if npreds+len(preds)+1 > MaxPreds {
				return nil, fmt.Errorf("filter %q: program too large: %d predicates, max %d", f.Name, npreds+len(preds)+1, MaxPreds)
			}
			npreds += len(preds) + 1
		}
		s.names = append(s.names, f.Name)
		s.asts = append(s.asts, parsed)
		s.preds = append(s.preds, preds)
		s.userspace = append(s.userspace, !ok)
	}
	if len(c.atoms) > 64 {
		return nil, fmt.Errorf("too many attribute predicates: %d, max %d", len(c.atoms), 64)
	}
	s.atoms = c.atoms
	for i := range s.names {
		end := Pred{Kind: PredEnd, A: uint8(i)}
		if s.userspace[i] {
			end.B = 1
		}
		s.flat = append(s.flat, s.preds[i]...)
		s.flat = append(s.flat, end)
	}
	for _, parsed := range s.asts {
		prg, err := env.Program(parsed)
		if err != nil {
			return nil, fmt.Errorf("cel program: %w", err)
		}
		s.progs = append(s.progs, prg)
	}
	return s, nil
}

func (s *Set) Names() []string {
	return s.names
}

func (s *Set) Atoms() []Atom {
	return s.atoms
}

func (s *Set) BPFProg() Prog {
	var p Prog
	p.NFilters = uint32(len(s.names))
	copy(p.Preds[:], s.flat)
	p.NPreds = uint32(len(s.flat))
	return p
}

func (s *Set) Evaluate(ev Event) (int, bool) {
	act := activation(ev)
	for i, prg := range s.progs {
		out, _, err := prg.Eval(act)
		if err != nil {
			continue
		}
		if b, ok := out.Value().(bool); ok && b {
			return i, true
		}
	}
	return 0, false
}

func activation(ev Event) map[string]any {
	return map[string]any{
		"ko_type":             ev.Type.String(),
		"ko_type_conn_failed": EvtConnFailed.String(),
		"ko_type_conn_closed": EvtConnClosed.String(),
		"ko_type_retransmit":  EvtRetransmit.String(),
		"ko_type_probe":       EvtProbe.String(),
		"ko_namespace":        ev.Namespace,
		"ko_container":        ev.Container,
		"ko_pod":              ev.Pod,
		"ko_rtt_us":           int64(ev.RTTUS),
		"ko_life_us":          int64(ev.LifeUS),
		"ko_retransmits":      int64(ev.Retransmits),
		"ko_segs_out":         int64(ev.SegsOut),
		"ko_local_addr":       net.JoinHostPort(ipString(ev.LocalIP), strconv.Itoa(int(ev.LocalPort))),
		"ko_remote_addr":      net.JoinHostPort(ipString(ev.RemoteIP), strconv.Itoa(int(ev.RemotePort))),
		"ko_loopback_cidrs":   LoopbackCIDRs,
		"ko_private_cidrs":    PrivateCIDRs,
	}
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}
