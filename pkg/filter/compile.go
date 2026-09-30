package filter

import (
	"errors"
	"fmt"
	"net/netip"

	"cel.dev/cel-go/common/ast"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
)

var (
	errUnknownList = errors.New("unknown list")
	errListLiteral = errors.New("list elements must be constants")
	errListString  = errors.New("list elements must be strings")
	errList        = errors.New("expected a list")
)

type atomKey struct {
	field uint8
	op    uint8
	vals  string
}

type compiler struct {
	atoms   []Atom
	atomIdx map[atomKey]int
}

var statsFields = map[string]uint8{
	"ko_rtt_us":      FldRTT,
	"ko_life_us":     FldLife,
	"ko_retransmits": FldRetrans,
	"ko_segs_out":    FldSegs,
	"ko_error":       FldErrno,
}

var attrFields = map[string]uint8{
	"ko_namespace": AttrNamespace,
	"ko_container": AttrContainer,
	"ko_pod":       AttrPod,
}

var builtinLists = map[string][]string{
	"ko_loopback_cidrs": LoopbackCIDRs,
	"ko_private_cidrs":  PrivateCIDRs,
}

var typeConsts = map[string]EventType{
	"ko_type_conn_failed": EvtConnFailed,
	"ko_type_conn_closed": EvtConnClosed,
	"ko_type_retransmit":  EvtRetransmit,
	"ko_type_probe":       EvtProbe,
}

var typesByName = map[string]EventType{
	EvtConnFailed.String(): EvtConnFailed,
	EvtConnClosed.String(): EvtConnClosed,
	EvtRetransmit.String(): EvtRetransmit,
	EvtProbe.String():      EvtProbe,
}

func typeBitOf(e ast.Expr) (uint64, bool) {
	if name, ok := identOf(e); ok {
		if t, ok := typeConsts[name]; ok {
			return 1 << uint64(t), true
		}
		return 0, false
	}
	v, ok := literalOf(e)
	if !ok {
		return 0, false
	}
	s, ok := v.(types.String)
	if !ok {
		return 0, false
	}
	t, ok := typesByName[string(s)]
	if !ok {
		return 0, false
	}
	return 1 << uint64(t), true
}

func typeMaskOf(e ast.Expr) (uint64, bool) {
	if e.Kind() != ast.ListKind {
		return 0, false
	}
	var mask uint64
	n := 0
	for _, el := range e.AsList().Elements() {
		bit, ok := typeBitOf(el)
		if !ok {
			return 0, false
		}
		mask |= bit
		n++
	}
	if n == 0 {
		return 0, false
	}
	return mask, true
}

// conj compiles an expression into a flat conjunction of predicates. It
// returns ok=false when the expression shape cannot be pushed down to eBPF
// (top-level ||, unsupported constructs): the filter then evaluates in
// userspace only.
func (c *compiler) conj(e ast.Expr) ([]Pred, bool) {
	switch e.Kind() {
	case ast.CallKind:
		call := e.AsCall()
		fn := call.FunctionName()
		args := call.Args()
		switch fn {
		case "_&&_":
			l, ok := c.conj(args[0])
			if !ok {
				return nil, false
			}
			r, ok := c.conj(args[1])
			if !ok {
				return nil, false
			}
			return append(l, r...), true
		case "!_":
			return c.negConj(args[0])
		case "_==_", "_!=_", "_<_", "_<=_", "_>_", "_>=_":
			return c.cmpPreds(args, cmpKind(fn))
		case "@in":
			return c.inPreds(args)
		case "ip_in":
			return c.ipInPreds(args, 0)
		}
	}
	return nil, false
}

func (c *compiler) negConj(e ast.Expr) ([]Pred, bool) {
	switch e.Kind() {
	case ast.CallKind:
		call := e.AsCall()
		fn := call.FunctionName()
		args := call.Args()
		switch fn {
		case "!_":
			return c.conj(args[0])
		case "_==_", "_!=_", "_<_", "_<=_", "_>_", "_>=_":
			return c.cmpPreds(args, flipCmp(cmpKind(fn)))
		case "@in":
			return c.negInPreds(args)
		case "ip_in":
			return c.ipInPreds(args, 1)
		}
	}
	return nil, false
}

func cmpKind(fn string) uint8 {
	switch fn {
	case "_==_":
		return CmpEq
	case "_!=_":
		return CmpNeq
	case "_<_":
		return CmpLt
	case "_<=_":
		return CmpLe
	case "_>_":
		return CmpGt
	case "_>=_":
		return CmpGe
	}
	return CmpEq
}

func flipCmp(kind uint8) uint8 {
	switch kind {
	case CmpEq:
		return CmpNeq
	case CmpNeq:
		return CmpEq
	case CmpLt:
		return CmpGe
	case CmpLe:
		return CmpGt
	case CmpGt:
		return CmpLe
	case CmpGe:
		return CmpLt
	}
	return kind
}

func (c *compiler) cmpPreds(args []ast.Expr, kind uint8) ([]Pred, bool) {
	if len(args) != 2 {
		return nil, false
	}
	if name, ok := identOf(args[0]); ok {
		if bit, ok := typeBitOf(args[1]); ok && name == "ko_type" {
			return typePreds(kind, bit), true
		}
		v, ok := literalOf(args[1])
		if !ok {
			return nil, false
		}
		preds := c.cmpField(name, kind, v)
		return preds, preds != nil
	}
	if name, ok := identOf(args[1]); ok {
		if bit, ok := typeBitOf(args[0]); ok && name == "ko_type" {
			return typePreds(flipCmp(kind), bit), true
		}
		v, ok := literalOf(args[0])
		if !ok {
			return nil, false
		}
		preds := c.cmpField(name, flipCmp(kind), v)
		return preds, preds != nil
	}
	return nil, false
}

func typePreds(kind uint8, bit uint64) []Pred {
	switch kind {
	case CmpEq:
		return []Pred{{Kind: PredCmp, A: FldType, B: CmpIn, Val: bit}}
	case CmpNeq:
		return []Pred{{Kind: PredCmp, A: FldType, B: CmpNotIn, Val: bit}}
	}
	return nil
}

func (c *compiler) cmpField(name string, kind uint8, v ref.Val) []Pred {
	if f, ok := statsFields[name]; ok {
		i, ok := v.(types.Int)
		if !ok {
			return nil
		}
		return []Pred{{Kind: PredCmp, A: f, B: kind, Val: uint64(int64(i))}}
	}
	if f, ok := attrFields[name]; ok {
		s, ok := v.(types.String)
		if !ok {
			return nil
		}
		switch kind {
		case CmpEq:
			return []Pred{c.attrPred(f, AttrEq, []string{string(s)}, 0)}
		case CmpNeq:
			return []Pred{c.attrPred(f, AttrEq, []string{string(s)}, 1)}
		}
		return nil
	}
	return nil
}

func (c *compiler) inPreds(args []ast.Expr) ([]Pred, bool) {
	if len(args) != 2 {
		return nil, false
	}
	name, ok := identOf(args[0])
	if !ok {
		return nil, false
	}
	if name == "ko_type" {
		mask, ok := typeMaskOf(args[1])
		if !ok {
			return nil, false
		}
		return []Pred{{Kind: PredCmp, A: FldType, B: CmpIn, Val: mask}}, true
	}
	f, ok := attrFields[name]
	if !ok {
		return nil, false
	}
	values, err := listOfStrings(args[1])
	if err != nil || len(values) == 0 {
		return nil, false
	}
	return []Pred{c.attrPred(f, AttrIn, values, 0)}, true
}

func (c *compiler) negInPreds(args []ast.Expr) ([]Pred, bool) {
	if len(args) != 2 {
		return nil, false
	}
	name, ok := identOf(args[0])
	if !ok {
		return nil, false
	}
	if name == "ko_type" {
		mask, ok := typeMaskOf(args[1])
		if !ok {
			return nil, false
		}
		return []Pred{{Kind: PredCmp, A: FldType, B: CmpNotIn, Val: mask}}, true
	}
	f, ok := attrFields[name]
	if !ok {
		return nil, false
	}
	values, err := listOfStrings(args[1])
	if err != nil || len(values) == 0 {
		return nil, false
	}
	preds := make([]Pred, 0, len(values))
	for _, v := range values {
		preds = append(preds, c.attrPred(f, AttrEq, []string{v}, 1))
	}
	return preds, true
}

func (c *compiler) attrPred(field uint8, op uint8, values []string, neg uint8) Pred {
	k := atomKey{field, op, fmt.Sprint(values)}
	id, ok := c.atomIdx[k]
	if !ok {
		id = len(c.atoms)
		c.atoms = append(c.atoms, Atom{Field: field, Op: op, Values: values})
		c.atomIdx[k] = id
	}
	return Pred{Kind: PredAttr, A: uint8(id), B: neg}
}

func (c *compiler) ipInPreds(args []ast.Expr, neg uint8) ([]Pred, bool) {
	if len(args) != 2 {
		return nil, false
	}
	name, ok := identOf(args[0])
	if !ok {
		return nil, false
	}
	var which uint8
	switch name {
	case "ko_local_addr":
		which = 0
	case "ko_remote_addr":
		which = 1
	default:
		return nil, false
	}
	values, err := listOfStrings(args[1])
	if err != nil {
		return nil, false
	}
	if len(values) == 0 {
		if neg == 0 {
			return nil, false
		}
		return []Pred{{Kind: PredIPSet, A: which, B: neg}}, true
	}
	if len(values) > MaxIPSet {
		return nil, false
	}
	var p Pred
	p.Kind = PredIPSet
	p.A = which
	p.B = neg
	p.N = uint8(len(values))
	for i, v := range values {
		pfx, err := netip.ParsePrefix(v)
		if err != nil {
			return nil, false
		}
		p.Plen[i] = uint16(pfx.Bits())
		if pfx.Addr().Is4() {
			p.Fam[i] = 4
			a4 := pfx.Addr().As4()
			copy(p.Addr[i][:], a4[:])
		} else {
			p.Fam[i] = 6
			a16 := pfx.Addr().As16()
			copy(p.Addr[i][:], a16[:])
		}
	}
	return []Pred{p}, true
}

func identOf(e ast.Expr) (string, bool) {
	if e.Kind() == ast.IdentKind {
		return e.AsIdent(), true
	}
	return "", false
}

func literalOf(e ast.Expr) (ref.Val, bool) {
	if e.Kind() == ast.LiteralKind {
		return e.AsLiteral(), true
	}
	return nil, false
}

func listOfStrings(e ast.Expr) ([]string, error) {
	if name, ok := identOf(e); ok {
		if vals, ok := builtinLists[name]; ok {
			return vals, nil
		}
		return nil, errUnknownList
	}
	if e.Kind() == ast.ListKind {
		els := e.AsList().Elements()
		out := make([]string, 0, len(els))
		for _, el := range els {
			v, ok := literalOf(el)
			if !ok {
				return nil, errListLiteral
			}
			s, ok := v.(types.String)
			if !ok {
				return nil, errListString
			}
			out = append(out, string(s))
		}
		return out, nil
	}
	return nil, errList
}
