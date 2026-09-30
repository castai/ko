package filter

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"testing"
	"unsafe"
)

func mustCompile(t *testing.T, cfg []Config) *Set {
	t.Helper()
	s, err := Compile(cfg)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return s
}

func TestCompileEvaluate(t *testing.T) {
	cases := []struct {
		expr  string
		ev    Event
		match bool
	}{
		{`ko_namespace == "prod"`, Event{Namespace: "prod"}, true},
		{`ko_namespace == "prod"`, Event{Namespace: "dev"}, false},
		{`ko_namespace != "kube-system"`, Event{Namespace: ""}, true},
		{`ko_container in ["app1", "app2"]`, Event{Container: "app2"}, true},
		{`ko_container in ["app1", "app2"]`, Event{Container: "app3"}, false},
		{`ko_pod not in ["a", "b"]`, Event{Pod: "c"}, true},
		{`ko_pod not in ["a", "b"]`, Event{Pod: "a"}, false},
		{`ko_rtt_us > 100000`, Event{RTTUS: 200000}, true},
		{`ko_rtt_us > 100000`, Event{RTTUS: 100000}, false},
		{`ko_life_us >= 5000`, Event{LifeUS: 5000}, true},
		{`ko_retransmits < 5`, Event{Retransmits: 4}, true},
		{`ko_retransmits <= 5`, Event{Retransmits: 6}, false},
		{`100000 < ko_rtt_us`, Event{RTTUS: 150000}, true},
		{`ip_in(ko_remote_addr, ["10.0.0.0/8", "192.168.0.0/16"])`, Event{RemoteIP: net.ParseIP("10.1.2.3")}, true},
		{`ip_in(ko_remote_addr, ["10.0.0.0/8", "192.168.0.0/16"])`, Event{RemoteIP: net.ParseIP("8.8.8.8")}, false},
		{`ip_in(ko_remote_addr, ko_loopback_cidrs)`, Event{RemoteIP: net.ParseIP("127.0.0.1")}, true},
		{`ip_in(ko_remote_addr, ko_loopback_cidrs)`, Event{RemoteIP: net.ParseIP("::1")}, true},
		{`ip_in(ko_remote_addr, ko_loopback_cidrs)`, Event{RemoteIP: net.ParseIP("10.0.0.1")}, false},
		{`!(ip_in(ko_remote_addr, ko_loopback_cidrs))`, Event{RemoteIP: net.ParseIP("127.0.0.1")}, false},
		{`ip_in(ko_local_addr, ko_private_cidrs)`, Event{LocalIP: net.ParseIP("172.17.0.2")}, true},
		{`ko_namespace == "prod" && ko_rtt_us > 1000`, Event{Namespace: "prod", RTTUS: 2000}, true},
		{`ko_namespace == "prod" && ko_rtt_us > 1000`, Event{Namespace: "prod", RTTUS: 500}, false},
		{`ko_namespace == "prod" || ko_container == "app1"`, Event{Container: "app1"}, true},
		{`ko_type == ko_type_conn_failed`, Event{Type: EvtConnFailed}, true},
		{`ko_type == ko_type_conn_failed`, Event{Type: EvtRetransmit}, false},
		{`ko_type == "conn_closed"`, Event{Type: EvtConnClosed}, true},
		{`ko_type == "nope"`, Event{Type: EvtConnClosed}, false},
		{`ko_type != ko_type_retransmit`, Event{Type: EvtConnClosed}, true},
		{`ko_type != ko_type_retransmit`, Event{Type: EvtRetransmit}, false},
		{`ko_type in [ko_type_conn_failed, ko_type_conn_closed]`, Event{Type: EvtConnClosed}, true},
		{`ko_type in [ko_type_conn_failed, ko_type_conn_closed]`, Event{Type: EvtRetransmit}, false},
		{`ko_type in ["conn_failed", "retransmit"]`, Event{Type: EvtRetransmit}, true},
		{`ko_type not in [ko_type_retransmit]`, Event{Type: EvtConnFailed}, true},
		{`ko_type not in [ko_type_retransmit]`, Event{Type: EvtRetransmit}, false},
		{`ko_type in [ko_type_conn_failed] && ko_rtt_us > 10`, Event{Type: EvtConnFailed, RTTUS: 20}, true},
		{`ko_type in [ko_type_conn_failed] && ko_rtt_us > 10`, Event{Type: EvtConnClosed, RTTUS: 20}, false},
		{`ko_error > 0`, Event{Errno: 111}, true},
		{`ko_error > 0`, Event{}, false},
		{`ko_error == 104`, Event{Errno: 104}, true},
		{`ko_error == 104`, Event{Errno: 111}, false},
		{`ko_type == ko_type_conn_closed && ko_error > 0`, Event{Type: EvtConnClosed, Errno: 110}, true},
		{`ko_type == ko_type_conn_closed && ko_error > 0`, Event{Type: EvtConnClosed}, false},
		{`ko_type == ko_type_conn_closed && ko_error > 0`, Event{Type: EvtConnFailed, Errno: 111}, false},
		{`!(ko_namespace in ["kube-system"])`, Event{Namespace: "kube-system"}, false},
		{`!(ko_namespace in ["kube-system"])`, Event{Namespace: "other"}, true},
		{`!(ko_rtt_us > 100 && ko_namespace == "x")`, Event{RTTUS: 200, Namespace: "x"}, false},
		{`!(ko_rtt_us > 100 && ko_namespace == "x")`, Event{RTTUS: 50, Namespace: "x"}, true},
		{`true`, Event{}, true},
		{`false`, Event{}, false},
	}
	for _, c := range cases {
		s := mustCompile(t, []Config{{Name: "f", Expr: c.expr}})
		_, matched := s.Evaluate(c.ev)
		if matched != c.match {
			t.Errorf("expr %q: got %v, want %v", c.expr, matched, c.match)
		}
	}
}

func attrsOf(ev Event) CgroupAttrs {
	return CgroupAttrs{Namespace: ev.Namespace, Container: ev.Container, Pod: ev.Pod}
}

func TestFirstMatch(t *testing.T) {
	s := mustCompile(t, []Config{
		{Name: "a", Expr: `ko_rtt_us > 100`},
		{Name: "b", Expr: `ko_namespace == "ns"`},
		{Name: "c", Expr: `true`},
	})
	ev := Event{RTTUS: 5, Namespace: "ns"}
	idx, matched := s.Evaluate(ev)
	if !matched || idx != 1 {
		t.Fatalf("got idx %d matched %v, want 1 true", idx, matched)
	}
	if s.Names()[idx] != "b" {
		t.Fatalf("got name %q, want b", s.Names()[idx])
	}
	mask := s.VerdictMask(attrsOf(ev))
	if got := s.RunPreds(ev, &mask); got != 1 {
		t.Fatalf("preds got %d, want 1", got)
	}
}

func TestRunPredsUndecided(t *testing.T) {
	s := mustCompile(t, []Config{{Name: "a", Expr: `ko_namespace == "ns"`}})
	ev := Event{}
	if got := s.RunPreds(ev, nil); got != FilterUndecided {
		t.Fatalf("preds without verdict got %d, want %d", got, FilterUndecided)
	}
	mask := s.VerdictMask(CgroupAttrs{Namespace: "other"})
	if got := s.RunPreds(ev, &mask); got != FilterDrop {
		t.Fatalf("preds with negative verdict got %d, want drop", got)
	}
}

func TestRunPredsUserspaceOnly(t *testing.T) {
	s := mustCompile(t, []Config{{Name: "a", Expr: `ko_namespace == "a" || ko_rtt_us > 5`}})
	ev := Event{Namespace: "a", RTTUS: 100}
	mask := s.VerdictMask(attrsOf(ev))
	if got := s.RunPreds(ev, &mask); got != FilterUndecided {
		t.Fatalf("userspace-only filter got %d, want undecided", got)
	}
	if _, matched := s.Evaluate(ev); !matched {
		t.Fatal("userspace-only filter must still evaluate in cel")
	}
}

func TestCompileErrors(t *testing.T) {
	cases := []string{
		`ko_pid == 1`,
		`ko_comm == "x"`,
		`ko_rtt_us == "x"`,
		`ip_in(ko_pid, ["10.0.0.0/8"])`,
	}
	for _, expr := range cases {
		if _, err := Compile([]Config{{Name: "f", Expr: expr}}); err == nil {
			t.Errorf("expr %q: expected error", expr)
		}
	}
	for _, expr := range []string{
		`ko_namespace < "a"`,
		`size("x") == 1`,
		`ko_namespace`,
		`ko_namespace == "a" || ko_rtt_us > 1`,
		`ip_in(ko_remote_addr, ["not-a-cidr"])`,
		`ko_rtt_us in [1, 2]`,
	} {
		s, err := Compile([]Config{{Name: "f", Expr: expr}})
		if err != nil {
			t.Errorf("expr %q: unexpected error: %v", expr, err)
			continue
		}
		mask := s.VerdictMask(CgroupAttrs{Namespace: "a"})
		if got := s.RunPreds(Event{Namespace: "a", RTTUS: 2}, &mask); got != FilterUndecided {
			t.Errorf("expr %q: expected userspace-only, got %d", expr, got)
		}
	}
	if _, err := Compile(nil); err == nil {
		t.Error("expected error for no filters")
	}
	if _, err := Compile([]Config{{Name: "", Expr: "true"}}); err == nil {
		t.Error("expected error for empty name")
	}
	if _, err := Compile([]Config{{Name: "f", Expr: "true"}, {Name: "f", Expr: "true"}}); err == nil {
		t.Error("expected error for duplicate name")
	}
}

func TestRewriteNotIn(t *testing.T) {
	got := rewriteNotIn(`ko_pod not in ["a", "b"] && ko_rtt_us > 5`)
	want := `!(ko_pod in ["a", "b"]) && ko_rtt_us > 5`
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestPredLayoutMatchesBPF(t *testing.T) {
	if unsafe.Sizeof(Pred{}) != 88 {
		t.Fatalf("pred size %d, want 88", unsafe.Sizeof(Pred{}))
	}
	if unsafe.Offsetof(Pred{}.Val) != 0 || unsafe.Offsetof(Pred{}.Plen) != 12 ||
		unsafe.Offsetof(Pred{}.Fam) != 20 || unsafe.Offsetof(Pred{}.Addr) != 24 {
		t.Fatal("pred field offsets drifted from struct ko_pred")
	}
	if unsafe.Sizeof(Prog{}) != 8+MaxPreds*88 {
		t.Fatalf("prog size %d, want %d", unsafe.Sizeof(Prog{}), 8+MaxPreds*88)
	}
	if binary.Size(Prog{}) != int(unsafe.Sizeof(Prog{})) {
		t.Fatal("prog has implicit padding: the bpf map update would fail")
	}
	if binary.Size(Pred{}) != int(unsafe.Sizeof(Pred{})) {
		t.Fatal("pred has implicit padding: the bpf map update would fail")
	}
}

var testStrs = []string{"a", "b", "c", ""}
var testCIDRs = []string{"10.0.0.0/8", "192.168.0.0/16", "127.0.0.0/8", "::1/128", "fd00::/8", "0.0.0.0/0"}
var testIPs = []string{"10.1.2.3", "8.8.8.8", "127.0.0.1", "192.168.5.5", "::1", "2001:db8::1", "fd12::9", "1.2.3.4"}

func TestPredsMatchEvaluate(t *testing.T) {
	r := rand.New(rand.NewSource(42))
	for i := 0; i < 300; i++ {
		expr := randomConj(r, 4)
		s, err := Compile([]Config{{Name: "f", Expr: expr}})
		if err != nil {
			t.Fatalf("expr %q: compile: %v", expr, err)
		}
		for j := 0; j < 20; j++ {
			ev := randomEvent(r)
			_, want := s.Evaluate(ev)
			mask := s.VerdictMask(attrsOf(ev))
			got := s.RunPreds(ev, &mask)
			if want && got != 0 {
				t.Fatalf("expr %q event %+v: preds idx %d, want 0", expr, ev, got)
			}
			if !want && got != FilterDrop {
				t.Fatalf("expr %q event %+v: preds %d, want drop", expr, ev, got)
			}
		}
	}
}

func randomConj(r *rand.Rand, depth int) string {
	if depth <= 0 {
		return randomAtom(r)
	}
	switch r.Intn(3) {
	case 0:
		return randomAtom(r)
	case 1:
		return fmt.Sprintf("(%s && %s)", randomConj(r, depth-1), randomConj(r, depth-1))
	default:
		return fmt.Sprintf("!(%s)", randomAtom(r))
	}
}

func randomAtom(r *rand.Rand) string {
	switch r.Intn(7) {
	case 0:
		kinds := []string{"==", "!=", "<", "<=", ">", ">="}
		return fmt.Sprintf("ko_rtt_us %s %d", kinds[r.Intn(len(kinds))], r.Intn(4)*1000)
	case 1:
		return fmt.Sprintf("ko_namespace %s %q", pick(r, []string{"==", "!="}), pick(r, []string{"a", "b", "prod", "kube-system"}))
	case 2:
		return fmt.Sprintf("ko_container in [%s]", strList(r))
	case 3:
		return fmt.Sprintf("ko_pod not in [%s]", strList(r))
	case 4:
		return fmt.Sprintf("ip_in(ko_remote_addr, [%s])", cidrList(r, 4))
	case 5:
		typeNames := []string{"ko_type_conn_failed", "ko_type_conn_closed", "ko_type_retransmit"}
		if r.Intn(2) == 0 {
			return fmt.Sprintf("ko_type == %s", pick(r, typeNames))
		}
		return fmt.Sprintf("ko_type in [%s, %s]", pick(r, typeNames), pick(r, typeNames))
	default:
		return fmt.Sprintf("ip_in(ko_local_addr, [%s])", cidrList(r, 4))
	}
}

func randomEvent(r *rand.Rand) Event {
	return Event{
		Type:        pick(r, []EventType{EvtConnFailed, EvtConnClosed, EvtRetransmit}),
		Namespace:   pick(r, testStrs),
		Container:   pick(r, testStrs),
		Pod:         pick(r, testStrs),
		RTTUS:       uint32(r.Intn(4000)),
		LifeUS:      uint64(r.Intn(100000)),
		Retransmits: uint32(r.Intn(8)),
		SegsOut:     uint32(r.Intn(300)),
		LocalIP:     net.ParseIP(pick(r, testIPs)),
		RemoteIP:    net.ParseIP(pick(r, testIPs)),
		LocalPort:   uint16(r.Intn(65535)),
		RemotePort:  uint16(r.Intn(65535)),
	}
}

func pick[T any](r *rand.Rand, xs []T) T {
	return xs[r.Intn(len(xs))]
}

func strList(r *rand.Rand) string {
	s := ""
	for i := 0; i < 1+r.Intn(2); i++ {
		if i > 0 {
			s += ", "
		}
		s += fmt.Sprintf("%q", pick(r, []string{"a", "b", "c"}))
	}
	return s
}

func cidrList(r *rand.Rand, max int) string {
	s := ""
	n := 1 + r.Intn(max)
	for i := 0; i < n; i++ {
		if i > 0 {
			s += ", "
		}
		s += fmt.Sprintf("%q", pick(r, testCIDRs))
	}
	return s
}
