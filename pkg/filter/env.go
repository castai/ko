package filter

import (
	"fmt"
	"net"
	"net/netip"
	"regexp"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
	"cel.dev/cel-go/common/types/traits"
)

var LoopbackCIDRs = []string{"127.0.0.0/8", "::1/128"}
var PrivateCIDRs = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fd00::/8"}

func newEnv() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable("ko_type", cel.StringType),
		cel.Variable("ko_type_conn_failed", cel.StringType),
		cel.Variable("ko_type_conn_closed", cel.StringType),
		cel.Variable("ko_type_retransmit", cel.StringType),
		cel.Variable("ko_type_probe", cel.StringType),
		cel.Variable("ko_namespace", cel.StringType),
		cel.Variable("ko_container", cel.StringType),
		cel.Variable("ko_pod", cel.StringType),
		cel.Variable("ko_rtt_us", cel.IntType),
		cel.Variable("ko_life_us", cel.IntType),
		cel.Variable("ko_retransmits", cel.IntType),
		cel.Variable("ko_segs_out", cel.IntType),
		cel.Variable("ko_error", cel.IntType),
		cel.Variable("ko_local_addr", cel.StringType),
		cel.Variable("ko_remote_addr", cel.StringType),
		cel.Variable("ko_loopback_cidrs", cel.ListType(cel.StringType)),
		cel.Variable("ko_private_cidrs", cel.ListType(cel.StringType)),
		cel.Function("ip_in",
			cel.Overload("ip_in_string_list",
				[]*cel.Type{cel.StringType, cel.ListType(cel.StringType)},
				cel.BoolType,
				cel.BinaryBinding(ipInVal),
			),
		),
	)
}

func ipInVal(a, b ref.Val) ref.Val {
	addr, ok := a.(types.String)
	if !ok {
		return types.NewErr("ip_in: invalid address")
	}
	list, ok := b.(traits.Lister)
	if !ok {
		return types.NewErr("ip_in: invalid cidr list")
	}
	var cidrs []string
	for it := list.Iterator(); it.HasNext() == types.True; {
		s, ok := it.Next().(types.String)
		if !ok {
			return types.NewErr("ip_in: cidrs must be strings")
		}
		cidrs = append(cidrs, string(s))
	}
	return types.Bool(AddrInCIDRs(string(addr), cidrs))
}

func AddrInCIDRs(addr string, cidrs []string) bool {
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			continue
		}
		prefix := p
		if p.Addr().Is4In6() {
			prefix = netip.PrefixFrom(p.Addr().Unmap(), p.Bits())
		}
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

var notInRe = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_.]*|\[[^\]]*\]|"[^"]*")\s+not\s+in\s+([A-Za-z_][A-Za-z0-9_.]*|\[[^\]]*\]|"[^"]*")`)

func rewriteNotIn(expr string) string {
	return notInRe.ReplaceAllString(expr, "!($1 in $2)")
}

func parseCheck(env *cel.Env, expr string) (*cel.Ast, error) {
	parsed, iss := env.Parse(rewriteNotIn(expr))
	if iss != nil && iss.Err() != nil {
		return nil, fmt.Errorf("parse: %w", iss.Err())
	}
	checked, iss := env.Check(parsed)
	if iss != nil && iss.Err() != nil {
		return nil, fmt.Errorf("check: %w", iss.Err())
	}
	return checked, nil
}
