#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_endian.h"

#define AF_INET   2
#define AF_INET6  10

#define TCP_ESTABLISHED  1
#define TCP_SYN_SENT     2
#define TCP_TIME_WAIT    6
#define TCP_NEW_SYN_RECV 12

#define IPPROTO_TCP 6

char LICENSE[] SEC("license") = "Dual BSD/GPL";

enum conn_evt {
    CONN_EVT_CONNECT_FAILED = 1,
    CONN_EVT_CLOSED         = 2,
    CONN_EVT_RETRANSMIT     = 3,
    CONN_EVT_PROBE          = 4,
};

// Raw tracepoint contexts: the original TP_PROTO arguments as a u64
// array. Unlike the formatted tracepoint events these are stable across
// kernel versions; all payload is read from the socket itself via CO-RE.
struct sock_state_args {
    u64 args[3]; // sk, oldstate, newstate
};

struct sock_args {
    u64 args[1]; // sk
};

typedef struct conn_ctx {
    u64 cgroup_id;
    u64 start_ts;
    u32 pid;
    char comm[16];
    u64 last_probe_ns;
} conn_ctx_t;

// Lifecycle event of a tracked connection with its final stats, all read
// from the socket at the state transition. retransmits is
// tcp_sock.total_retrans: every retransmit on the connection including the
// handshake SYN retries, so on a failed connect it degenerates to the SYN
// retry count. error is sk_err: the failure reason on connect_failed, the
// reset or abort cause on conn_closed, zero on clean closes.
struct conn_event_t {
    u64 ts;
    u32 pid;
    u32 error;
    char comm[16];
    u16 family;
    u16 local_port;
    u16 remote_port;
    u16 type;
    u8 local_ip[16];
    u8 remote_ip[16];
    u64 cgroup_id;
    u64 life_us;
    u32 rtt_us;
    u32 retransmits;
    u32 segs_out;
    u32 snd_cwnd;
    u32 snd_ssthresh;
    u32 snd_wnd;
    u32 rcv_wnd;
    u16 filter_idx;
};

// Address endpoints normalized to 16 byte arrays, 8-byte aligned so the
// CIDR matcher can load them as words.
struct __attribute__((aligned(8))) sock_addrs {
    u8 local[16];
    u8 remote[16];
};

// Event attribution: the socket's own cgroup, with pid/comm from the
// connect-time ctx.
typedef struct attr {
    u64 cgroup_id;
    u32 pid;
    char comm[16];
} attr_t;

// Keyed by sock address. Captured at connect time: the only place where
// pid/comm attribution is reliable. Events are gated on it: only sockets
// seen connecting are reported, accepted and pre-existing ones are not.
// The cgroup itself is read from the socket; this map carries pid/comm
// and the connection lifetime.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, u64);
    __type(value, conn_ctx_t);
} ko_sock_ctx SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
    __type(value, struct conn_event_t);
} ko_events SEC(".maps");

#define KO_MAX_PREDS 32
#define KO_MAX_IPSET 4

#define KO_TRI_FALSE 0
#define KO_TRI_TRUE 1
#define KO_TRI_UNKNOWN 2

#define KO_FILTER_DROP 0xfffd
#define KO_FILTER_UNDECIDED 0xfffe
#define KO_FILTER_UNFILTERED 0xffff

// Predicate kinds, field and comparison ids mirroring pkg/filter.
#define KO_PRED_CMP 1
#define KO_PRED_IPSET 2
#define KO_PRED_ATTR 4
#define KO_PRED_END 5

#define KO_FLD_RTT_US 0
#define KO_FLD_LIFE_US 1
#define KO_FLD_RETRANSMITS 2
#define KO_FLD_SEGS_OUT 3
#define KO_FLD_TYPE 4

#define KO_CMP_EQ 0
#define KO_CMP_NEQ 1
#define KO_CMP_LT 2
#define KO_CMP_LE 3
#define KO_CMP_GT 4
#define KO_CMP_GE 5
#define KO_CMP_IN 6
#define KO_CMP_NOT_IN 7

// One predicate of the compiled CEL filter stream. Filters are laid out
// flat: their predicates followed by an END marker. Attribute predicates
// (namespace, container, pod) are decided through the per-cgroup verdict
// map and stay unknown for cgroups without an entry. Filters that cannot
// be expressed this way emit an END marker flagged userspace and are
// resolved in Go.
struct ko_pred {
    u64 val;    // CMP: constant
    u8 kind;    // CMP, IPSET, IPSET_NOT, ATTR, END
    u8 a;       // CMP: stats field; IPSET: 0 local, 1 remote; ATTR: atom id; END: filter index
    u8 b;       // CMP: comparison kind; ATTR: 0 bit set, 1 bit clear; END: 1 userspace
    u8 n;       // IPSET: prefix count
    u16 plen[KO_MAX_IPSET];
    u8 fam[KO_MAX_IPSET];
    u8 addr[KO_MAX_IPSET][16];
};

struct ko_prog {
    u32 nfilters;
    u32 npreds;
    struct ko_pred preds[KO_MAX_PREDS];
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct ko_prog);
} ko_filter_prog SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} ko_filter_cfg SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, u64);
    __type(value, u64);
} ko_cgroup_verdict SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} ko_filter_drops SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} ko_ringbuf_drops SEC(".maps");

static __always_inline void fill_addrs(struct conn_event_t *e, u16 family, struct sock_addrs *a)
{
    if (family == AF_INET) {
        __builtin_memcpy(e->local_ip, a->local, 4);
        __builtin_memcpy(e->remote_ip, a->remote, 4);
    } else if (family == AF_INET6) {
        __builtin_memcpy(e->local_ip, a->local, 16);
        __builtin_memcpy(e->remote_ip, a->remote, 16);
    }
}

// The socket's cgroup: the id matches bpf_get_current_cgroup_id() at socket
// creation time and stays valid for accepted and pre-existing sockets.
static __always_inline u64 sock_cgroup_id(u64 skaddr)
{
    struct sock *sk = (struct sock *) skaddr;
    struct cgroup *cgrp = NULL;
    BPF_CORE_READ_INTO(&cgrp, sk, sk_cgrp_data.cgroup);
    if (!cgrp)
        return 0;
    u64 id = 0;
    BPF_CORE_READ_INTO(&id, cgrp, kn, id);
    return id;
}

static __always_inline void attr_resolve(attr_t *at, u64 skaddr, conn_ctx_t *cctx)
{
    __builtin_memset(at, 0, sizeof(*at));
    at->cgroup_id = sock_cgroup_id(skaddr);
    if (cctx) {
        at->pid = cctx->pid;
        __builtin_memcpy(at->comm, cctx->comm, sizeof(at->comm));
        if (!at->cgroup_id)
            at->cgroup_id = cctx->cgroup_id;
    }
}

// Reads the event payload from the socket: family, ports and both address
// families. Returns false for unknown families.
static __always_inline bool sock_read_endpoints(u64 skaddr, u16 *family, u16 *sport, u16 *dport, struct sock_addrs *a)
{
    struct sock *sk = (struct sock *) skaddr;

    BPF_CORE_READ_INTO(family, sk, __sk_common.skc_family);
    if (*family != AF_INET && *family != AF_INET6)
        return false;

    // TIME_WAIT and request mini-sockets only carry sock_common: inet_sport
    // lives past their bounds and reads as garbage. Skip them.
    u8 state = 0;
    BPF_CORE_READ_INTO(&state, sk, __sk_common.skc_state);
    if (state == TCP_TIME_WAIT || state == TCP_NEW_SYN_RECV)
        return false;

    // The local port is read from inet_sport: unlike skc_num it survives the
    // socket teardown that precedes the close state transition.
    u16 sport_be = 0;
    BPF_CORE_READ_INTO(&sport_be, (struct inet_sock *) skaddr, inet_sport);
    *sport = bpf_ntohs(sport_be);
    u16 dport_be = 0;
    BPF_CORE_READ_INTO(&dport_be, sk, __sk_common.skc_dport);
    *dport = bpf_ntohs(dport_be);

    if (*family == AF_INET) {
        u32 saddr = 0;
        u32 daddr = 0;
        BPF_CORE_READ_INTO(&saddr, sk, __sk_common.skc_rcv_saddr);
        BPF_CORE_READ_INTO(&daddr, sk, __sk_common.skc_daddr);
        __builtin_memcpy(a->local, &saddr, 4);
        __builtin_memcpy(a->remote, &daddr, 4);
    } else {
        struct in6_addr s6 = {};
        struct in6_addr d6 = {};
        BPF_CORE_READ_INTO(&s6, sk, __sk_common.skc_v6_rcv_saddr);
        BPF_CORE_READ_INTO(&d6, sk, __sk_common.skc_v6_daddr);
        __builtin_memcpy(a->local, &s6, 16);
        __builtin_memcpy(a->remote, &d6, 16);
    }
    return true;
}

// CIDR set membership over one endpoint, comparing words instead of
// bytes: no memory loops, so the verifier's path space stays linear. The
// address words are normalized first: v4-mapped v6 addresses act as IPv4,
// matching the userspace unmap() in the CEL ip_in implementation. Prefix
// bits map to the low plen bits of the little-endian words (the first
// address bits are the first bytes' bits, reversed within each byte, which
// preserves the compared set).
static __always_inline bool ko_ip_in_set(u8 which, u16 family, struct sock_addrs *a, struct ko_pred *p)
{
    const u8 *ip = which == 0 ? a->local : a->remote;
    u64 aw0 = 0, aw1 = 0;
    __builtin_memcpy(&aw0, ip, 8);
    __builtin_memcpy(&aw1, ip + 8, 8);
    bool is4;
    if (family == AF_INET) {
        is4 = true;
    } else if (family == AF_INET6) {
        is4 = aw0 == 0 && (aw1 & 0xffff) == 0 && (u32)((aw1 >> 16) & 0xffff) == 0xffff;
        if (is4)
            aw0 = aw1 >> 32;
    } else {
        return false;
    }

    for (u32 i = 0; i < KO_MAX_IPSET; i++) {
        if (i >= p->n)
            break;
        u32 plen = p->plen[i];
        if (p->fam[i] == 4) {
            if (!is4)
                continue;
            if (plen == 0)
                return true;
            if (plen > 32)
                continue;
            u64 pw = 0;
            __builtin_memcpy(&pw, p->addr[i], 8);
            // 32-bit shift: the high bits fall out of the word, leaving
            // exactly the first plen address bits to compare.
            u32 x = (u32)pw ^ (u32)aw0;
            if ((x << (32 - plen)) == 0)
                return true;
        } else if (p->fam[i] == 6) {
            if (is4)
                continue;
            if (plen == 0)
                return true;
            if (plen > 128)
                continue;
            u64 pw0 = 0, pw1 = 0;
            __builtin_memcpy(&pw0, p->addr[i], 8);
            __builtin_memcpy(&pw1, p->addr[i] + 8, 8);
            if (plen <= 64) {
                if (((pw0 ^ aw0) << (64 - plen)) == 0)
                    return true;
            } else if (pw0 == aw0 && (((pw1 ^ aw1) << (128 - plen)) == 0)) {
                return true;
            }
        }
    }
    return false;
}

// Three-valued walk of the flat predicate stream, mirroring the userspace
// RunPreds. Each filter is the conjunction of its predicates, terminated
// by an END marker: true when every predicate holds, unknown when an
// attribute predicate lacks a cgroup verdict and nothing else is false,
// false when any predicate is provably false. The first true filter wins;
// an unknown filter defers the whole event to userspace because a later
// match could never be proven first. The only loop-carried state is the
// stream index and the verdict, so the verifier prunes states instead of
// exploding on them.
static __always_inline u16 ko_filter_eval(u64 cgroup_id, u32 rtt_us, u64 life_us, u32 retransmits, u32 segs_out, u16 type, u16 family, struct sock_addrs *a)
{
    u32 zero = 0;
    u64 *cfg = bpf_map_lookup_elem(&ko_filter_cfg, &zero);
    if (!cfg || *cfg == 0)
        return KO_FILTER_UNFILTERED;

    struct ko_prog *prog = bpf_map_lookup_elem(&ko_filter_prog, &zero);
    if (!prog)
        return KO_FILTER_UNFILTERED;
    if (prog->nfilters == 0)
        return KO_FILTER_DROP;

    u8 res = KO_TRI_TRUE;
    for (u32 k = 0; k < KO_MAX_PREDS; k++) {
        if (k >= prog->npreds)
            return KO_FILTER_DROP;
        struct ko_pred *p = &prog->preds[k];
        bool ok = true;
        switch (p->kind) {
        case KO_PRED_CMP: {
            u64 v = 0;
            switch (p->a) {
            case KO_FLD_RTT_US:
                v = rtt_us;
                break;
            case KO_FLD_LIFE_US:
                v = life_us;
                break;
            case KO_FLD_RETRANSMITS:
                v = retransmits;
                break;
            case KO_FLD_SEGS_OUT:
                v = segs_out;
                break;
            case KO_FLD_TYPE:
                v = 1ULL << type;
                break;
            }
            switch (p->b) {
            case KO_CMP_EQ:
                ok = v == p->val;
                break;
            case KO_CMP_NEQ:
                ok = v != p->val;
                break;
            case KO_CMP_LT:
                ok = v < p->val;
                break;
            case KO_CMP_LE:
                ok = v <= p->val;
                break;
            case KO_CMP_GT:
                ok = v > p->val;
                break;
            case KO_CMP_GE:
                ok = v >= p->val;
                break;
            case KO_CMP_IN:
                ok = (v & p->val) != 0;
                break;
            case KO_CMP_NOT_IN:
                ok = (v & p->val) == 0;
                break;
            default:
                ok = false;
                break;
            }
            break;
        }
        case KO_PRED_IPSET:
            ok = ko_ip_in_set(p->a, family, a, p) == (p->b == 0);
            break;
        case KO_PRED_ATTR: {
            u64 *verdict = bpf_map_lookup_elem(&ko_cgroup_verdict, &cgroup_id);
            if (!verdict) {
                if (res == KO_TRI_TRUE)
                    res = KO_TRI_UNKNOWN;
                continue;
            }
            bool bit = (*verdict >> p->a) & 1;
            ok = bit == (p->b == 0);
            break;
        }
        case KO_PRED_END:
            if (p->b)
                return KO_FILTER_UNDECIDED;
            if (res == KO_TRI_TRUE)
                return (u16)p->a;
            if (res == KO_TRI_UNKNOWN)
                return KO_FILTER_UNDECIDED;
            res = KO_TRI_TRUE;
            continue;
        default:
            return KO_FILTER_UNDECIDED;
        }
        if (!ok)
            res = KO_TRI_FALSE;
    }
    return KO_FILTER_DROP;
}

static __always_inline void ko_count_filter_drop(void)
{
    u32 zero = 0;
    u64 *drops = bpf_map_lookup_elem(&ko_filter_drops, &zero);
    if (drops)
        *drops += 1;
}

// Emits a connection lifecycle event: attribution from the ctx, identity
// from the already-read endpoints, and the final stats straight from the
// socket. The CEL filter program runs before the ring buffer reserve so
// non-matching events are never produced.
static __always_inline void submit_conn_evt(u64 skaddr, conn_ctx_t *cctx, u16 type, u16 family, u16 sport, u16 dport, struct sock_addrs *a)
{
    attr_t at = {};
    attr_resolve(&at, skaddr, cctx);

    u32 sk_err = 0;
    BPF_CORE_READ_INTO(&sk_err, (struct sock *) skaddr, sk_err);

    struct tcp_sock *tp = (struct tcp_sock *) skaddr;
    u32 srtt_us = 0;
    u32 total_retrans = 0;
    u32 segs_out = 0;
    u32 snd_cwnd = 0;
    u32 snd_ssthresh = 0;
    u32 snd_wnd = 0;
    u32 rcv_wnd = 0;
    BPF_CORE_READ_INTO(&srtt_us, tp, srtt_us);
    BPF_CORE_READ_INTO(&total_retrans, tp, total_retrans);
    BPF_CORE_READ_INTO(&segs_out, tp, segs_out);
    BPF_CORE_READ_INTO(&snd_cwnd, tp, snd_cwnd);
    BPF_CORE_READ_INTO(&snd_ssthresh, tp, snd_ssthresh);
    BPF_CORE_READ_INTO(&snd_wnd, tp, snd_wnd);
    BPF_CORE_READ_INTO(&rcv_wnd, tp, rcv_wnd);

    u64 now = bpf_ktime_get_ns();
    u64 life_us = (now - cctx->start_ts) / 1000;
    u32 rtt_us = srtt_us >> 3;

    u16 filter_idx = ko_filter_eval(at.cgroup_id, rtt_us, life_us, total_retrans, segs_out, type, family, a);
    if (filter_idx == KO_FILTER_DROP) {
        ko_count_filter_drop();
        return;
    }

    struct conn_event_t *e = bpf_ringbuf_reserve(&ko_events, sizeof(*e), 0);
    if (!e) {
        u32 zero = 0;
        u64 *drops = bpf_map_lookup_elem(&ko_ringbuf_drops, &zero);
        if (drops)
            *drops += 1;
        return;
    }
    __builtin_memset(e, 0, sizeof(*e));

    e->ts = now;
    e->life_us = life_us;
    e->type = type;
    e->pid = at.pid;
    e->cgroup_id = at.cgroup_id;
    __builtin_memcpy(e->comm, at.comm, sizeof(e->comm));
    e->family = family;
    e->local_port = sport;
    e->remote_port = dport;
    fill_addrs(e, family, a);
    e->error = sk_err;
    e->rtt_us = rtt_us;
    e->retransmits = total_retrans;
    e->segs_out = segs_out;
    e->snd_cwnd = snd_cwnd;
    e->snd_ssthresh = snd_ssthresh;
    e->snd_wnd = snd_wnd;
    e->rcv_wnd = rcv_wnd;
    e->filter_idx = filter_idx;

    bpf_ringbuf_submit(e, 0);
}

SEC("raw_tp/inet_sock_set_state")
int ko_sock_state(struct sock_state_args *ctx)
{
    u64 skaddr = ctx->args[0];
    int oldstate = (int) ctx->args[1];
    int newstate = (int) ctx->args[2];
    struct sock *sk = (struct sock *) skaddr;

    u16 protocol = 0;
    BPF_CORE_READ_INTO(&protocol, sk, sk_protocol);
    if (protocol != IPPROTO_TCP)
        return 0;

    u16 family = 0;
    u16 sport = 0;
    u16 dport = 0;
    struct sock_addrs addrs = {};
    if (!sock_read_endpoints(skaddr, &family, &sport, &dport, &addrs))
        return 0;

    // * -> TCP_SYN_SENT runs inside the connecting task's connect(2) syscall:
    // the only point where pid/comm attribution is reliable. SYN retries
    // re-enter SYN_SENT from softirq context and must not overwrite the
    // captured task identity.
    if (newstate == TCP_SYN_SENT && oldstate != TCP_SYN_SENT) {
        conn_ctx_t cctx = {};
        u64 pid_tgid = bpf_get_current_pid_tgid();
        cctx.cgroup_id = bpf_get_current_cgroup_id();
        cctx.start_ts = bpf_ktime_get_ns();
        cctx.pid = pid_tgid >> 32;
        bpf_get_current_comm(&cctx.comm, sizeof(cctx.comm));
        bpf_map_update_elem(&ko_sock_ctx, &skaddr, &cctx, BPF_ANY);
        return 0;
    }

    conn_ctx_t *cctxp = bpf_map_lookup_elem(&ko_sock_ctx, &skaddr);
    if (!cctxp)
        return 0;
    conn_ctx_t cctx = *cctxp;

    // Leaving TCP_ESTABLISHED ends the connection: emit its lifetime and
    // final health. This happens before TIME_WAIT so the lifetime is not
    // inflated by the wait period.
    if (oldstate == TCP_ESTABLISHED) {
        bpf_map_delete_elem(&ko_sock_ctx, &skaddr);
        submit_conn_evt(skaddr, &cctx, CONN_EVT_CLOSED, family, sport, dport, &addrs);
        return 0;
    }

    if (oldstate != TCP_SYN_SENT)
        return 0;

    // The connect attempt succeeded: keep the context so the close event
    // can still be attributed.
    if (newstate == TCP_ESTABLISHED)
        return 0;

    // Leaving TCP_SYN_SENT to anything but TCP_ESTABLISHED means the
    // connection attempt failed (RST, timeout, local abort).
    bpf_map_delete_elem(&ko_sock_ctx, &skaddr);
    submit_conn_evt(skaddr, &cctx, CONN_EVT_CONNECT_FAILED, family, sport, dport, &addrs);
    return 0;
}

// Every retransmission of a tracked connection: SYN retries while
// connecting and data retransmits while established. The stats fields are
// the connection's values at retransmit time; the per-connection totals
// on conn_closed and connect_failed stay unchanged.
SEC("raw_tp/tcp_retransmit_skb")
int ko_retransmit(struct sock_args *ctx)
{
    u64 skaddr = ctx->args[0];

    conn_ctx_t *cctxp = bpf_map_lookup_elem(&ko_sock_ctx, &skaddr);
    if (!cctxp)
        return 0;
    conn_ctx_t cctx = *cctxp;

    u16 family = 0;
    u16 sport = 0;
    u16 dport = 0;
    struct sock_addrs addrs = {};
    if (!sock_read_endpoints(skaddr, &family, &sport, &dport, &addrs))
        return 0;

    submit_conn_evt(skaddr, &cctx, CONN_EVT_RETRANSMIT, family, sport, dport, &addrs);
    return 0;
}

#define KO_PROBE_MIN_INTERVAL_NS 100000000ULL

// A congestion-window sample of a tracked connection. The kernel fires
// the tcp_probe tracepoint from inbound processing per segment on some
// kernels, so each socket is rate limited here to one sample per
// KO_PROBE_MIN_INTERVAL_NS; events carry the sender's congestion state
// at sample time.
SEC("raw_tp/tcp_probe")
int ko_probe(struct sock_args *ctx)
{
    u64 skaddr = ctx->args[0];

    conn_ctx_t *cctxp = bpf_map_lookup_elem(&ko_sock_ctx, &skaddr);
    if (!cctxp)
        return 0;
    u64 now = bpf_ktime_get_ns();
    if (now - cctxp->last_probe_ns < KO_PROBE_MIN_INTERVAL_NS)
        return 0;
    cctxp->last_probe_ns = now;
    conn_ctx_t cctx = *cctxp;

    u16 family = 0;
    u16 sport = 0;
    u16 dport = 0;
    struct sock_addrs addrs = {};
    if (!sock_read_endpoints(skaddr, &family, &sport, &dport, &addrs))
        return 0;

    submit_conn_evt(skaddr, &cctx, CONN_EVT_PROBE, family, sport, dport, &addrs);
    return 0;
}

SEC("raw_tp/tcp_destroy_sock")
int ko_destroy_sock(struct sock_args *ctx)
{
    u64 skaddr = ctx->args[0];
    bpf_map_delete_elem(&ko_sock_ctx, &skaddr);
    return 0;
}
