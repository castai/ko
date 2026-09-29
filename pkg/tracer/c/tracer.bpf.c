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

// Tracer filter config, patched at load time (spec.Variables).
volatile const bool ko_filter_ignore_loopback = false;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

enum conn_evt {
    CONN_EVT_CONNECT_FAILED = 1,
    CONN_EVT_CLOSED         = 2,
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
    u32 rtt_us;      // tcp_sock.srtt_us, unshifted; 0 when never sampled
    u32 retransmits; // tcp_sock.total_retrans
    u32 segs_out;    // tcp_sock.segs_out
};

// Address endpoints normalized to 16 byte arrays.
struct sock_addrs {
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

// Loopback peer: the connection never left the host. Covers 127.0.0.0/8,
// ::1 and the v4-mapped 127.0.0.0/104 seen on dual-stack sockets.
static __always_inline bool remote_is_loopback(u16 family, struct sock_addrs *a)
{
    const u8 *r = a->remote;
    if (family == AF_INET)
        return r[0] == 127;
    if (family != AF_INET6)
        return false;
    if (!(r[0] | r[1] | r[2] | r[3] | r[4] | r[5] | r[6] | r[7] | r[8] | r[9] | r[10] | r[11] | r[12] | r[13] | r[14]) && r[15] == 1)
        return true;
    return !(r[0] | r[1] | r[2] | r[3] | r[4] | r[5] | r[6] | r[7] | r[8] | r[9]) &&
           r[10] == 0xff && r[11] == 0xff && r[12] == 127;
}

static __always_inline bool sock_filtered(u16 family, struct sock_addrs *a)
{
    if (ko_filter_ignore_loopback && remote_is_loopback(family, a))
        return true;
    return false;
}

// Emits a connection lifecycle event: attribution from the ctx, identity
// from the already-read endpoints, and the final stats straight from the
// socket.
static __always_inline void submit_conn_evt(u64 skaddr, conn_ctx_t *cctx, u16 type, u16 family, u16 sport, u16 dport, struct sock_addrs *a)
{
    struct conn_event_t *e = bpf_ringbuf_reserve(&ko_events, sizeof(*e), 0);
    if (!e) {
        u32 zero = 0;
        u64 *drops = bpf_map_lookup_elem(&ko_ringbuf_drops, &zero);
        if (drops)
            *drops += 1;
        return;
    }
    __builtin_memset(e, 0, sizeof(*e));

    attr_t at = {};
    attr_resolve(&at, skaddr, cctx);

    e->ts = bpf_ktime_get_ns();
    e->life_us = (e->ts - cctx->start_ts) / 1000;
    e->type = type;
    e->pid = at.pid;
    e->cgroup_id = at.cgroup_id;
    __builtin_memcpy(e->comm, at.comm, sizeof(e->comm));
    e->family = family;
    e->local_port = sport;
    e->remote_port = dport;
    fill_addrs(e, family, a);

    BPF_CORE_READ_INTO(&e->error, (struct sock *) skaddr, sk_err);

    // tp->srtt_us is stored shifted left by TCP_RTT_SHIFT (3) for the
    // EWMA: unshift to real microseconds. A connection that never
    // completed the handshake has no sample and reads zero.
    struct tcp_sock *tp = (struct tcp_sock *) skaddr;
    u32 srtt_us = 0;
    BPF_CORE_READ_INTO(&srtt_us, tp, srtt_us);
    e->rtt_us = srtt_us >> 3;
    BPF_CORE_READ_INTO(&e->retransmits, tp, total_retrans);
    BPF_CORE_READ_INTO(&e->segs_out, tp, segs_out);

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

    if (sock_filtered(family, &addrs))
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

SEC("raw_tp/tcp_destroy_sock")
int ko_destroy_sock(struct sock_args *ctx)
{
    u64 skaddr = ctx->args[0];
    bpf_map_delete_elem(&ko_sock_ctx, &skaddr);
    return 0;
}
