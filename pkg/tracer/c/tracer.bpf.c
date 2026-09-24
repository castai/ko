#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_endian.h"

#define AF_INET   2
#define AF_INET6  10

#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT    2
#define TCP_CLOSE       7
#define TCP_TIME_WAIT   6
#define TCP_NEW_SYN_RECV 12

#define IPPROTO_TCP 6

// Congestion control states (include/net/tcp.h): 0 open, 1 disorder, 2 cwr,
// 3 recovery (fast retransmit), 4 loss (RTO).
#define TCP_CA_Loss 4

// Event suppression thresholds. A single fast retransmit or SYN-ACK retry
// is ordinary loss recovery, not an incident: data retransmits are only
// reported when RTO-driven (ca_state Loss), zero-window (snd_wnd 0) or already
// repeated on the same connection; SYN-ACK retransmits only once, when the
// handshake is truly stuck (second retry: client unresponsive for seconds).
#define DATA_RTX_MIN 3
#define SYNACK_STUCK_RETRANS 1

// Tracer filter config, patched at load time (spec.Variables).
volatile const bool ko_filter_ignore_loopback = false;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

enum conn_evt {
    CONN_EVT_CONNECT_FAILED    = 1,
    CONN_EVT_RETRANSMIT         = 2,
    CONN_EVT_RETRANSMIT_SYNACK = 3,
    CONN_EVT_SEND_RESET        = 4,
    CONN_EVT_RECEIVE_RESET     = 5,
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

struct sk_skb_args {
    u64 args[2]; // sk, skb
};

struct sk_req_args {
    u64 args[2]; // sk, req
};

typedef struct conn_ctx {
    u64 cgroup_id;
    u64 start_ts;
    u32 pid;
    char comm[16];
} conn_ctx_t;

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
    u64 conn_count;
    u32 conn_rate;
    u32 rtt_avg_us;
    u64 life_avg_us;
    // Retransmit payload, zero on other event types. rtx_count is the
    // retransmits the connection already had before this one (SYN-ACK
    // retries for retransmit_synack).
    u32 seg_len;     // retransmitted skb->len
    u32 snd_wnd;     // peer's advertised window at retransmit time
    u32 packets_out; // segments in flight at retransmit time
    u32 rtx_ratio_pm; // retransmitted/sent segments, per-mille, over the stats key
    u8 ca_state;    // icsk_ca_state at retransmit time: 4=Loss (RTO), 3=Recovery (fast)
    u8 rtx_count;
    u8 _pad[2];
};

// Socket statistics are aggregated per destination to give single events
// their baseline: how many connections the process makes to this peer, at
// what rate, and how healthy those connections look.
typedef struct stats_key {
    u64 cgroup_id;
    u32 pid;
    u16 family;
    u16 dst_port;
    u8 src_ip[16];
    u8 dst_ip[16];
} stats_key_t;

typedef struct stats {
    u64 conn_count;
    u64 window_start;
    u32 conn_rate;
    u32 conn_rate_prev; // last completed 1s window
    u64 rtt_sum_us;
    u64 rtt_count;
    u64 life_sum_ns;
    u64 life_count;
    u64 rtx_sum;  // sum of tcp_sock.total_retrans at close
    u64 segs_sum; // sum of tcp_sock.segs_out at close
} stats_t;

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
    __uint(max_entries, 1 << 17);
    __type(value, struct conn_event_t);
} ko_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, stats_key_t);
    __type(value, stats_t);
} ko_sock_stats SEC(".maps");

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

static __always_inline void stats_key_fill(stats_key_t *k, u64 cgroup_id, u32 pid, u16 family, u16 dport, struct sock_addrs *a)
{
    k->cgroup_id = cgroup_id;
    k->pid = pid;
    k->family = family;
    k->dst_port = dport;
    if (family == AF_INET) {
        __builtin_memcpy(k->src_ip, a->local, 4);
        __builtin_memcpy(k->dst_ip, a->remote, 4);
    } else if (family == AF_INET6) {
        __builtin_memcpy(k->src_ip, a->local, 16);
        __builtin_memcpy(k->dst_ip, a->remote, 16);
    }
}

static __always_inline void stats_count_attempt(stats_key_t *k)
{
    stats_t *s = bpf_map_lookup_elem(&ko_sock_stats, k);
    if (!s) {
        stats_t zero = {};
        bpf_map_update_elem(&ko_sock_stats, k, &zero, BPF_NOEXIST);
        s = bpf_map_lookup_elem(&ko_sock_stats, k);
        if (!s)
            return;
    }
    // The window rollover is not atomic across CPUs: conn_rate is
    // approximate by design.
    u64 now = bpf_ktime_get_ns();
    if (now - s->window_start >= 1000000000) {
        s->conn_rate_prev = s->conn_rate;
        s->window_start = now;
        s->conn_rate = 0;
    }
    __sync_fetch_and_add(&s->conn_rate, 1);
    __sync_fetch_and_add(&s->conn_count, 1);
}

static __always_inline void stats_into_event(stats_key_t *k, struct conn_event_t *e)
{
    stats_t *s = bpf_map_lookup_elem(&ko_sock_stats, k);
    if (!s)
        return;
    e->conn_count = s->conn_count;
    // Mid-window the current count is partial: report whichever of the
    // current or the last completed window shows the higher rate.
    e->conn_rate = s->conn_rate > s->conn_rate_prev ? s->conn_rate : s->conn_rate_prev;
    if (s->rtt_count)
        e->rtt_avg_us = s->rtt_sum_us / s->rtt_count;
    if (s->life_count)
        e->life_avg_us = s->life_sum_ns / s->life_count / 1000;
    if (s->segs_sum)
        e->rtx_ratio_pm = s->rtx_sum * 1000 / s->segs_sum;
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

// Fills attribution and aggregate fields shared by all event types.
static __always_inline void event_common(struct conn_event_t *e, attr_t *at, u16 type, u16 family, u16 sport, u16 dport, struct sock_addrs *a)
{
    e->pid = at->pid;
    e->cgroup_id = at->cgroup_id;
    __builtin_memcpy(e->comm, at->comm, sizeof(e->comm));
    e->type = type;
    e->family = family;
    e->local_port = sport;
    e->remote_port = dport;
    fill_addrs(e, family, a);

    stats_key_t k = {};
    stats_key_fill(&k, at->cgroup_id, at->pid, family, dport, a);
    stats_into_event(&k, e);
}

// Base for events raised on the raw tcp:* tracepoints. Only sockets seen
// connecting earlier are reported: without pid/comm an event cannot be
// correlated to a workload.
static __always_inline void submit_sk_evt(u64 skaddr, u16 type)
{
    if (!skaddr)
        return;

    u16 family = 0;
    u16 sport = 0;
    u16 dport = 0;
    struct sock_addrs addrs = {};
    if (!sock_read_endpoints(skaddr, &family, &sport, &dport, &addrs))
        return;

    if (sock_filtered(family, &addrs))
        return;

    conn_ctx_t *cctx = bpf_map_lookup_elem(&ko_sock_ctx, &skaddr);
    if (!cctx)
        return;
    attr_t at = {};
    attr_resolve(&at, skaddr, cctx);

    // bpf_ringbuf_reserve does not zero the record: stale bytes from
    // previously consumed records leak into fields this path does not set.
    struct conn_event_t *e = bpf_ringbuf_reserve(&ko_events, sizeof(*e), 0);
    if (!e)
        return;
    __builtin_memset(e, 0, sizeof(*e));

    event_common(e, &at, type, family, sport, dport, &addrs);

    e->ts = bpf_ktime_get_ns();
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

        stats_key_t k = {};
        stats_key_fill(&k, cctx.cgroup_id, cctx.pid, family, dport, &addrs);
        stats_count_attempt(&k);
        return 0;
    }

    conn_ctx_t *cctx = bpf_map_lookup_elem(&ko_sock_ctx, &skaddr);
    if (!cctx)
        return 0;

    u64 start_ts = cctx->start_ts;
    attr_t at = {};
    attr_resolve(&at, skaddr, cctx);

    // Leaving TCP_ESTABLISHED ends the connection: record its lifetime and
    // final health into the stats. This happens before TIME_WAIT so the
    // lifetime is not inflated by the wait period.
    if (oldstate == TCP_ESTABLISHED) {
        bpf_map_delete_elem(&ko_sock_ctx, &skaddr);

        stats_key_t k = {};
        stats_key_fill(&k, at.cgroup_id, at.pid, family, dport, &addrs);
        stats_t *s = bpf_map_lookup_elem(&ko_sock_stats, &k);
        if (s) {
            __sync_fetch_and_add(&s->life_sum_ns, bpf_ktime_get_ns() - start_ts);
            __sync_fetch_and_add(&s->life_count, 1);

            u32 srtt_us = 0;
            u32 total_retrans = 0;
            u32 segs_out = 0;
            struct tcp_sock *tp = (struct tcp_sock *) skaddr;
            BPF_CORE_READ_INTO(&srtt_us, tp, srtt_us);
            BPF_CORE_READ_INTO(&total_retrans, tp, total_retrans);
            BPF_CORE_READ_INTO(&segs_out, tp, segs_out);
            if (srtt_us) {
                // tp->srtt_us is stored shifted left by TCP_RTT_SHIFT (3)
                // for the EWMA: unshift to real microseconds.
                __sync_fetch_and_add(&s->rtt_sum_us, srtt_us >> 3);
                __sync_fetch_and_add(&s->rtt_count, 1);
            }
            __sync_fetch_and_add(&s->rtx_sum, (u64) total_retrans);
            __sync_fetch_and_add(&s->segs_sum, (u64) segs_out);
        }
        return 0;
    }

    if (oldstate != TCP_SYN_SENT)
        return 0;

    // The connect attempt succeeded: keep the context so later retransmit
    // and reset events on the connection can still be attributed.
    if (newstate == TCP_ESTABLISHED)
        return 0;

    // Leaving TCP_SYN_SENT to anything but TCP_ESTABLISHED means the
    // connection attempt failed (RST, timeout, local abort).
    bpf_map_delete_elem(&ko_sock_ctx, &skaddr);

    struct conn_event_t *e = bpf_ringbuf_reserve(&ko_events, sizeof(*e), 0);
    if (!e)
        return 0;
    __builtin_memset(e, 0, sizeof(*e));

    event_common(e, &at, CONN_EVT_CONNECT_FAILED, family, sport, dport, &addrs);

    int sk_err = 0;
    BPF_CORE_READ_INTO(&sk_err, sk, sk_err);
    e->error = (u32) sk_err;

    e->ts = bpf_ktime_get_ns();
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("raw_tp/tcp_retransmit_skb")
int ko_rtx_skb(struct sk_skb_args *ctx)
{
    u64 skaddr = ctx->args[0];
    u64 skbaddr = ctx->args[1];
    if (!skaddr)
        return 0;

    u16 family = 0;
    u16 sport = 0;
    u16 dport = 0;
    struct sock_addrs addrs = {};
    if (!sock_read_endpoints(skaddr, &family, &sport, &dport, &addrs))
        return 0;

    if (sock_filtered(family, &addrs))
        return 0;

    conn_ctx_t *cctx = bpf_map_lookup_elem(&ko_sock_ctx, &skaddr);
    if (!cctx)
        return 0;

    // RTO vs fast retransmit discriminator: TCP_CA_Loss (4) means the RTO
    // fired (stall/blackhole), TCP_CA_Recovery (3) a fast retransmit
    // (ordinary loss). Bitfields need the probed CO-RE read.
    u8 ca_state = (u8) BPF_CORE_READ_BITFIELD_PROBED((struct inet_connection_sock *) skaddr, icsk_ca_state);

    // Receiver pressure: zero peer window with segments in flight means the
    // peer is not extending the window (throttled receiver).
    struct tcp_sock *tp = (struct tcp_sock *) skaddr;
    u32 total_retrans = 0;
    u32 snd_wnd = 0;
    u32 packets_out = 0;
    BPF_CORE_READ_INTO(&total_retrans, tp, total_retrans);
    BPF_CORE_READ_INTO(&snd_wnd, tp, snd_wnd);
    BPF_CORE_READ_INTO(&packets_out, tp, packets_out);

    u32 seg_len = 0;
    if (skbaddr) {
        struct sk_buff *skb = (struct sk_buff *) skbaddr;
        BPF_CORE_READ_INTO(&seg_len, skb, len);
    }

    // Ordinary fast retransmits are routine loss recovery: report only
    // RTO-driven retransmits, zero peer windows and connections already
    // carrying several retransmits.
    if (ca_state != TCP_CA_Loss && snd_wnd != 0 && total_retrans < DATA_RTX_MIN)
        return 0;

    attr_t at = {};
    attr_resolve(&at, skaddr, cctx);

    struct conn_event_t *e = bpf_ringbuf_reserve(&ko_events, sizeof(*e), 0);
    if (!e)
        return 0;
    __builtin_memset(e, 0, sizeof(*e));

    event_common(e, &at, CONN_EVT_RETRANSMIT, family, sport, dport, &addrs);

    e->ca_state = ca_state;
    e->seg_len = seg_len;
    e->snd_wnd = snd_wnd;
    e->packets_out = packets_out;
    e->rtx_count = (u8) total_retrans;

    e->ts = bpf_ktime_get_ns();
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("raw_tp/tcp_retransmit_synack")
int ko_rtx_synack(struct sk_req_args *ctx)
{
    // The sock is the listener with no peer endpoints: the remote is read
    // from the request socket instead.
    if (!ctx->args[0] || !ctx->args[1])
        return 0;

    u64 skaddr = ctx->args[0];
    u64 reqaddr = ctx->args[1];

    struct request_sock *req = (struct request_sock *) reqaddr;

    // A single SYN-ACK retry is one lost packet; a second means the client
    // is unresponsive (gone, or the path is broken). Report only that one.
    u8 num_retrans = 0;
    BPF_CORE_READ_INTO(&num_retrans, req, num_retrans);
    if (num_retrans != SYNACK_STUCK_RETRANS)
        return 0;

    u16 family = 0;
    u16 sport = 0;
    u16 dport = 0;
    struct sock_addrs addrs = {};
    if (!sock_read_endpoints(skaddr, &family, &sport, &dport, &addrs))
        return 0;

    if (family == AF_INET) {
        u32 rmt = 0;
        BPF_CORE_READ_INTO(&rmt, req, __req_common.skc_daddr);
        __builtin_memcpy(addrs.remote, &rmt, 4);
    } else {
        struct in6_addr rmt = {};
        BPF_CORE_READ_INTO(&rmt, req, __req_common.skc_v6_daddr);
        __builtin_memcpy(addrs.remote, &rmt, 16);
    }
    u16 rmt_port_be = 0;
    BPF_CORE_READ_INTO(&rmt_port_be, req, __req_common.skc_dport);
    dport = bpf_ntohs(rmt_port_be);

    if (sock_filtered(family, &addrs))
        return 0;

    attr_t at = {};
    attr_resolve(&at, skaddr, NULL);

    struct conn_event_t *e = bpf_ringbuf_reserve(&ko_events, sizeof(*e), 0);
    if (!e)
        return 0;
    __builtin_memset(e, 0, sizeof(*e));

    event_common(e, &at, CONN_EVT_RETRANSMIT_SYNACK, family, sport, dport, &addrs);

    e->rtx_count = num_retrans;

    e->ts = bpf_ktime_get_ns();
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("raw_tp/tcp_send_reset")
int ko_send_reset(struct sk_skb_args *ctx)
{
    // RSTs generated without a socket carry no payload we can read.
    submit_sk_evt(ctx->args[0], CONN_EVT_SEND_RESET);
    return 0;
}

SEC("raw_tp/tcp_receive_reset")
int ko_recv_reset(struct sock_args *ctx)
{
    submit_sk_evt(ctx->args[0], CONN_EVT_RECEIVE_RESET);
    return 0;
}

SEC("raw_tp/tcp_destroy_sock")
int ko_destroy_sock(struct sock_args *ctx)
{
    u64 skaddr = ctx->args[0];
    bpf_map_delete_elem(&ko_sock_ctx, &skaddr);
    return 0;
}
