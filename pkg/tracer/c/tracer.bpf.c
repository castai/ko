#include "vmlinux.h"
#include "bpf/bpf_helpers.h"
#include "bpf/bpf_core_read.h"
#include "bpf/bpf_endian.h"

#define AF_INET   2
#define AF_INET6  10

#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT    2
#define TCP_CLOSE       7

#define IPPROTO_TCP 6

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
    u32 _pad;
    u64 rtt_sum_us;
    u64 rtt_count;
    u64 life_sum_ns;
    u64 life_count;
} stats_t;

// Address endpoints normalized to 16 byte arrays.
struct sock_addrs {
    u8 local[16];
    u8 remote[16];
};

// Keyed by sock address. Captured at connect time, kept while the
// connection is established to attribute later events and measure its life.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, u64);
    __type(value, conn_ctx_t);
} ko_sock_ctx SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
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
    u64 now = bpf_ktime_get_ns();
    if (now - s->window_start >= 1000000000) {
        s->window_start = now;
        s->conn_rate = 0;
    }
    s->conn_rate++;
    s->conn_count++;
}

static __always_inline void stats_into_event(stats_key_t *k, struct conn_event_t *e)
{
    stats_t *s = bpf_map_lookup_elem(&ko_sock_stats, k);
    if (!s)
        return;
    e->conn_count = s->conn_count;
    e->conn_rate = s->conn_rate;
    if (s->rtt_count)
        e->rtt_avg_us = s->rtt_sum_us / s->rtt_count;
    if (s->life_count)
        e->life_avg_us = s->life_sum_ns / s->life_count / 1000;
}

// Reads the event payload from the socket: family, ports and both address
// families. Returns false for unknown families.
static __always_inline bool sock_read_endpoints(u64 skaddr, u16 *family, u16 *sport, u16 *dport, struct sock_addrs *a)
{
    struct sock *sk = (struct sock *) skaddr;

    BPF_CORE_READ_INTO(family, sk, __sk_common.skc_family);
    if (*family != AF_INET && *family != AF_INET6)
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

// Base for events raised on the raw tcp:* tracepoints: enrich with pid/comm
// when the sock was seen connecting earlier, otherwise pid stays zero.
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

    conn_ctx_t *cctx = bpf_map_lookup_elem(&ko_sock_ctx, &skaddr);

    struct conn_event_t *e = bpf_ringbuf_reserve(&ko_events, sizeof(*e), 0);
    if (!e)
        return;

    u32 pid = 0;
    u64 cgroup_id = 0;
    if (cctx) {
        pid = cctx->pid;
        cgroup_id = cctx->cgroup_id;
        e->pid = pid;
        e->cgroup_id = cgroup_id;
        __builtin_memcpy(e->comm, cctx->comm, sizeof(e->comm));
    }

    e->type = type;
    e->family = family;
    e->local_port = sport;
    e->remote_port = dport;
    fill_addrs(e, family, &addrs);

    stats_key_t k = {};
    stats_key_fill(&k, cgroup_id, pid, family, dport, &addrs);
    stats_into_event(&k, e);

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

    // * -> TCP_SYN_SENT runs inside the connecting task's connect(2) syscall:
    // the only point where pid/comm attribution is reliable. The failure
    // transition may later fire from softirq context.
    if (newstate == TCP_SYN_SENT) {
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

    u32 pid = cctx->pid;
    u64 cgroup_id = cctx->cgroup_id;
    u64 start_ts = cctx->start_ts;
    char comm[16];
    __builtin_memcpy(comm, cctx->comm, sizeof(comm));

    // Leaving TCP_ESTABLISHED ends the connection: record its lifetime and
    // final RTT. This happens before TIME_WAIT so the lifetime is not
    // inflated by the wait period.
    if (oldstate == TCP_ESTABLISHED) {
        bpf_map_delete_elem(&ko_sock_ctx, &skaddr);

        stats_key_t k = {};
        stats_key_fill(&k, cgroup_id, pid, family, dport, &addrs);
        stats_t *s = bpf_map_lookup_elem(&ko_sock_stats, &k);
        if (s) {
            s->life_sum_ns += bpf_ktime_get_ns() - start_ts;
            s->life_count++;

            u32 srtt_us = 0;
            struct tcp_sock *tp = (struct tcp_sock *) skaddr;
            BPF_CORE_READ_INTO(&srtt_us, tp, srtt_us);
            if (srtt_us) {
                s->rtt_sum_us += srtt_us;
                s->rtt_count++;
            }
        }
        return 0;
    }

    if (oldstate != TCP_SYN_SENT)
        return 0;

    // The connect attempt succeeded: keep the context so later retransmit
    // and reset events on the connection can still be attributed.
    if (newstate == TCP_ESTABLISHED)
        return 0;

    bpf_map_delete_elem(&ko_sock_ctx, &skaddr);

    // Leaving TCP_SYN_SENT to anything but TCP_ESTABLISHED means the
    // connection attempt failed (RST, timeout, local abort).
    struct conn_event_t *e = bpf_ringbuf_reserve(&ko_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->pid = pid;
    e->cgroup_id = cgroup_id;
    __builtin_memcpy(e->comm, comm, sizeof(e->comm));
    e->type = CONN_EVT_CONNECT_FAILED;
    e->family = family;
    e->local_port = sport;
    e->remote_port = dport;
    fill_addrs(e, family, &addrs);

    s16 sk_err = 0;
    BPF_CORE_READ_INTO(&sk_err, sk, sk_err);
    e->error = (u32) sk_err;

    stats_key_t k = {};
    stats_key_fill(&k, cgroup_id, pid, family, dport, &addrs);
    stats_into_event(&k, e);

    e->ts = bpf_ktime_get_ns();
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("raw_tp/tcp_retransmit_skb")
int ko_rtx_skb(struct sk_skb_args *ctx)
{
    submit_sk_evt(ctx->args[0], CONN_EVT_RETRANSMIT);
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

    u16 family = 0;
    u16 sport = 0;
    u16 dport = 0;
    struct sock_addrs addrs = {};
    if (!sock_read_endpoints(skaddr, &family, &sport, &dport, &addrs))
        return 0;

    struct request_sock *req = (struct request_sock *) reqaddr;
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

    struct conn_event_t *e = bpf_ringbuf_reserve(&ko_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = CONN_EVT_RETRANSMIT_SYNACK;
    e->family = family;
    e->local_port = sport;
    e->remote_port = dport;
    fill_addrs(e, family, &addrs);

    stats_key_t k = {};
    stats_key_fill(&k, 0, 0, family, dport, &addrs);
    stats_into_event(&k, e);

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
