# Ko

Ko is Kubernetes eBPF based issues detection and root cause tool. Currently, it supports TCP issues detection.

## Install

```sh
  helm upgrade ko --install -n ko \
    oci://ghcr.io/castai/ko-chart/ko \
    --version="0.0.0-dev.1790675576.anjmao.e0125e9" \
    --create-namespace
```

## Metrics

Ko reports TCP connection lifecycle events as structured `tcp_event` log lines (logfmt, `ko_`-prefixed fields) meant for Loki ingestion. Two events cover every tracked connection: when a connect attempt fails and when a connection closes. Each carries the connection's final stats: lifetime, RTT, retransmits, and the socket error when the end was not clean. Only outgoing connections are tracked (sockets the workload opened via connect()); accepted and pre-existing sockets are not.

### Filters

Optional named CEL expressions select which events are reported. Filters are an ordered list; an event carries the first matching filter as `ko_filter`, and events matching no filter are dropped. Expressions decide in the eBPF program whenever possible: kernel-side facts (stats, CIDR matches) and per-cgroup verdicts for namespace/container/pod predicates are evaluated before the event is produced.

Supported fields: `ko_namespace`, `ko_container`, `ko_pod`, `ko_rtt_us`, `ko_life_us`, `ko_retransmits`, `ko_segs_out`, `ip_in(ko_local_addr, cidrs)`, `ip_in(ko_remote_addr, cidrs)`, with the built-in CIDR lists `ko_loopback_cidrs` and `ko_private_cidrs`. Anything else fails validation at startup.

Expressions that are pure conjunctions of the supported comparisons compile to an eBPF predicate stream; anything else (e.g. top-level `||`) is marked userspace and resolved exactly in Go, as is every event whose cgroup verdict is not yet known. The `ko_filter_events_total` metric's `passed_bpf`/`passed_userspace`/`dropped_bpf`/`dropped_userspace` decisions show the split. Setting `verify: true` re-evaluates every eBPF-decided event in userspace and counts disagreements on `ko_filter_verify_mismatches_total`, which must stay zero.

```yaml
tracer:
  filters:
    cel:
      - name: prod-pod-degradation
        expr: ko_namespace == "production" && ko_rtt_us > 100000
      - name: noisy-neighbors
        expr: ko_container not in ["app1", "app2"] || ip_in(ko_remote_addr, ko_private_cidrs)
```

Excluding loopback peers (the old `ignoreLoopback` toggle) is now a regular filter: `!ip_in(ko_remote_addr, ko_loopback_cidrs)`.

Example:

```text
time=2026-09-29T11:22:01.605Z level=info msg=tcp_event ko_type=conn_closed ko_comm=api ko_pid=2184305 ko_cgroup_id=340879 ko_local_addr=10.20.147.247:46336 ko_remote_addr=10.0.5.24:443 ko_life_us=1496571 ko_rtt_us=879 ko_retransmits=1 ko_segs_out=48 ko_runtime=containerd ko_container_id=50e6b5be58679f2620d8028ff7ed9f870d5f37a4822bbc01e9ce8989e5f1cd0b ko_container=api ko_pod=api-7f8cf8d9cb-68wsv ko_namespace=production
```

### Event types

`ko_type` identifies what happened:

| `ko_type` | Meaning |
| --- | --- |
| `conn_failed` | The connection attempt failed: the peer refused it (RST), it timed out, or it was aborted locally. See `ko_error`. |
| `conn_closed` | The connection ended: either side closed it, or it was aborted (reset, timeout). `ko_error` carries the cause when the close was not clean. |

### Fields

Stats fields are per connection: every counter is the final value read from the socket at the event.

| Field | Events | Description |
| --- | --- | --- |
| `ko_type` | all | Event type, see above. |
| `ko_comm` | all | Command name of the process that opened the connection. |
| `ko_pid` | all | PID of the process that opened the connection. |
| `ko_cgroup_id` | all | cgroup ID the socket belonged to; used to resolve the container context. |
| `ko_local_addr` | all | Connection local endpoint as `ip:port`. |
| `ko_remote_addr` | all | Connection remote endpoint as `ip:port`. |
| `ko_life_us` | all | Connection duration in microseconds, from the connect attempt to the event. |
| `ko_rtt_us` | all | Kernel's smoothed RTT (srtt) of the connection in microseconds; `0` when the handshake never completed. |
| `ko_retransmits` | all | Total retransmits on the connection: data retransmits plus handshake SYN retries on `conn_closed`, just the SYN retries on `connect_failed`. |
| `ko_segs_out` | all | Total segments the connection sent; the denominator for `ko_retransmits`. |
| `ko_error` | `connect_failed`; `conn_closed` when not clean | Kernel errno for the failure or the abort/reset cause, e.g. `connection refused`, `connection reset by peer`; omitted on clean closes. |
| `ko_filter` | when CEL filters match | Name of the first matching CEL filter. |
| `ko_runtime` | containers | Container runtime of the workload, e.g. `containerd`. |
| `ko_container_id` | containers | Full container ID. |
| `ko_container` | containers | Container name. |
| `ko_pod` | containers | Pod name. |
| `ko_namespace` | containers | Pod namespace. |

Container fields are present only when the event's cgroup resolves to a container.

### Metrics

`metrics.addr` serves Prometheus metrics. The agent enables kernel-side BPF program runtime accounting (Linux 5.8+), which adds a small per-run cost to every BPF program on the node while the agent runs.

`ko_ebpf_prog_runtime_ns_total{prog,tag,type}` and `ko_ebpf_prog_runs_total` cover **every** BPF program on the node — ko's own (`ko_sock_state`, `ko_destroy_sock`) next to the rest (Cilium, other tracers) — so the tool's overhead can be compared with its neighbors:

```promql
# CPU consumed by each program
sum by (prog) (rate(ko_ebpf_prog_runtime_ns_total[5m]))

# Average time per invocation
sum by (prog) (rate(ko_ebpf_prog_runtime_ns_total[5m]))
  / sum by (prog) (rate(ko_ebpf_prog_runs_total[5m]))
```

### Loki

By default events are exported to stdout. Here are some example queries to get started.

Rate by event type
```
sum by (ko_type) (
  rate(
    {namespace="ko"} | logfmt [1m]
  )
)
```

Grep all metrics

```
{namespace="ko"}
```
