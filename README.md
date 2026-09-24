# Ko

Ko is Kubernetes eBPF based issues detection and root cause tool. Currently, it supports TCP issues detection.

## Install

```sh
 helm upgrade ko --install -n ko \
    oci://ghcr.io/castai/ko-chart/ko \
    --version="0.0.0-dev.anjmao.d906441.1790232416" \
    --create-namespace
```

## Metrics

Ko reports TCP incidents as structured `tcp_event` log lines (logfmt, `ko_`-prefixed fields) meant for Loki ingestion. Only incidents are reported: routine loss recovery such as a single fast retransmit or a single SYN-ACK retry is suppressed.

Example:

```text
time=2026-09-24T06:34:32.604Z level=info msg=tcp_event ko_type=retransmit ko_comm=api ko_pid=2184305 ko_cgroup_id=340879 ko_local_addr=10.20.147.247:46336 ko_remote_addr=10.0.5.24:443 ko_conn_rate=1 ko_conn_total=5773 ko_rtt_avg_us=80362 ko_life_avg_us=34561297 ko_retrans_ratio_pm=0 ko_ca_state=rto ko_seg_len=0 ko_snd_wnd=0 ko_packets_out=1 ko_retrans_count=1 ko_runtime=containerd ko_container_id=50e6b5be58679f2620d8028ff7ed9f870d5f37a4822bbc01e9ce8989e5f1cd0b ko_container=api ko_pod=api-7f8cf8d9cb-68wsv ko_namespace=production
```

### Event types

`ko_type` identifies what happened:

| `ko_type` | Meaning |
| --- | --- |
| `connect_failed` | The connection attempt failed: the peer refused it (RST), it timed out, or it was aborted locally. See `ko_error`. |
| `retransmit` | A data segment was retransmitted under incident conditions: RTO-driven, zero peer window, or already repeated on the same connection. |
| `retransmit_synack` | The server retransmitted a SYN-ACK on its second retry: the client is unresponsive or the path to it is broken. |
| `send_reset` | This host sent a TCP RST. |
| `receive_reset` | The peer sent a TCP RST. |

### Fields

Aggregate fields (`ko_conn_rate`, `ko_conn_total`, `ko_rtt_avg_us`, `ko_life_avg_us`, `ko_retrans_ratio_pm`) are computed over past connections to the same destination (cgroup + PID + source IP + destination IP + destination port), giving each event its baseline.

| Field | Events | Description |
| --- | --- | --- |
| `ko_type` | all | Event type, see above. |
| `ko_comm` | all | Command name of the process that opened the connection. |
| `ko_pid` | all | PID of the process that opened the connection. |
| `ko_cgroup_id` | all | cgroup ID the socket belonged to; used to resolve the container context. |
| `ko_local_addr` | all | Connection local endpoint as `ip:port`. |
| `ko_remote_addr` | all | Connection remote endpoint as `ip:port`. |
| `ko_conn_rate` | all | Connect attempts per second to this destination, from the current or the last completed 1s window, whichever is higher. |
| `ko_conn_total` | all | Total connect attempts to this destination since the agent started. |
| `ko_rtt_avg_us` | all | Average TCP round-trip time in microseconds, from the kernel's smoothed RTT (srtt) of established connections to this destination. |
| `ko_life_avg_us` | all | Average connection lifetime in microseconds, from connect to leaving the established state. |
| `ko_retrans_ratio_pm` | all | Retransmitted segments per mille (per 1000) of sent segments across connections to this destination. |
| `ko_error` | `connect_failed` | Kernel errno for the failure, e.g. `connection refused`; `aborted locally` when the socket was closed before the handshake resolved. |
| `ko_ca_state` | `retransmit` | Congestion control state at retransmit time: `rto` (retransmission timeout fired: the connection stalled), `fast_retransmit` (loss recovery), `cwr`, `disorder` or `open`. |
| `ko_seg_len` | `retransmit` | Size of the retransmitted segment in bytes. |
| `ko_snd_wnd` | `retransmit` | Peer's advertised receive window in bytes; `0` means the peer stopped extending the window (throttled or stuck receiver). |
| `ko_packets_out` | `retransmit` | Segments in flight at retransmit time. |
| `ko_retrans_count` | `retransmit`, `retransmit_synack` | Retransmits the connection (or the handshake, for `retransmit_synack`) already had before this event. |
| `ko_runtime` | containers | Container runtime of the workload, e.g. `containerd`. |
| `ko_container_id` | containers | Full container ID. |
| `ko_container` | containers | Container name. |
| `ko_pod` | containers | Pod name. |
| `ko_namespace` | containers | Pod namespace. |

Container fields are present only when the event's cgroup resolves to a container.

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
