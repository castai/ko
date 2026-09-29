# Ko

Ko is Kubernetes eBPF based issues detection and root cause tool. Currently, it supports TCP issues detection.

## Install

```sh
 helm upgrade ko --install -n ko \
    oci://ghcr.io/castai/ko-chart/ko \
    --version="0.0.0-dev.anjmao.1790674182.3391983" \
    --create-namespace
```

## Metrics

Ko reports TCP connection lifecycle events as structured `tcp_event` log lines (logfmt, `ko_`-prefixed fields) meant for Loki ingestion. Two events cover every tracked connection: when a connect attempt fails and when a connection closes. Each carries the connection's final stats: lifetime, RTT, retransmits, and the socket error when the end was not clean. Only outgoing connections are tracked (sockets the workload opened via connect()); accepted and pre-existing sockets are not.

Example:

```text
time=2026-09-29T11:22:01.605Z level=info msg=tcp_event ko_type=conn_closed ko_comm=api ko_pid=2184305 ko_cgroup_id=340879 ko_local_addr=10.20.147.247:46336 ko_remote_addr=10.0.5.24:443 ko_life_us=1496571 ko_rtt_us=879 ko_retransmits=1 ko_segs_out=48 ko_runtime=containerd ko_container_id=50e6b5be58679f2620d8028ff7ed9f870d5f37a4822bbc01e9ce8989e5f1cd0b ko_container=api ko_pod=api-7f8cf8d9cb-68wsv ko_namespace=production
```

### Event types

`ko_type` identifies what happened:

| `ko_type` | Meaning |
| --- | --- |
| `connect_failed` | The connection attempt failed: the peer refused it (RST), it timed out, or it was aborted locally. See `ko_error`. |
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
