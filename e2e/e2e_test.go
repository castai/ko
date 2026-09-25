//go:build e2e

package e2e

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	kubeContext = "kind-ko-e2e"
	namespace   = "ko-e2e"
	release     = "ko"
)

func TestKo(t *testing.T) {
	imageRepo := envOrDefault("E2E_IMAGE_REPO", "ko-e2e")
	imageTag := envOrDefault("E2E_IMAGE_TAG", "local")

	installChart(t, imageRepo, imageTag)

	t.Run("tracer exports connect failures", func(t *testing.T) {
		// A pod constantly attempting connections to a closed port on its own
		// loopback generates connect failures attributed to its cgroup.
		runConnectorPod(t)
		defer kubectl(t, "delete", "pod", "--ignore-not-found", "bad-connector")

		want := []string{
			"msg=tcp_event",
			"type=connect_failed",
			"pod=bad-connector",
			"namespace=" + namespace,
			"container=bad-connector",
			"remote_addr=127.0.0.1:9999",
		}

		deadline := time.Now().Add(3 * time.Minute)
		for time.Now().Before(deadline) {
			logs := koLogs(t)
			for _, line := range strings.Split(logs, "\n") {
				if containsAll(line, want) {
					t.Logf("found event: %s", line)
					return
				}
			}
			time.Sleep(5 * time.Second)
		}

		t.Fatalf("no exported event found in ko logs:\n%s", koLogs(t))
	})

	t.Run("conntest mesh connected", func(t *testing.T) {
		pods := koPodList(t)
		if len(pods) != 2 {
			t.Fatalf("expected 2 ko pods on 2 nodes, got %d: %+v", len(pods), pods)
		}
		if pods[0].Node == pods[1].Node {
			t.Fatalf("ko pods must run on different nodes: %+v", pods)
		}

		runHelperPod(t)
		defer kubectl(t, "delete", "pod", "--ignore-not-found", "metrics-helper")

		deadline := time.Now().Add(3 * time.Minute)
		for time.Now().Before(deadline) {
			if conntestMeshHealthy(t, pods) {
				t.Logf("conntest mesh connected between %s and %s", pods[0].Node, pods[1].Node)
				return
			}
			time.Sleep(5 * time.Second)
		}

		for _, p := range pods {
			t.Logf("metrics of %s:\n%s", p.Name, fetchMetrics(p.IP))
		}
		t.Fatal("conntest metrics not populated on all pods")
	})
}

func conntestMeshHealthy(t *testing.T, pods []koPod) bool {
	t.Helper()

	for _, src := range pods {
		body := fetchMetrics(src.IP)
		if body == "" {
			return false
		}
		for _, dst := range pods {
			if dst.Name == src.Name {
				continue
			}
			if v, ok := metricValue(body, "ko_conntest_state", map[string]string{"state": "connected", "target_pod": dst.Name}); !ok || v != 1 {
				return false
			}
			if p, ok := metricValue(body, "ko_conntest_pings_total", map[string]string{"target_pod": dst.Name}); !ok || p < 1 {
				return false
			}
			if _, ok := metricValue(body, "ko_conntest_rtt_seconds", map[string]string{"target_pod": dst.Name}); !ok {
				return false
			}
		}
	}
	return true
}

type koPod struct {
	Name string
	IP   string
	Node string
}

func koPodList(t *testing.T) []koPod {
	t.Helper()

	out := kubectl(t, "get", "pods", "-l", "app.kubernetes.io/name="+release,
		"-o", `jsonpath={range .items[*]}{.metadata.name}{" "}{.status.podIP}{" "}{.spec.nodeName}{"\n"}{end}`)

	var pods []koPod
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 3 {
			pods = append(pods, koPod{Name: fields[0], IP: fields[1], Node: fields[2]})
		}
	}
	return pods
}

func runHelperPod(t *testing.T) {
	t.Helper()

	kubectl(t, "delete", "pod", "--ignore-not-found", "metrics-helper")
	kubectl(t, "run", "metrics-helper",
		"--image=busybox",
		"--restart=Never",
		"--", "sh", "-c", "sleep 600",
	)
	kubectl(t, "wait", "--for=condition=Ready", "--timeout=2m", "pod/metrics-helper")
}

func fetchMetrics(podIP string) string {
	out, err := kubectlSoft("exec", "metrics-helper", "--", "wget", "-qO-", "http://"+podIP+":9081/metrics")
	if err != nil {
		return ""
	}
	return out
}

func metricValue(body, name string, want map[string]string) (float64, bool) {
	for _, line := range strings.Split(body, "\n") {
		if !strings.HasPrefix(line, name+"{") {
			continue
		}
		closeIdx := strings.LastIndexByte(line, '}')
		if closeIdx < 0 {
			continue
		}
		labels := map[string]string{}
		for _, pair := range strings.Split(line[len(name)+1:closeIdx], ",") {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) == 2 {
				labels[kv[0]] = strings.Trim(kv[1], `"`)
			}
		}
		matched := true
		for k, v := range want {
			if labels[k] != v {
				matched = false
				break
			}
		}
		if !matched {
			continue
		}
		value, err := strconv.ParseFloat(strings.TrimSpace(line[closeIdx+1:]), 64)
		if err != nil {
			return 0, false
		}
		return value, true
	}
	return 0, false
}

func kubectlSoft(args ...string) (string, error) {
	args = append([]string{"--context", kubeContext, "-n", namespace}, args...)
	out, err := exec.Command("kubectl", args...).CombinedOutput()
	return string(out), err
}

func installChart(t *testing.T, imageRepo, imageTag string) {
	t.Helper()

	args := []string{
		"--kube-context", kubeContext,
		"upgrade", "--install", release, "../charts/ko",
		"--namespace", namespace, "--create-namespace",
		"-f", "values.yaml",
		"--set", "image.repository=" + imageRepo,
		"--set", "image.tag=" + imageTag,
		"--set", "jsonLog=false",
		"--wait", "--timeout", "5m",
	}
	if out, err := exec.Command("helm", args...).CombinedOutput(); err != nil {
		t.Fatalf("helm install: %v\n%s", err, out)
	}

	// Wait for the agent pod: it only starts exporting once its eBPF
	// programs are loaded.
	kubectl(t, "wait", "--for=condition=Ready", "--timeout=2m", "pod", "-l", "app.kubernetes.io/name="+release)
}

func runConnectorPod(t *testing.T) {
	t.Helper()

	kubectl(t, "delete", "pod", "--ignore-not-found", "bad-connector")
	kubectl(t, "run", "bad-connector",
		"--image=busybox",
		"--restart=Never",
		"--", "sh", "-c",
		`while true; do nc -w 1 127.0.0.1 9999 >/dev/null 2>&1; sleep 1; done`,
	)
	kubectl(t, "wait", "--for=condition=Ready", "--timeout=2m", "pod/bad-connector")
}

func koLogs(t *testing.T) string {
	t.Helper()

	pods := kubectl(t, "get", "pods", "-l", "app.kubernetes.io/name="+release, "-o", "name")
	var logs strings.Builder
	for _, pod := range strings.Fields(pods) {
		logs.WriteString(kubectl(t, "logs", strings.TrimPrefix(pod, "pod/")))
		logs.WriteString("\n")
	}
	return logs.String()
}

func kubectl(t *testing.T, args ...string) string {
	t.Helper()

	args = append([]string{"--context", kubeContext, "-n", namespace}, args...)
	out, err := exec.Command("kubectl", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("kubectl %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func envOrDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func containsAll(line string, want []string) bool {
	for _, w := range want {
		if !strings.Contains(line, w) {
			return false
		}
	}
	return true
}
