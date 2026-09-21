//go:build e2e

package e2e

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const (
	kubeContext = "kind-ko-e2e"
	namespace   = "ko-e2e"
	release     = "ko"
)

func TestE2EDaemonSetExportsEvents(t *testing.T) {
	imageRepo := envOrDefault("E2E_IMAGE_REPO", "ko-e2e")
	imageTag := envOrDefault("E2E_IMAGE_TAG", "local")

	installChart(t, imageRepo, imageTag)

	// A pod constantly attempting connections to a closed port on its own
	// loopback generates connect failures attributed to its cgroup.
	runConnectorPod(t)

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
}

func installChart(t *testing.T, imageRepo, imageTag string) {
	t.Helper()

	args := []string{
		"--kube-context", kubeContext,
		"upgrade", "--install", release, "../charts/ko",
		"--namespace", namespace, "--create-namespace",
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
	pod := strings.TrimSpace(pods)
	if pod == "" {
		return ""
	}
	return kubectl(t, "logs", strings.TrimPrefix(pod, "pod/"))
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
