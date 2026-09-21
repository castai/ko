package kontext

import (
	"os"
	"testing"
)

func TestContainerIDFromCgroupPath(t *testing.T) {
	id := "0ea0d452a34368ae62b2f6e976bcbff616e86190bd8e0d26faebc1a875c1e2ba"
	cases := []struct {
		path      string
		container string
		runtime   string
	}{
		{
			path:      "/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1234.slice/cri-containerd-" + id + ".scope",
			container: id,
			runtime:   "containerd",
		},
		{
			path:      "/sys/fs/cgroup/system.slice/containerd.service/kubepods-besteffort.slice/cri-containerd-" + id + ".scope",
			container: id,
			runtime:   "containerd",
		},
		{
			path:      "/sys/fs/cgroup/system.slice/docker-" + id + ".scope",
			container: id,
			runtime:   "docker",
		},
		{
			path:      "/sys/fs/cgroup/kubepods/burstable/pod1234/" + id,
			container: id,
			runtime:   "docker",
		},
		{
			path:      "/sys/fs/cgroup/machine.slice/libpod-" + id + ".scope",
			container: id,
			runtime:   "podman",
		},
		{
			path: "/sys/fs/cgroup/system.slice/sshd.service",
		},
		{
			path: "/sys/fs/cgroup/kubepods.slice/kubepods.slice-x.slice",
		},
	}

	for _, c := range cases {
		container, runtime := containerIDFromCgroupPath(c.path)
		if container != c.container || runtime != c.runtime {
			t.Errorf("path=%q got container=%q runtime=%q, want container=%q runtime=%q",
				c.path, container, runtime, c.container, c.runtime)
		}
	}
}

func TestWalkCgroupsMapsInodeToPath(t *testing.T) {
	dir := t.TempDir()
	nested := dir + "/kubepods.slice/cri-containerd-abc.scope"
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}

	paths, err := walkCgroups(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 3 {
		t.Fatalf("expected 3 cgroups, got %d: %v", len(paths), paths)
	}
	found := false
	for _, path := range paths {
		if path == nested {
			found = true
		}
	}
	if !found {
		t.Errorf("nested cgroup %q not found in walk result: %v", nested, paths)
	}
}
