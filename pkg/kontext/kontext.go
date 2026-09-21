package kontext

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/castai/logging"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	criapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

const (
	// DefaultSocket is the containerd socket which also serves the CRI API.
	DefaultSocket = "unix:///run/containerd/containerd.sock"
	cgroupRoot    = "/sys/fs/cgroup"

	podNamespaceLabel  = "io.kubernetes.pod.namespace"
	podNameLabel       = "io.kubernetes.pod.name"
	podUIDLabel        = "io.kubernetes.pod.uid"
	containerNameLabel = "io.kubernetes.container.name"
)

var ErrContainerNotFound = errors.New("container not found")

// ContainerInfo is the k8s scope of a container observed on the node.
// Fields other than CgroupID, ContainerID and Runtime are only populated
// for containers created via CRI (e.g. k8s pods).
type ContainerInfo struct {
	CgroupID      uint64
	ContainerID   string
	Runtime       string
	ContainerName string
	PodName       string
	PodNamespace  string
	PodUID        string
}

type Client struct {
	log  *logging.Logger
	cri  criapi.RuntimeServiceClient
	conn func() error
	root string

	mu       sync.RWMutex
	byCgroup map[uint64]*ContainerInfo

	lastSync        atomic.Int64
	syncMu          sync.Mutex
	resyncInterval  time.Duration
	minSyncInterval time.Duration
}

func New(log *logging.Logger, socket string) (*Client, error) {
	if err := requireCgroupV2(); err != nil {
		return nil, err
	}

	conn, err := grpc.NewClient(socket,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		// Disable HTTPS_PROXY for unix socket connections.
		grpc.WithNoProxy(),
	)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", socket, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cri := criapi.NewRuntimeServiceClient(conn)
	if _, err := cri.Version(ctx, &criapi.VersionRequest{}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("CRI version check via %s: %w", socket, err)
	}

	return &Client{
		log:             log.WithField("component", "kontext"),
		cri:             cri,
		conn:            conn.Close,
		root:            cgroupRoot,
		byCgroup:        map[uint64]*ContainerInfo{},
		resyncInterval:  30 * time.Second,
		minSyncInterval: 2 * time.Second,
	}, nil
}

func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn()
	}
	return nil
}

// Run keeps the container cache in sync: an initial sync, then a periodic
// resync. Syncs are also triggered lazily by GetContainerInfo cache misses.
func (c *Client) Run(ctx context.Context) error {
	c.Sync(ctx)

	ticker := time.NewTicker(c.resyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			c.Sync(ctx)
		}
	}
}

// GetContainerInfo resolves a cgroup ID captured by the eBPF tracer to
// its container and, when the container belongs to a k8s pod, pod scope.
func (c *Client) GetContainerInfo(ctx context.Context, cgroupID uint64) (*ContainerInfo, error) {
	if info := c.lookup(cgroupID); info != nil {
		return info, nil
	}

	c.ensureSynced(ctx)

	if info := c.lookup(cgroupID); info != nil {
		return info, nil
	}
	return nil, ErrContainerNotFound
}

func (c *Client) lookup(cgroupID uint64) *ContainerInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.byCgroup[cgroupID]
}

// ensureSynced rate-limits miss-triggered syncs so a stream of events from
// host processes (which never resolve to containers) cannot stampede the
// cgroupfs walk.
func (c *Client) ensureSynced(ctx context.Context) {
	if time.Since(c.lastSyncTime()) < c.minSyncInterval {
		return
	}
	c.syncMu.Lock()
	defer c.syncMu.Unlock()
	if time.Since(c.lastSyncTime()) < c.minSyncInterval {
		return
	}
	c.Sync(ctx)
}

func (c *Client) lastSyncTime() time.Time {
	return time.Unix(0, c.lastSync.Load())
}

// Sync rebuilds the cache from scratch: walk the cgroup v2 filesystem once,
// extract container IDs from cgroup paths, and join them with CRI container
// metadata for k8s scope.
func (c *Client) Sync(ctx context.Context) {
	started := time.Now()

	paths, err := walkCgroups(c.root)
	if err != nil {
		c.log.Warnf("walking cgroupfs: %v", err)
		return
	}

	// A CRI error degrades the sync to container ID and runtime only.
	criByID := map[string]*criapi.Container{}
	if resp, err := c.cri.ListContainers(ctx, &criapi.ListContainersRequest{
		Filter: &criapi.ContainerFilter{
			State: &criapi.ContainerStateValue{State: criapi.ContainerState_CONTAINER_RUNNING},
		},
	}); err != nil {
		c.log.Warnf("listing CRI containers: %v", err)
	} else {
		for _, container := range resp.Containers {
			criByID[container.Id] = container
		}
	}

	byCgroup := make(map[uint64]*ContainerInfo, len(paths))
	for cgroupID, path := range paths {
		containerID, runtime := containerIDFromCgroupPath(path)
		if containerID == "" {
			continue
		}
		info := &ContainerInfo{
			CgroupID:    cgroupID,
			ContainerID: containerID,
			Runtime:     runtime,
		}
		if cri, ok := criByID[containerID]; ok {
			info.ContainerName = cri.Labels[containerNameLabel]
			info.PodName = cri.Labels[podNameLabel]
			info.PodNamespace = cri.Labels[podNamespaceLabel]
			info.PodUID = cri.Labels[podUIDLabel]
		}
		byCgroup[cgroupID] = info
	}

	c.mu.Lock()
	c.byCgroup = byCgroup
	c.mu.Unlock()

	c.lastSync.Store(time.Now().UnixNano())
	c.log.Debugf("synced %d containers from %d cgroups in %s", len(byCgroup), len(paths), time.Since(started))
}

// walkCgroups maps cgroup IDs (the kernfs inode numbers reported by
// bpf_get_current_cgroup_id) to cgroup paths. The low 32 bits are used as the
// key: this is where the id lives on all kernels that report a 64 bit inode.
func walkCgroups(root string) (map[uint64]string, error) {
	res := map[uint64]string{}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		// nolint:nilerr
		if err != nil || !d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil
		}
		res[uint64(stat.Ino)&0xFFFFFFFF] = path
		return nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func requireCgroupV2() error {
	if _, err := os.Stat(filepath.Join(cgroupRoot, "cgroup.controllers")); err != nil {
		return fmt.Errorf("kontext requires cgroup v2: %w", err)
	}
	return nil
}

var containerIDRegex = regexp.MustCompile(`^[A-Fa-f0-9]{64}$`)

// containerIDFromCgroupPath extracts the container ID and runtime from a
// cgroup v2 path. It scans path components from the innermost outwards.
func containerIDFromCgroupPath(cgroupPath string) (string, string) {
	parts := strings.Split(cgroupPath, "/")

	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if len(part) < 28 {
			// Container IDs are at least 28 characters long.
			continue
		}

		runtime := ""
		id := strings.TrimSuffix(part, ".scope")

		switch {
		case strings.HasPrefix(id, "docker-"):
			runtime, id = "docker", strings.TrimPrefix(id, "docker-")
		case strings.HasPrefix(id, "crio-"):
			runtime, id = "crio", strings.TrimPrefix(id, "crio-")
		case strings.HasPrefix(id, "cri-containerd-"):
			runtime, id = "containerd", strings.TrimPrefix(id, "cri-containerd-")
		case strings.Contains(part, ":cri-containerd:"):
			runtime, id = "containerd", part[strings.LastIndex(part, ":cri-containerd:")+len(":cri-containerd:"):]
		case strings.HasPrefix(id, "libpod-"):
			runtime, id = "podman", strings.TrimPrefix(id, "libpod-")
		}

		if !containerIDRegex.MatchString(id) {
			continue
		}

		if runtime == "" {
			if hasAncestor(parts, i, "docker") || hasAncestor(parts, i, "kubepods") {
				runtime = "docker"
			} else {
				continue
			}
		}
		return id, runtime
	}
	return "", ""
}

func hasAncestor(parts []string, from int, name string) bool {
	for i := from; i >= 0; i-- {
		if parts[i] == name {
			return true
		}
	}
	return false
}
