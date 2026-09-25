package conntest

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
)

type Pod struct {
	Name     string
	IP       string
	NodeName string
	Phase    string
	Labels   map[string]string
}

type WatchEvent struct {
	Type string
	Pod  Pod
}

type KubeAPI interface {
	GetPod(ctx context.Context, name string) (Pod, error)
	ListPods(ctx context.Context, labelSelector string) ([]Pod, string, error)
	WatchPods(ctx context.Context, labelSelector, resourceVersion string) (<-chan WatchEvent, error)
}

const serviceAccountDir = "/var/run/secrets/kubernetes.io/serviceaccount"

type kubeClient struct {
	baseURL string
	token   string
	ns      string
	client  *http.Client
}

type podJSON struct {
	Metadata struct {
		Name   string            `json:"name"`
		Labels map[string]string `json:"labels"`
	} `json:"metadata"`
	Spec struct {
		NodeName string `json:"nodeName"`
	} `json:"spec"`
	Status struct {
		Phase string `json:"phase"`
		PodIP string `json:"podIP"`
	} `json:"status"`
}

func (p podJSON) toPod() Pod {
	return Pod{
		Name:     p.Metadata.Name,
		IP:       p.Status.PodIP,
		NodeName: p.Spec.NodeName,
		Phase:    p.Status.Phase,
		Labels:   p.Metadata.Labels,
	}
}

func newKubeClient(baseURL, token, namespace string, client *http.Client) *kubeClient {
	return &kubeClient{
		baseURL: baseURL,
		token:   token,
		ns:      namespace,
		client:  client,
	}
}

func newInClusterClient() (*kubeClient, error) {
	token, err := os.ReadFile(filepath.Join(serviceAccountDir, "token"))
	if err != nil {
		return nil, fmt.Errorf("reading service account token: %w", err)
	}
	namespace, err := os.ReadFile(filepath.Join(serviceAccountDir, "namespace"))
	if err != nil {
		return nil, fmt.Errorf("reading service account namespace: %w", err)
	}
	ca, err := os.ReadFile(filepath.Join(serviceAccountDir, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("reading cluster CA: %w", err)
	}
	host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, errors.New("not running inside a cluster: KUBERNETES_SERVICE_HOST is not set")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("parsing cluster CA")
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
	}
	return newKubeClient("https://"+net.JoinHostPort(host, port), string(token), string(namespace), client), nil
}

func (c *kubeClient) podsPath() string {
	return "/api/v1/namespaces/" + c.ns + "/pods"
}

func (c *kubeClient) newRequest(ctx context.Context, path string, query url.Values) (*http.Request, error) {
	target := c.baseURL + path
	if encoded := query.Encode(); encoded != "" {
		target += "?" + encoded
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	return req, nil
}

func (c *kubeClient) do(ctx context.Context, path string, query url.Values, out any) error {
	req, err := c.newRequest(ctx, path, query)
	if err != nil {
		return err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", path, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *kubeClient) GetPod(ctx context.Context, name string) (Pod, error) {
	var p podJSON
	if err := c.do(ctx, c.podsPath()+"/"+name, nil, &p); err != nil {
		return Pod{}, err
	}
	return p.toPod(), nil
}

func (c *kubeClient) ListPods(ctx context.Context, labelSelector string) ([]Pod, string, error) {
	query := url.Values{}
	if labelSelector != "" {
		query.Set("labelSelector", labelSelector)
	}
	var list struct {
		Metadata struct {
			ResourceVersion string `json:"resourceVersion"`
		} `json:"metadata"`
		Items []podJSON `json:"items"`
	}
	if err := c.do(ctx, c.podsPath(), query, &list); err != nil {
		return nil, "", err
	}
	pods := make([]Pod, 0, len(list.Items))
	for _, p := range list.Items {
		pods = append(pods, p.toPod())
	}
	return pods, list.Metadata.ResourceVersion, nil
}

func (c *kubeClient) WatchPods(ctx context.Context, labelSelector, resourceVersion string) (<-chan WatchEvent, error) {
	query := url.Values{}
	if labelSelector != "" {
		query.Set("labelSelector", labelSelector)
	}
	query.Set("watch", "true")
	query.Set("resourceVersion", resourceVersion)
	req, err := c.newRequest(ctx, c.podsPath(), query)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return nil, fmt.Errorf("watch pods: %s", resp.Status)
	}
	events := make(chan WatchEvent)
	go func() {
		defer close(events)
		defer resp.Body.Close()
		dec := json.NewDecoder(resp.Body)
		for {
			var ev struct {
				Type   string  `json:"type"`
				Object podJSON `json:"object"`
			}
			if err := dec.Decode(&ev); err != nil {
				return
			}
			select {
			case events <- WatchEvent{Type: ev.Type, Pod: ev.Object.toPod()}:
			case <-ctx.Done():
				return
			}
		}
	}()
	return events, nil
}
