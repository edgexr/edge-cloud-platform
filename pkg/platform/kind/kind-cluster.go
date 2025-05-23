// Copyright 2022 MobiledgeX, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package kind

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/xind"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	ssh "github.com/edgexr/golang-ssh"
)

// See https://hub.docker.com/r/kindest/node/tags for all available versions
// Use env var KIND_IMAGE to override default below.
// NOTE: image digest is required, otherwise the image pulled will be for the latest version of KIND
// Below is for KIND v0.20.0
var DefaultNodeImage = "kindest/node:v1.26.6@sha256:6e2d8b28a5b601defe327b98bd1c2d1930b49e5d8c512e1895099e4504007adb"

func (s *Platform) CreateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback, timeout time.Duration) (map[string]string, error) {
	var err error

	switch clusterInst.Deployment {
	case cloudcommon.DeploymentTypeDocker:
		updateCallback(edgeproto.UpdateTask, "Create done for Docker Cluster on KIND")
		return nil, nil
	case cloudcommon.DeploymentTypeKubernetes:
		updateCallback(edgeproto.UpdateTask, "Create KIND Cluster")
	default:
		return nil, fmt.Errorf("Only K8s and Docker clusters are supported on KIND")
	}
	// Create K8s cluster
	if err = s.CreateKINDCluster(ctx, clusterInst); err != nil {
		return nil, err
	}
	return nil, nil
}

func (s *Platform) UpdateClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) (map[string]string, error) {
	return nil, fmt.Errorf("update cluster not supported for KIND")
}

func (s *Platform) ChangeClusterInstDNS(ctx context.Context, clusterInst *edgeproto.ClusterInst, oldFqdn string, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("cluster dns change not supported for KIND")
}

func (s *Platform) DeleteClusterInst(ctx context.Context, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	return s.DeleteKINDCluster(ctx, clusterInst)
}

type ConfigParams struct {
	Image      string
	NumMasters []struct{}
	NumNodes   []struct{}
}

var ConfigTemplate = `
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
nodes:
{{- range .NumMasters}}
- role: control-plane
  image: {{$.Image}}
{{- end}}
{{- range .NumNodes}}
- role: worker
  image: {{$.Image}}
{{- end}}
`

func (s *Platform) CreateKINDCluster(ctx context.Context, clusterInst *edgeproto.ClusterInst) error {
	name := k8smgmt.GetK8sNodeNameSuffix(clusterInst)
	kconf := k8smgmt.GetKconfName(clusterInst)
	log.SpanLog(ctx, log.DebugLevelInfra, "create KIND cluster", "name", name, "kconf", kconf)
	client, err := s.Xind.GetClient(ctx)
	if err != nil {
		return err
	}
	nodeImage := os.Getenv("KIND_IMAGE")
	if nodeImage == "" {
		nodeImage = DefaultNodeImage
	}
	tmpl, err := template.New("config").Parse(ConfigTemplate)
	if err != nil {
		return err
	}
	params := &ConfigParams{
		Image:      nodeImage,
		NumMasters: make([]struct{}, clusterInst.NumMasters),
		NumNodes:   make([]struct{}, clusterInst.GetNumNodes()),
	}
	buf := bytes.Buffer{}
	err = tmpl.Execute(&buf, params)
	if err != nil {
		return err
	}
	configFile := name + "-config.yaml"

	// see if cluster already exists with the correct config
	exists, err := ClusterExists(ctx, client, name)
	if err != nil {
		return err
	}
	if exists {
		log.SpanLog(ctx, log.DebugLevelInfra, "cluster exists, checking config", "name", name, "config", configFile)
		cmd := fmt.Sprintf("cat %s", configFile)
		out, err := client.Output(cmd)
		if err == nil && strings.TrimSpace(out) == strings.TrimSpace(buf.String()) {
			log.SpanLog(ctx, log.DebugLevelInfra, "cluster exists and config matches, reusing")
			// unpause nodes if they were paused
			nodes, err := GetClusterContainerNames(ctx, client, name)
			if err != nil {
				return err
			}
			err = xind.UnpauseContainers(ctx, client, nodes)
			if err != nil {
				return err
			}
			// clear out any leftover AppInsts
			err = k8smgmt.ClearCluster(ctx, client, clusterInst)
			if err != nil {
				return err
			}
			log.SpanLog(ctx, log.DebugLevelInfra, "reusing existing KIND cluster", "name", name)
			return nil
		}
		// delete cluster
		log.SpanLog(ctx, log.DebugLevelInfra, "missing or mismatched config, removing existing and then recreating", "name", name)
		cmd = fmt.Sprintf("kind delete cluster --name=%s", name)
		out, err = client.Output(cmd)
		if err != nil {
			return cmdFailed(cmd, out, err)
		}
	}

	// write config
	err = pc.WriteFile(client, configFile, buf.String(), "KIND config", pc.NoSudo)
	if err != nil {
		return err
	}
	kconfArg := "--kubeconfig=" + kconf
	cmd := fmt.Sprintf("kind create cluster --config=%s %s --name=%s", configFile, kconfArg, name)
	out, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("failed to run cmd %s, %s, %s", cmd, out, err)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "successfully created KIND cluster", "name", name)
	cmd = fmt.Sprintf(`kubectl %s apply -f "https://cloud.weave.works/k8s/net?k8s-version=$(kubectl %s version | base64 | tr -d '\n')"`, kconfArg, kconfArg)
	// XXX: in case we decide to use cilium, or in case we need to test
	// against cilium, this is how to install it:
	// cmd = fmt.Sprintf(`%s kubectl create -f https://raw.githubusercontent.com/cilium/cilium/v1.9/install/kubernetes/quick-install.yaml`, kconfEnv)
	log.SpanLog(ctx, log.DebugLevelInfra, "installing weave", "cmd", cmd)
	out, err = client.Output(cmd)
	log.SpanLog(ctx, log.DebugLevelInfra, "weave install result", "out", out, "err", err)
	if err != nil {
		return fmt.Errorf("failed to install weave %s: %s, %s", cmd, out, err)
	}
	err = xind.WaitClusterReady(ctx, client, clusterInst, 300*time.Second)
	if err != nil {
		return err
	}
	return nil
}

func (s *Platform) DeleteKINDCluster(ctx context.Context, clusterInst *edgeproto.ClusterInst) error {
	name := k8smgmt.GetK8sNodeNameSuffix(clusterInst)
	log.SpanLog(ctx, log.DebugLevelInfra, "delete KIND cluster", "name", name)
	client, err := s.Xind.GetClient(ctx)
	if err != nil {
		return err
	}

	log.SpanLog(ctx, log.DebugLevelInfra, "pausing cluster instead of deleting", "name", name)
	// clear out any AppInsts
	err = k8smgmt.ClearCluster(ctx, client, clusterInst)
	if err != nil {
		return err
	}
	// pause nodes
	nodes, err := GetClusterContainerNames(ctx, client, name)
	if err != nil {
		return err
	}
	err = xind.PauseContainers(ctx, client, nodes)
	log.SpanLog(ctx, log.DebugLevelInfra, "successfully paused KIND cluster", "name", name)
	return nil
}

func (s *Platform) GetMasterIp(ctx context.Context, names *k8smgmt.KubeNames) (string, error) {
	masterContainer := names.K8sNodeNameSuffix + "-control-plane"
	client, err := s.Xind.GetClient(ctx)
	if err != nil {
		return "", err
	}
	cmd := fmt.Sprintf("docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' %s", masterContainer)
	out, err := client.Output(cmd)
	if err != nil {
		return "", err
	}
	lines := strings.Split(out, "\n")
	return strings.TrimSpace(lines[0]), nil
}

func (s *Platform) GetDockerNetworkName(ctx context.Context, names *k8smgmt.KubeNames) (string, error) {
	masterContainer := names.K8sNodeNameSuffix + "-control-plane"
	client, err := s.Xind.GetClient(ctx)
	if err != nil {
		return "", err
	}
	cmd := fmt.Sprintf("docker inspect -f '{{.HostConfig.NetworkMode}}' %s", masterContainer)
	out, err := client.Output(cmd)
	if err != nil {
		return "", err
	}
	lines := strings.Split(out, "\n")
	return strings.TrimSpace(lines[0]), nil
}

func cmdFailed(cmd string, out string, err error) error {
	return fmt.Errorf("command failed, %s: %s, %s", cmd, out, err)
}

func GetClusters(ctx context.Context, client ssh.Client) ([]string, error) {
	cmd := "kind get clusters"
	out, err := client.Output(cmd)
	if err != nil {
		return nil, cmdFailed(cmd, out, err)
	}
	if strings.Contains(out, "No kind clusters found") {
		return []string{}, nil
	}
	clusters := []string{}
	for _, name := range strings.Split(out, "\n") {
		name = strings.TrimSpace(name)
		if name != "" {
			clusters = append(clusters, name)
		}
	}
	return clusters, nil
}

func ClusterExists(ctx context.Context, client ssh.Client, name string) (bool, error) {
	cmd := "kind get clusters"
	out, err := client.Output(cmd)
	if err != nil {
		return false, cmdFailed(cmd, out, err)
	}
	for _, n := range strings.Split(out, "\n") {
		if name == n {
			return true, nil
		}
	}
	return false, nil
}

func GetClusterContainerNames(ctx context.Context, client ssh.Client, clusterName string) ([]string, error) {
	cmd := fmt.Sprintf("kind get nodes --name %s", clusterName)
	out, err := client.Output(cmd)
	if err != nil {
		return nil, cmdFailed(cmd, out, err)
	}
	nodes := []string{}
	for _, name := range strings.Split(out, "\n") {
		name = strings.TrimSpace(name)
		if name != "" {
			nodes = append(nodes, name)
		}
	}
	return nodes, nil
}

func (s *Platform) ActiveChanged(ctx context.Context, platformActive bool) error {
	return nil
}

func (s *Platform) NameSanitize(name string) string {
	return name
}

func (s *Platform) GetCloudletManagedClusters(ctx context.Context) ([]*edgeproto.CloudletManagedCluster, error) {
	return nil, errors.New("not supported")
}

func (s *Platform) GetCloudletManagedClusterInfo(ctx context.Context, in *edgeproto.ClusterInst) (*edgeproto.CloudletManagedClusterInfo, error) {
	return nil, errors.New("not supported")
}
