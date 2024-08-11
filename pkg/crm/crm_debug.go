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

package crm

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/node"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
)

const (
	GetEnvoyVersionCmd = "get-cluster-envoy-version"
	CRMCmd             = "crmcmd"
)

func InitDebug(nodeMgr *node.NodeMgr) {
	nodeMgr.Debug.AddDebugFunc(CRMCmd, runCrmCmd)
}

func runCrmCmd(ctx context.Context, req *edgeproto.DebugRequest) string {
	if req.Args == "" {
		return "please specify shell command in args field"
	}
	rd := csv.NewReader(strings.NewReader(req.Args))
	rd.Comma = ' '
	args, err := rd.Read()
	if err != nil {
		return fmt.Sprintf("failed to split args string, %v", err)
	}
	cmd := exec.Command(args[0], args[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("exec failed, %v, %s", err, string(out))
	}
	return string(out)
}

type EnvoyContainerVersion struct {
	ContainerName string
	EnvoyVersion  string
	Error         string
}

type RootLBEnvoyVersion struct {
	NodeType        string
	NodeName        string
	EnvoyContainers []EnvoyContainerVersion
}

func (s *CRMData) GetClusterEnvoyVersion(ctx context.Context, req *edgeproto.DebugRequest) string {
	clusterInsts := []edgeproto.ClusterInst{}
	s.ClusterInstCache.Mux.Lock()
	for _, v := range s.ClusterInstCache.Objs {
		clusterInsts = append(clusterInsts, *v.Obj)
	}
	s.ClusterInstCache.Mux.Unlock()
	nodes, err := s.platform.ListCloudletMgmtNodes(ctx, clusterInsts, nil)
	if err != nil {
		return fmt.Sprintf("unable to get list of cluster nodes, %v", err)
	}
	if len(nodes) == 0 {
		return fmt.Sprintf("no nodes found")
	}
	nodeVersions := []RootLBEnvoyVersion{}
	for _, node := range nodes {
		if !strings.Contains(node.Type, "rootlb") {
			continue
		}
		client, err := s.platform.GetNodePlatformClient(ctx, &node)
		if err != nil {
			return fmt.Sprintf("failed to get ssh client for node %s, %v", node.Name, err)
		}
		out, err := client.Output(`docker ps --format "{{.Names}}" --filter name="^envoy"`)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to find envoy containers on rootlb", "rootlb", node, "err", err, "out", out)
			return fmt.Sprintf("failed to find envoy containers on rootlb %s, %v", node.Name, err)
		}
		nodeVersion := RootLBEnvoyVersion{
			NodeType: node.Type,
			NodeName: node.Name,
		}
		for _, name := range strings.Split(out, "\n") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			envoyContainerVers := EnvoyContainerVersion{
				ContainerName: name,
			}
			out, err := client.Output(fmt.Sprintf("docker exec %s envoy --version", name))
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "failed to find envoy container version on rootlb", "rootlb", node, "container", name, "err", err, "out", out)
				envoyContainerVers.Error = err.Error()
				nodeVersion.EnvoyContainers = append(nodeVersion.EnvoyContainers, envoyContainerVers)
				continue
			}
			version := strings.TrimSpace(out)
			envoyContainerVers.EnvoyVersion = version
			nodeVersion.EnvoyContainers = append(nodeVersion.EnvoyContainers, envoyContainerVers)
		}
		nodeVersions = append(nodeVersions, nodeVersion)
	}
	out, err := json.Marshal(nodeVersions)
	if err != nil {
		return fmt.Sprintf("Failed to marshal node versions: %s, %v", string(out), err)
	}
	return string(out)
}
