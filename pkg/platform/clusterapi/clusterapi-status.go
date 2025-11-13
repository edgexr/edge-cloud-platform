// Copyright 2025 EdgeXR, Inc
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

package clusterapi

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	ssh "github.com/edgexr/golang-ssh"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clusterv1 "sigs.k8s.io/cluster-api/api/core/v1beta2"
)

type ClusterStatus struct {
	Phase               string
	ConditionMessage    string
	ControlNodesReady   int
	ControlNodesDesired int
	WorkerNodesReady    int
	WorkerNodesDesired  int
	ControlNodes        string
	WorkerReplicas      string
	KconfNames          k8smgmt.KconfNames
	KubeAPIReady        bool
}

func (s *ClusterAPI) waitForCluster(ctx context.Context, client ssh.Client, names *k8smgmt.KconfNames, clusterName string, clusterInst *edgeproto.ClusterInst, action cloudcommon.Action, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "waiting for capi cluster", "clusterName", clusterName, "action", action.String())

	lastStatus := ClusterStatus{}

	for {
		status, err := s.checkClusterStatus(ctx, client, names, clusterName, clusterInst, lastStatus, action)
		if err != nil {
			if action == cloudcommon.Delete {
				str := strings.ToLower(err.Error())
				if strings.Contains(str, "not found") || strings.Contains(str, "notfound") {
					updateCallback(edgeproto.UpdateTask, "Cluster deleted")
					break
				}
			}
			return err
		}
		if status.Phase != "" && lastStatus.Phase != status.Phase {
			updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Cluster Phase: %s", status.Phase))
		}
		if status.ConditionMessage != "" && lastStatus.ConditionMessage != status.ConditionMessage {
			updateCallback(edgeproto.UpdateTask, status.ConditionMessage)
		}
		if status.ControlNodes != "" && lastStatus.ControlNodes != status.ControlNodes {
			updateCallback(edgeproto.UpdateTask, status.ControlNodes)
		}
		if status.WorkerReplicas != "" && lastStatus.WorkerReplicas != status.WorkerReplicas {
			updateCallback(edgeproto.UpdateTask, status.WorkerReplicas)
		}
		if action == cloudcommon.Create {
			if status.KconfNames.KconfName != "" && lastStatus.KconfNames.KconfName == "" {
				updateCallback(edgeproto.UpdateTask, "Kubeconfig available, waiting for Kube API...")
			}
			if status.KubeAPIReady && !lastStatus.KubeAPIReady {
				updateCallback(edgeproto.UpdateTask, "Kube API ready, installing CNI...")
				err = k8smgmt.InstallCilium(ctx, client, &status.KconfNames, clusterName, clusterInst, updateCallback)
				if err != nil {
					return err
				}
			}
		}
		if action == cloudcommon.Create || action == cloudcommon.Update {
			if status.ControlNodesDesired > 0 && status.WorkerNodesDesired > 0 && status.ControlNodesReady == status.ControlNodesDesired && status.WorkerNodesReady == status.WorkerNodesDesired {
				updateCallback(edgeproto.UpdateTask, "Cluster ready")
				break
			}
		}
		lastStatus = status
		if err := ctx.Err(); err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "context error, aborting wait for capi cluster", "clusterName", clusterName, "err", err)
			return err
		}
		time.Sleep(2 * time.Second)
	}
	return nil
}

func (s *ClusterAPI) checkClusterStatus(ctx context.Context, client ssh.Client, names *k8smgmt.KconfNames, clusterName string, clusterInst *edgeproto.ClusterInst, lastStatus ClusterStatus, action cloudcommon.Action) (ClusterStatus, error) {
	status := ClusterStatus{}
	cluster := clusterv1.Cluster{}
	err := s.getKubeObject(ctx, client, names, "cluster", s.namespace, clusterName, &cluster)
	if err != nil {
		return status, err
	}

	status.Phase = string(cluster.Status.Phase)
	// last condition message
	var lastCondition v1.Condition
	for _, condition := range cluster.Status.Conditions {
		if lastCondition.LastTransitionTime.Before(&condition.LastTransitionTime) && condition.Message != "" {
			lastCondition = condition
			status.ConditionMessage = "Status: " + condition.Message
		}
	}
	// control replicas
	if cluster.Status.ControlPlane != nil {
		if cluster.Status.ControlPlane.ReadyReplicas != nil {
			status.ControlNodesReady = int(*cluster.Status.ControlPlane.ReadyReplicas)
		}
		if cluster.Status.ControlPlane.DesiredReplicas != nil {
			status.ControlNodesDesired = int(*cluster.Status.ControlPlane.DesiredReplicas)
		}
		status.ControlNodes = fmt.Sprintf("Control nodes ready: %d/%d", status.ControlNodesReady, status.ControlNodesDesired)
	}
	// worker replicas
	if cluster.Status.Workers != nil {
		if cluster.Status.Workers.ReadyReplicas != nil {
			status.WorkerNodesReady = int(*cluster.Status.Workers.ReadyReplicas)
		}
		if cluster.Status.Workers.DesiredReplicas != nil {
			status.WorkerNodesDesired = int(*cluster.Status.Workers.DesiredReplicas)
		}
		status.WorkerReplicas = fmt.Sprintf("Worker nodes ready: %d/%d", status.WorkerNodesReady, status.WorkerNodesDesired)
	}
	if status.ControlNodesDesired == 0 {
		// don't bother checking kubeconfig/kubectl
		return status, nil
	}
	if action == cloudcommon.Delete || action == cloudcommon.Update {
		// ignore kube api checks
		return status, nil
	}
	// check if we can get kubeconfig
	status.KconfNames = lastStatus.KconfNames
	if status.KconfNames.KconfName == "" {
		clusterNames, err := s.ensureClusterKubeconfig(ctx, client, names, clusterInst, clusterName)
		if err == nil {
			status.KconfNames = *clusterNames
		} else {
			// just log error and retry
			log.SpanLog(ctx, log.DebugLevelInfra, "check cluster status failed to ensure cluster kubeconfig", "clusterName", clusterName, "err", err)
		}
	}
	// check if we can contact the kube API
	status.KubeAPIReady = lastStatus.KubeAPIReady
	if !status.KubeAPIReady && status.KconfNames.KconfArg != "" {
		cmd := fmt.Sprintf("kubectl %s cluster-info --request-timeout=0.5s", status.KconfNames.KconfArg)
		out, err := client.Output(cmd)
		if err == nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "kube api ready", "cmd", cmd, "out", out)
			status.KubeAPIReady = true
		}
	}
	return status, nil
}

func (s *ClusterAPI) getKubeObject(ctx context.Context, client ssh.Client, names *k8smgmt.KconfNames, kind string, namespace string, name string, obj any) error {
	cmd := fmt.Sprintf("kubectl %s get -n %s %s %s -o json", names.KconfArg, namespace, kind, name)
	out, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("CAPI get kube object failed, %s, %s, %s", cmd, out, err)
	}
	err = json.Unmarshal([]byte(out), obj)
	if err != nil {
		return fmt.Errorf("failed to unmarshal kube object data, %s", err)
	}
	return nil
}
