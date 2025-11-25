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
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/metal3"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	ssh "github.com/edgexr/golang-ssh"
	v1 "k8s.io/api/core/v1"

	metal3v1 "github.com/metal3-io/baremetal-operator/apis/metal3.io/v1alpha1"
	metal3provv1 "github.com/metal3-io/cluster-api-provider-metal3/api/v1beta1"
	clusterv1 "sigs.k8s.io/cluster-api/api/core/v1beta2"
)

type ClusterStatus struct {
	Phase                string
	Conditions           map[string]string
	ControlNodesReady    int
	ControlNodesDesired  int
	WorkerNodesReady     int
	WorkerNodesDesired   int
	NodesJoined          int
	ControlNodes         string
	WorkerReplicas       string
	KconfNames           k8smgmt.KconfNames
	KconfNamesErr        string
	LBReady              bool
	KubeAPIReady         bool
	BareMetalHostsStatus map[string]string
}

func NewClusterStatus() *ClusterStatus {
	return &ClusterStatus{
		BareMetalHostsStatus: make(map[string]string),
		Conditions:           make(map[string]string),
	}
}

func (s *ClusterAPI) waitForCluster(ctx context.Context, client ssh.Client, names *k8smgmt.KconfNames, clusterName string, clusterInst *edgeproto.ClusterInst, action cloudcommon.Action, initialStatus *ClusterStatus, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "waiting for capi cluster", "clusterName", clusterName, "action", action.String())

	lastStatus := initialStatus
	if lastStatus == nil {
		lastStatus = NewClusterStatus()
	}

	numNodes := 0
	for _, pool := range clusterInst.NodePools {
		if pool.ControlPlane {
			// Kamaji control plane does not create nodes
			continue
		}
		numNodes += int(pool.NumNodes)
	}

	for {
		status, err := s.checkClusterStatus(ctx, client, names, clusterName, clusterInst, lastStatus, action)
		if err != nil {
			if action == cloudcommon.Delete {
				str := strings.ToLower(err.Error())
				if strings.Contains(str, "not found") || strings.Contains(str, "notfound") {
					updateCallback(edgeproto.UpdateTask, "Cluster deleted")
					return nil
				}
			}
			return err
		}
		if status.Phase != "" && lastStatus.Phase != status.Phase {
			updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Cluster Phase: %s", status.Phase))
		}
		for typ, cond := range status.Conditions {
			lastCond, ok := lastStatus.Conditions[typ]
			// these are a little too low-level to show to the user,
			// but they are useful for debug
			if !ok || lastCond != cond {
				log.SpanLog(ctx, log.DebugLevelInfra, "condition", "cluster", clusterName, "cond", cond)
			}
		}
		if err := checkMetal3MachineStatus(ctx, client, names, s.namespace, clusterName); err != nil {
			return err
		}
		if status.ControlNodes != "" && lastStatus.ControlNodes != status.ControlNodes {
			updateCallback(edgeproto.UpdateTask, status.ControlNodes)
		}
		if status.WorkerReplicas != "" && lastStatus.WorkerReplicas != status.WorkerReplicas {
			updateCallback(edgeproto.UpdateTask, status.WorkerReplicas)
		}
		for name, hostStatus := range status.BareMetalHostsStatus {
			lastHostStatus, ok := lastStatus.BareMetalHostsStatus[name]
			if !ok || lastHostStatus != hostStatus {
				updateCallback(edgeproto.UpdateTask, hostStatus)
			}
			delete(lastStatus.BareMetalHostsStatus, name)
		}
		for name := range lastStatus.BareMetalHostsStatus {
			updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Node %s removed", name))
		}
		if action == cloudcommon.Create {
			if status.KconfNames.KconfName == "" {
				// check for unsupported version in KamajiControlPlane.
				if err := s.checkKamajiControlPlaneStatus(ctx, client, names, clusterName); err != nil {
					return err
				}
			}
			if !lastStatus.LBReady {
				ok, err := s.assignControlPlaneVIP(ctx, client, names, clusterName, clusterInst, updateCallback)
				if err != nil {
					return err
				}
				status.LBReady = ok
			}
			if status.KconfNames.KconfName != "" && lastStatus.KconfNames.KconfName == "" {
				updateCallback(edgeproto.UpdateTask, "Kubeconfig available, waiting for Kube API...")
			}
			if status.KubeAPIReady && !lastStatus.KubeAPIReady {
				updateCallback(edgeproto.UpdateTask, "Kube API ready, waiting for nodes to be provisioned and joined...")
			}
			if status.KubeAPIReady {
				nodes, err := k8smgmt.GetNodes(ctx, client, status.KconfNames.KconfArg)
				if err != nil {
					return err
				}
				status.NodesJoined = len(nodes)
				if status.NodesJoined != lastStatus.NodesJoined {
					updateCallback(edgeproto.UpdateTask, fmt.Sprintf("nodes joined %d/%d", status.NodesJoined, numNodes))
				}
			}
			// Note: it takes a while between the control plane coming
			// up (which is fast because it's hosted in the managed cluster)
			// and the worker nodes coming up, as they need the OS to be
			// installed and then joined to the cluster.
			// Don't install the CNI until the nodes are joined, otherwise
			// we wait a long time for the nodes to join which can cause
			// the CNI install to timeout.
			if status.NodesJoined == numNodes && lastStatus.NodesJoined != numNodes {
				updateCallback(edgeproto.UpdateTask, "all nodes joined, installing CNI...")
				err = k8smgmt.InstallCilium(ctx, client, &status.KconfNames, clusterName, clusterInst, updateCallback)
				if err != nil {
					return err
				}
				// Note: we assign load balancer IPs statically from a
				// cloudlet pool, so we don't want metalLB deciding which
				// IP to use. However, metalLB will not use an IP that is
				// not part of its pool. So we just create a pool with all
				// IPs but non-assignable.
				params := &infracommon.MetalConfigmapParams{
					AddressRanges:     []string{"0.0.0.0/0"},
					DisableAutoAssign: true,
				}
				err = infracommon.InstallAndConfigMetalLbIfNotInstalled(ctx, client, &status.KconfNames, clusterName, clusterInst, params, updateCallback)
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

func (s *ClusterAPI) checkClusterStatus(ctx context.Context, client ssh.Client, names *k8smgmt.KconfNames, clusterName string, clusterInst *edgeproto.ClusterInst, lastStatus *ClusterStatus, action cloudcommon.Action) (*ClusterStatus, error) {
	status := NewClusterStatus()
	cluster := clusterv1.Cluster{}
	err := s.getKubeObject(ctx, client, names, "cluster", s.namespace, clusterName, &cluster)
	if err != nil {
		return status, err
	}

	status.Phase = string(cluster.Status.Phase)
	for _, condition := range cluster.Status.Conditions {
		if condition.Status != "True" {
			continue
		}
		reason := condition.Reason
		// sometimes the reason is the same as the condition.Type,
		// which generates a confusing message like:
		// Condition Ready: Ready
		// So if replace it with "true" to make a better message.
		if reason == condition.Type {
			reason = "True"
		}
		condStr := fmt.Sprintf("Condition %s: %s", condition.Type, reason)
		if condition.Message != "" {
			msg := strings.TrimPrefix(condition.Message, "* ")
			condStr += ", " + msg
		}
		status.Conditions[condition.Type] = condStr
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
	hosts, err := metal3.GetBareMetalHosts(ctx, client, names, s.namespace, clusterName)
	for _, host := range hosts {
		status.BareMetalHostsStatus[host.Name] = getBareMetalHostStatus(&host)
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
	status.KconfNamesErr = lastStatus.KconfNamesErr
	if status.KconfNames.KconfName == "" {
		clusterNames, err := s.ensureClusterKubeconfig(ctx, client, names, clusterInst, clusterName)
		if err == nil {
			status.KconfNames = *clusterNames
		} else if status.KconfNamesErr != err.Error() {
			// just log error once and retry
			log.SpanLog(ctx, log.DebugLevelInfra, "check cluster status failed to ensure cluster kubeconfig", "clusterName", clusterName, "err", err)
			status.KconfNamesErr = err.Error()
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

func getBareMetalHostStatus(bmh *metal3v1.BareMetalHost) string {
	status := bmh.Status
	switch status.OperationalStatus {
	case metal3v1.OperationalStatusError:
		return fmt.Sprintf("Node %s: %s: %s", bmh.Name, status.ErrorType, status.ErrorMessage)
	case metal3v1.OperationalStatusOK:
		powerState := "offline"
		if bmh.Status.PoweredOn {
			powerState = "online"
		}
		return fmt.Sprintf("Node %s: %s, %s", bmh.Name, status.Provisioning.State, powerState)
	default:
		return fmt.Sprintf("Node %s: %s", bmh.Name, status.OperationalStatus)
	}
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

func (s *ClusterAPI) checkKamajiControlPlaneStatus(ctx context.Context, client ssh.Client, names *k8smgmt.KconfNames, clusterName string) error {
	cmd := fmt.Sprintf("kubectl %s -n %s get kamajicontrolplane %s -o json", names.KconfArg, s.namespace, clusterName)
	out, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("CAPI get kamaji control plane failed, %s, %s, %s", cmd, out, err)
	}
	// unfortunately we hit import hell trying to import the kamaji
	// golang types, so we use a generic map here.
	data := map[string]any{}
	err = json.Unmarshal([]byte(out), &data)
	if err != nil {
		return fmt.Errorf("failed to unmarshal kamaji control plane data, %s", err)
	}
	status, ok := data["status"].(map[string]any)
	if !ok {
		log.SpanLog(ctx, log.DebugLevelInfra, "no status yet from kamaji control plane data")
		return nil
	}
	conditions, ok := status["conditions"].([]any)
	if !ok {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to get conditions from kamaji control plane status", "status", status)
		return nil
	}
	if len(conditions) == 0 {
		log.SpanLog(ctx, log.DebugLevelInfra, "no conditions from kamaji control plane status", "status", status)
		return nil
	}
	for _, conditionObj := range conditions {
		condition, ok := conditionObj.(map[string]any)
		if !ok {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to get condition from kamaji control plane conditions", "conditions", conditions)
			return nil
		}
		message, ok := condition["message"].(string)
		if !ok {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to get message from kamaji control plane condition", "condition", condition)
			return nil
		}
		if strings.Contains(message, "unable to create a TenantControlPlane with a Kubernetes version greater than the supported one") {
			return errors.New(message)
		}
	}
	return nil
}

func (s *ClusterAPI) assignControlPlaneVIP(ctx context.Context, client ssh.Client, names *k8smgmt.KconfNames, clusterName string, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) (bool, error) {
	vip, ok := clusterInst.Annotations[cloudcommon.AnnotationControlVIP]
	if !ok {
		return false, fmt.Errorf("no floating VIP allocated for cluster %s", clusterName)
	}
	svc := v1.Service{}
	err := s.getKubeObject(ctx, client, names, "svc", s.namespace, clusterName, &svc)
	if err != nil {
		if strings.Contains(err.Error(), "NotFound") {
			return false, nil
		}
		return false, err
	}
	// How we apply the VIP depends on how the management cluster
	// is set up. We currently assume it's a k3s cluster with
	// metalLB.
	key := k8smgmt.MetalLBLoadbalancerIPsAnnotation
	if val, ok := svc.Annotations[key]; ok && val == vip {
		return true, nil
	}
	updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Assigning control plane LB VIP %s", vip))
	lb := edgeproto.LoadBalancer{
		Key: edgeproto.LoadBalancerKey{
			Name:      clusterName,
			Namespace: s.namespace,
		},
		Ipv4: vip,
	}
	err = k8smgmt.AnnotateLoadBalancerIP(ctx, client, names, &lb, key)
	if err != nil {
		return false, err
	}
	return true, nil
}

func checkMetal3MachineStatus(ctx context.Context, client ssh.Client, names *k8smgmt.KconfNames, namespace, clusterName string) error {
	// check the status of the metal3machines. These associate between
	// clusterapi machines and bare metal hosts. We are checking
	// if there were not enough bare metal hosts available.
	cmd := fmt.Sprintf("kubectl %s get metal3machine -n %s -o json %s", names.KconfArg, namespace, metal3.GetClusterLabel(clusterName))
	// no logging as this is polled by clusterapi status
	out, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("get metal3machines failed, %s, %v", out, err)
	}
	mlist := metal3provv1.Metal3MachineList{}
	err = json.Unmarshal([]byte(out), &mlist)
	if err != nil {
		return fmt.Errorf("unmarshal metal3machines failed, %s, %v", out, err)
	}
	missing := map[string]int{}
	for _, machine := range mlist.Items {
		flavor, ok := machine.Spec.HostSelector.MatchLabels[metal3.FlavorLabel]
		if !ok {
			continue
		}
		for _, cond := range machine.Status.Conditions {
			if cond.Type == metal3provv1.AssociateBMHCondition && cond.Reason == metal3provv1.AssociateBMHFailedReason {
				missing[flavor]++
			}
		}
	}
	if len(missing) == 0 {
		return nil
	}
	msgs := []string{}
	for flavor, count := range missing {
		msgs = append(msgs, fmt.Sprintf("%d more needed for flavor %s", count, flavor))
	}
	slices.Sort(msgs)
	return fmt.Errorf("Not enough bare metal hosts available, %s", strings.Join(msgs, ", "))
}
