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

package k8smgmt

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	"github.com/edgexr/edge-cloud-platform/pkg/resspec"
	ssh "github.com/edgexr/golang-ssh"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	apimachineryversion "k8s.io/apimachinery/pkg/version"
)

type NoScheduleMasterTaintAction string

const NoScheduleMasterTaintAdd NoScheduleMasterTaintAction = "master-noschedule-taint-add"
const NoScheduleMasterTaintRemove NoScheduleMasterTaintAction = "master-noschedule-taint-remove"
const NoScheduleMasterTaintNone NoScheduleMasterTaintAction = "master-noschedule-taint-none"

const NoScheduleMasterTaintAnnotaionOld = "node-role.kubernetes.io/master"
const NoScheduleMasterTaintAnnotaionNew = "node-role.kubernetes.io/control-plane"

type ClusterAddonInfo struct {
	IngressNginxOps []IngressNginxOp
}

func DeleteNodes(ctx context.Context, client ssh.Client, kconfArg string, nodes []string) error {
	for _, node := range nodes {
		cmd := fmt.Sprintf("kubectl %s delete node %s", kconfArg, node)
		log.SpanLog(ctx, log.DebugLevelInfra, "k8smgmt delete node", "node", node, "cmd", cmd)
		out, err := client.Output(cmd)
		if err != nil {
			return fmt.Errorf("failed to delete k8s node, %s, %s, %v", cmd, out, err)
		}
	}
	return nil
}

func SetMasterNoscheduleTaint(ctx context.Context, client ssh.Client, masterName string, kubeconfig string, action NoScheduleMasterTaintAction) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "SetMasterNoscheduleTaint", "masterName", masterName, "action", action)

	var cmd string
	taintAnnotation := NoScheduleMasterTaintAnnotaionNew
	cmd = fmt.Sprintf("kubectl version --short --kubeconfig=%s | grep Server", kubeconfig)
	out, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("Unable to get k8s version, %v", err)
	}
	// For old clusters NoSchedule taint is different
	if strings.Contains(out, "v1.18") {
		taintAnnotation = NoScheduleMasterTaintAnnotaionOld
	}
	if action == NoScheduleMasterTaintAdd {
		log.SpanLog(ctx, log.DebugLevelInfra, "adding taint to master", "masterName", masterName)
		cmd = fmt.Sprintf("kubectl taint nodes %s %s=:NoSchedule --kubeconfig=%s", masterName, taintAnnotation, kubeconfig)
		out, err := client.Output(cmd)
		if err != nil {
			if strings.Contains(out, "already has node-role.kubernetes.io") {
				log.SpanLog(ctx, log.DebugLevelInfra, "master taint already present")
			} else {
				log.SpanLog(ctx, log.DebugLevelInfra, "error adding master taint", "out", out, "err", err)
				return fmt.Errorf("Cannot add NoSchedule taint to master, %v", err)

			}
		}
	} else if action == NoScheduleMasterTaintRemove {
		log.SpanLog(ctx, log.DebugLevelInfra, "removing taint from master", "masterName", masterName)
		cmd = fmt.Sprintf("kubectl taint nodes %s %s:NoSchedule-  --kubeconfig=%s", masterName, taintAnnotation, kubeconfig)
		out, err := client.Output(cmd)
		if err != nil {
			if strings.Contains(out, "not found") {
				log.SpanLog(ctx, log.DebugLevelInfra, "master taint already gone")
			} else {
				log.SpanLog(ctx, log.DebugLevelInfra, "error removing master taint", "out", out, "err", err)
				return fmt.Errorf("Cannot remove NoSchedule taint from master, %v", err)
			}
		}
	}
	return nil
}

func CleanupClusterConfig(ctx context.Context, client ssh.Client, clusterInst *edgeproto.ClusterInst) error {
	names, err := GetKubeNames(clusterInst, &edgeproto.App{}, &edgeproto.AppInst{})
	if err != nil {
		return err
	}
	configDir := GetConfigDirName(names)
	log.SpanLog(ctx, log.DebugLevelInfra, "CleanupClusterConfig remove dir", "configDir", configDir)
	err = pc.DeleteDir(ctx, client, configDir, pc.NoSudo)
	if err != nil {
		return fmt.Errorf("failed to delete cluster config dir %s: %v", configDir, err)
	}
	err = RemoveKubeconfigs(ctx, client, names)
	if err != nil {
		return err
	}
	return nil
}

func ClearCluster(ctx context.Context, client ssh.Client, clusterInst *edgeproto.ClusterInst) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "clearing cluster", "cluster", clusterInst.Key)
	names, err := GetKubeNames(clusterInst, &edgeproto.App{}, &edgeproto.AppInst{})
	if err != nil {
		return err
	}
	// For a single-tenant cluster, all config will be in one dir
	configDir := GetConfigDirName(names)
	if err := ClearClusterConfig(ctx, client, configDir, "", names.KconfArg); err != nil {
		return err
	}
	// For a multi-tenant cluster, each namespace will have a config dir
	cmd := fmt.Sprintf("kubectl %s get ns -o name", names.KconfArg)
	out, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error getting namespaces, %s: %s, %s", cmd, out, err)
	}
	for _, str := range strings.Split(out, "\n") {
		str = strings.TrimSpace(str)
		str = strings.TrimPrefix(str, "namespace/")
		if strings.HasPrefix(str, "kube-") || str == "default" || str == "" {
			continue
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "cleaning config for namespace", "namespace", str)
		nsNames := *names
		nsNames.InstanceNamespace = str
		configDir := GetConfigDirName(&nsNames)
		err = ClearClusterConfig(ctx, client, configDir, str, names.KconfArg)
		if err != nil {
			return err
		}
		cmd = fmt.Sprintf("kubectl %s delete ns %s", names.KconfArg, str)
		log.SpanLog(ctx, log.DebugLevelInfra, "deleting extra namespace", "cmd", cmd)
		out, err = client.Output(cmd)
		if err != nil {
			return fmt.Errorf("error deleting namespace, %s: %s, %s", cmd, out, err)
		}
	}

	// delete all helm installs (and leftover junk)
	cmd = fmt.Sprintf("helm %s ls -q", names.KconfArg)
	out, err = client.Output(cmd)
	if err != nil {
		if strings.Contains(out, "could not find tiller") {
			// helm not installed
			out = ""
		} else {
			return fmt.Errorf("error listing helm instances, %s: %s, %s", cmd, out, err)
		}
	}
	helmServs := []string{}
	for _, name := range strings.Split(out, "\n") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		cmd = fmt.Sprintf("helm %s delete %s", names.KconfArg, name)
		log.SpanLog(ctx, log.DebugLevelInfra, "deleting helm install", "cmd", cmd)
		out, err = client.Output(cmd)
		if err != nil && !strings.Contains(out, "not found") {
			return fmt.Errorf("error deleting helm install, %s: %s, %s", cmd, out, err)
		}
		helmServs = append(helmServs, name+"-pr-kubelet")
	}
	// If helm prometheus-operator 7.1.1 was installed, pr-kubelet services will
	// be leftover. Need to delete manually.
	if len(helmServs) > 0 {
		cmd = fmt.Sprintf("kubectl %s delete --ignore-not-found --namespace=kube-system service %s", names.KconfArg, strings.Join(helmServs, " "))
		log.SpanLog(ctx, log.DebugLevelInfra, "deleting helm services", "cmd", cmd)
		out, err = client.Output(cmd)
		if err != nil {
			return fmt.Errorf("error deleting helm services, %s: %s, %s", cmd, out, err)
		}
	}
	// If helm prometheus-operator was installed, CRDs will be leftover.
	// Need to delete manually.
	cmd = fmt.Sprintf("kubectl %s delete --ignore-not-found customresourcedefinitions prometheuses.monitoring.coreos.com servicemonitors.monitoring.coreos.com podmonitors.monitoring.coreos.com alertmanagers.monitoring.coreos.com alertmanagerconfigs.monitoring.coreos.com prometheusrules.monitoring.coreos.com probes.monitoring.coreos.com thanosrulers.monitoring.coreos.com", names.KconfArg)
	log.SpanLog(ctx, log.DebugLevelInfra, "deleting prometheus CRDs", "cmd", cmd)
	out, err = client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error deleting prometheus-operator CRDs, %s: %s, %s", cmd, out, err)
	}
	return nil
}

func ClearClusterConfig(ctx context.Context, client ssh.Client, configDir, namespace, kconfArg string) error {
	// if config dir doesn't exist, then there's no config
	cmd := fmt.Sprintf("stat %s", configDir)
	out, err := client.Output(cmd)
	log.SpanLog(ctx, log.DebugLevelInfra, "clear cluster config", "dir", configDir, "out", out, "err", err)
	if err != nil {
		if strings.Contains(out, "No such file or directory") {
			return nil
		}
		return err
	}
	nsArg := ""
	if namespace != "" {
		nsArg = "-n " + namespace
	}
	// delete all AppInsts configs in cluster
	cmd = fmt.Sprintf("kubectl %s delete %s -f %s", kconfArg, nsArg, configDir)
	log.SpanLog(ctx, log.DebugLevelInfra, "deleting cluster app", "cmd", cmd)
	out, err = client.Output(cmd)
	// bash returns "does not exist", zsh returns "no matches found"
	if err != nil && !strings.Contains(out, "does not exist") && !strings.Contains(out, "no matches found") {
		for _, msg := range strings.Split(out, "\n") {
			msg = strings.TrimSpace(msg)
			if msg == "" || strings.Contains(msg, " deleted") || strings.Contains(msg, "NotFound") {
				continue
			}
			return fmt.Errorf("error deleting cluster apps, %s: %s, %s", cmd, out, err)
		}
	}
	// delete all AppInst config files
	cmd = fmt.Sprintf("rm %s/*.yaml", configDir)
	log.SpanLog(ctx, log.DebugLevelInfra, "deleting all app config files", "cmd", cmd)
	out, err = client.Output(cmd)
	// bash returns "No such file or directory", zsh returns "no matches found"
	if err != nil && !strings.Contains(out, "No such file or directory") && !strings.Contains(out, "no matches found") {
		return fmt.Errorf("error deleting cluster config files, %s: %s, %s", cmd, out, err)
	}
	// remove configDir
	cmd = fmt.Sprintf("rmdir %s", configDir)
	log.SpanLog(ctx, log.DebugLevelInfra, "removing config dir", "cmd", cmd)
	out, err = client.Output(cmd)
	if err != nil && !strings.Contains(out, "Directory not empty") && !strings.Contains(out, "No such file or directory") {
		return fmt.Errorf("error removing config dir, %s: %s, %s", cmd, out, err)
	}
	return nil
}

func filterWarnings(out string) string {
	lines := strings.Split(out, "\n")
	linesFiltered := []string{}
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "warning: ") {
			continue
		}
		linesFiltered = append(linesFiltered, line)
	}
	return strings.Join(linesFiltered, "\n")
}

type KubectlVersion struct {
	ClientVersion    apimachineryversion.Info `json:"clientVersion"`
	ServerVersion    apimachineryversion.Info `json:"serverVersion"`
	KustomizeVersion string                   `json:"kustomizeVersion"`
}

func GetClusterVersion(ctx context.Context, client ssh.Client, kconfArg string) (string, error) {
	cmd := fmt.Sprintf("kubectl %s version --output=json", kconfArg)
	log.SpanLog(ctx, log.DebugLevelInfra, "k8s version", "cmd", cmd)
	out, err := client.Output(cmd)
	if err != nil {
		return "", fmt.Errorf("get cluster version failed, %s, %v", out, err)
	}
	// dispose of warnings
	out = filterWarnings(out)
	// parse output
	kv := KubectlVersion{}
	err = json.Unmarshal([]byte(out), &kv)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal kubectl version data, %s", err)
	}
	return fmt.Sprintf("%s.%s", kv.ServerVersion.Major, kv.ServerVersion.Minor), nil
}

func GetNodes(ctx context.Context, client ssh.Client, kconfArg string) ([]v1.Node, error) {
	// no logging here please, this is polled by clusterapi waitForCluster.
	cmd := fmt.Sprintf("kubectl %s get nodes --output=json", kconfArg)
	out, err := client.Output(cmd)
	if err != nil {
		return nil, fmt.Errorf("get nodes failed, %s, %v", out, err)
	}
	nodes := v1.NodeList{}
	err = json.Unmarshal([]byte(out), &nodes)
	if err != nil {
		return nil, err
	}
	return nodes.Items, nil
}

func GetNodeInfos(ctx context.Context, client ssh.Client, kconfArg string) ([]*edgeproto.NodeInfo, error) {
	nodes, err := GetNodes(ctx, client, kconfArg)
	if err != nil {
		return nil, err
	}
	info := []*edgeproto.NodeInfo{}
	for _, item := range nodes {
		nodeInfo := &edgeproto.NodeInfo{}
		nodeInfo.Name = item.Name
		nodeInfo.Allocatable = make(map[string]*edgeproto.Udec64)
		nodeInfo.Capacity = make(map[string]*edgeproto.Udec64)
		amdGPUCount := 0
		for res, quantity := range item.Status.Allocatable {
			name, dec, err := convertNodeResource(res, quantity)
			if err == nil && name == unsupportedResource {
				continue
			}
			if err != nil {
				return nil, err
			}
			nodeInfo.Allocatable[name] = dec
		}
		for res, quantity := range item.Status.Capacity {
			if res == cloudcommon.KubernetesAMDGPUResource {
				amdGPUCount = int(quantity.Value())
			}
			name, dec, err := convertNodeResource(res, quantity)
			if err == nil && name == unsupportedResource {
				continue
			}
			if err != nil {
				return nil, err
			}
			nodeInfo.Capacity[name] = dec
		}
		gpus, gpuSW, err := GetNodeGPUInfo(item.Labels)
		if err != nil {
			return nil, err
		}
		nodeInfo.Gpus = gpus
		nodeInfo.GpuSoftware = gpuSW
		// AMD does not provide gpu count in the labels, so infer from
		// the resource count
		if amdGPUCount > 0 && len(nodeInfo.Gpus) > 0 {
			nodeInfo.Gpus[0].Count = uint32(amdGPUCount)
		}
		info = append(info, nodeInfo)
	}
	return info, nil
}

// GetNodePools converts node infos into node pools
func GetNodePools(ctx context.Context, nodeInfos []*edgeproto.NodeInfo) []*edgeproto.NodePool {
	pools := map[string]*edgeproto.NodePool{}
	poolID := 0
	for _, nodeInfo := range nodeInfos {
		// we group nodes by capacity
		resVals := resspec.ResValMap{}
		for resName, val := range nodeInfo.Capacity {
			resVals.Add(resspec.NewDecimalResVal(resName, "", *val))
		}
		for _, gpu := range nodeInfo.Gpus {
			resVals.Add(resspec.NewWholeResVal(gpu.ModelId, "", uint64(gpu.Count)))
		}
		key := resVals.String()
		pool, ok := pools[key]
		if !ok {
			pool = &edgeproto.NodePool{}
			pool.Name = fmt.Sprintf("pool%02d", poolID)
			poolID++
			pool.NodeResources = &edgeproto.NodeResources{}
			pool.NodeResources.Vcpus = resVals.GetInt(cloudcommon.ResourceVcpus)
			pool.NodeResources.Ram = resVals.GetInt(cloudcommon.ResourceRamMb)
			pool.NodeResources.Disk = resVals.GetInt(cloudcommon.ResourceDiskGb)
			pools[key] = pool
			pool.NodeResources.Gpus = nodeInfo.Gpus
		}
		pool.NumNodes++
	}
	orderedPools := []*edgeproto.NodePool{}
	for _, p := range pools {
		orderedPools = append(orderedPools, p)
	}
	slices.SortFunc(orderedPools, func(a, b *edgeproto.NodePool) int {
		return cmp.Compare(a.Name, b.Name)
	})
	return orderedPools
}

var unsupportedResource = "unsupported"

func convertNodeResource(res v1.ResourceName, quantity resource.Quantity) (string, *edgeproto.Udec64, error) {
	var name string
	scale := uint64(1)
	switch res {
	case v1.ResourceCPU:
		name = cloudcommon.ResourceVcpus
	case v1.ResourceMemory:
		name = cloudcommon.ResourceRamMb
		scale = 1024 * 1024
	case v1.ResourceEphemeralStorage:
		name = cloudcommon.ResourceDiskGb
		scale = 1024 * 1024 * 1024
	default:
		// unsupported
		return unsupportedResource, nil, nil
	}
	dec, err := QuantityToUdec64(quantity)
	if err != nil {
		return name, nil, fmt.Errorf("Resource %s, %v", name, err)
	}
	if scale != 1 {
		dec.Whole /= scale
	}
	return name, dec, nil
}

func GetNodeGPUInfo(labels map[string]string) ([]*edgeproto.GPUResource, *edgeproto.GPUSoftwareInfo, error) {
	// Note: we only support one GPU type per node, although
	// the data structures are designed to support multiple
	// gpu types (i.e. an A100 and a T4) per node in the future.
	// I believe the nvidia gpu-operator also does not support
	// multiple gpu types currently.
	// Nvidia GPU operator labels:
	// https://github.com/NVIDIA/k8s-device-plugin/tree/main/docs/gpu-feature-discovery
	// https://github.com/NVIDIA/k8s-device-plugin/blob/main/README.md#catalog-of-labels

	gpu := &edgeproto.GPUResource{}
	gpuFound := false
	sw := &edgeproto.GPUSoftwareInfo{}
	for k, v := range labels {
		switch k {
		case "nvidia.com/gpu.product":
			gpu.ModelId = ensureGPUPrefix(v, cloudcommon.GPUVendorNVIDIA)
			gpu.Vendor = cloudcommon.GPUVendorNVIDIA
			gpuFound = true
		case "nvidia.com/gpu.memory":
			val, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to parse gpu memory %s: %s, %v", k, v, err)
			}
			// nvidia memory is specified in MB
			gpu.Memory = val / 1024
		case "nvidia.com/gpu.count":
			val, err := strconv.ParseUint(v, 10, 32)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to parse gpu count %s: %s, %v", k, v, err)
			}
			gpu.Count = uint32(val)
		case "nvidia.com/cuda.driver-version.full":
			sw.DriverVersion = v
		case "nvidia.com/cuda.runtime-version.full":
			sw.RuntimeVersion = v
		case "beta.amd.com/gpu.product-name":
			gpu.ModelId = ensureGPUPrefix(v, cloudcommon.GPUVendorAMD)
			gpu.Vendor = cloudcommon.GPUVendorAMD
			gpuFound = true
		case "amd.com/gpu.vram":
			if strings.HasSuffix(v, "G") {
				val, err := strconv.ParseUint(v[:len(v)-1], 10, 64)
				if err != nil {
					return nil, nil, fmt.Errorf("failed to parse gpu vram %s: %s, %v", k, v, err)
				}
				gpu.Memory = val
			} else {
				q, err := resource.ParseQuantity(v)
				if err != nil {
					return nil, nil, fmt.Errorf("failed to parse gpu vram %s: %s, %v", k, v, err)
				}
				gpu.Memory = uint64(q.Value() / 1024 / 1024 / 1024)
			}
		}
	}
	gpus := []*edgeproto.GPUResource{}
	if gpuFound {
		if gpu.Count == 0 {
			gpu.Count = 1
		}
		gpus = append(gpus, gpu)
	}
	return gpus, sw, nil
}

// GPU product names should be prefixed with the vendor already.
// If not, we need to prepend the vendor to ensure uniqueness.
func ensureGPUPrefix(product, vendor string) string {
	if !strings.HasPrefix(strings.ToLower(product), strings.ToLower(vendor)) {
		return fmt.Sprintf("%s-%s", vendor, product)
	}
	return product
}

// CheckNodesReady returns the number of ready and not ready nodes.
func CheckNodesReady(ctx context.Context, client ssh.Client, clusterInst *edgeproto.ClusterInst) (int, int, error) {
	kconf := GetKconfName(clusterInst)
	cmd := fmt.Sprintf("kubectl --kubeconfig=%s get nodes", kconf)
	out, err := client.Output(cmd)
	if err != nil {
		return 0, 0, err
	}
	statusIdx := 1
	readyCount := 0
	notReadyCount := 0
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		parts := strings.Fields(line)
		if len(parts) <= statusIdx {
			log.SpanLog(ctx, log.DebugLevelInfra, "check nodes ready ignoring invalid line, expected more parts", "parts", parts, "statusIdx", statusIdx)
			continue
		}
		if parts[statusIdx] == "STATUS" {
			continue // header
		}
		if parts[statusIdx] == "Ready" {
			readyCount++
		} else {
			notReadyCount++
		}
	}
	return readyCount, notReadyCount, nil
}

func WaitNodesReady(ctx context.Context, client ssh.Client, clusterInst *edgeproto.ClusterInst, wantReadyNodesCount int, delay time.Duration, retries int) error {
	for ii := 0; ii < retries; ii++ {
		ready, notReady, err := CheckNodesReady(ctx, client, clusterInst)
		if err == nil && ready >= wantReadyNodesCount {
			return nil
		}
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "wait nodes ready check got error, will retry", "cluster", clusterInst.Key, "err", err)
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "wait nodes ready not ready yet", "cluster", clusterInst.Key, "ready", ready, "not ready", notReady, "want ready", wantReadyNodesCount)
		}
		time.Sleep(delay)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "wait nodes ready timed out", "cluster", clusterInst.Key)
	return fmt.Errorf("timed out waiting for %s nodes to be ready", clusterInst.Key.GetKeyString())
}
