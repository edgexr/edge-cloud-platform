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

package cloudcommon

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
)

const (
	// Common platform resources
	ResourceRamMb       = "RAM"
	ResourceVcpus       = "vCPUs"
	ResourceDiskGb      = "Disk"
	ResourceGpus        = "GPUs"
	ResourceExternalIPs = "External IPs"

	// Platform specific resources
	ResourceInstances             = "Instances"
	ResourceFloatingIPs           = "Floating IPs"
	ResourceK8sClusters           = "K8s Clusters"
	ResourceMaxK8sNodesPerCluster = "Maximum K8s Nodes Per Cluster"
	ResourceTotalK8sNodes         = "Total Number Of K8s Nodes"
	ResourceNetworkLBs            = "Network Load Balancers"

	// Resource units
	ResourceRamUnits  = "MB"
	ResourceDiskUnits = "GB"

	// Resource metrics
	ResourceMetricRamMB                 = "ramUsed"
	ResourceMetricVcpus                 = "vcpusUsed"
	ResourceMetricDisk                  = "diskUsed"
	ResourceMetricGpus                  = "gpusUsed"
	ResourceMetricInstances             = "instancesUsed"
	ResourceMetricExternalIPs           = "externalIpsUsed"
	ResourceMetricFloatingIPs           = "floatingIpsUsed"
	ResourceMetricK8sClusters           = "k8sClustersUsed"
	ResourceMetricMaxK8sNodesPerCluster = "maxK8sNodesPerClusterUsed"
	ResourceMetricTotalK8sNodes         = "totalK8sNodesUsed"
	ResourceMetricNetworkLBs            = "networkLBsUsed"

	// Resource types
	ResourceTypeGeneric = "" // default resource type for vcpu, ram, etc
	ResourceTypeGPU     = "gpu"
	ResourceTypeFlavor  = "flavor"

	// GPU vendors
	GPUVendorAMD    = "amd"
	GPUVendorNVIDIA = "nvidia"
	// Kubernetes GPU resource names
	KubernetesNvidiaGPUResource = "nvidia.com/gpu"
	KubernetesAMDGPUResource    = "amd.com/gpu"
)

var (
	// Common cloudlet resources
	CommonCloudletResources = map[string]string{
		ResourceRamMb:       ResourceRamUnits,
		ResourceVcpus:       "",
		ResourceDiskGb:      ResourceDiskUnits,
		ResourceGpus:        "",
		ResourceExternalIPs: "",
	}

	ResourceQuotaDesc = map[string]string{
		ResourceRamMb:                 "Limit on RAM available (MB)",
		ResourceVcpus:                 "Limit on vCPUs available",
		ResourceDiskGb:                "Limit on disk available (GB)",
		ResourceGpus:                  "Limit on GPUs available",
		ResourceExternalIPs:           "Limit on external IPs available",
		ResourceInstances:             "Limit on number of instances that can be provisioned",
		ResourceFloatingIPs:           "Limit on number of floating IPs that can be created",
		ResourceK8sClusters:           "Limit on number of k8s clusters than can be created",
		ResourceMaxK8sNodesPerCluster: "Limit on maximum number of k8s nodes that can be created as part of k8s cluster",
		ResourceTotalK8sNodes:         "Limit on total number of k8s nodes that can be created altogether",
		ResourceNetworkLBs:            "Limit on maximum number of network load balancers that can be created in a region",
	}

	ResourceMetricsDesc = map[string]string{
		ResourceMetricRamMB:                 "RAM Usage (MB)",
		ResourceMetricVcpus:                 "vCPU Usage",
		ResourceMetricDisk:                  "Disk Usage (GB)",
		ResourceMetricGpus:                  "GPU Usage",
		ResourceMetricExternalIPs:           "External IP Usage",
		ResourceMetricInstances:             "VM Instance Usage",
		ResourceMetricFloatingIPs:           "Floating IP Usage",
		ResourceMetricK8sClusters:           "K8s Cluster Usage",
		ResourceMetricMaxK8sNodesPerCluster: "Maximum K8s Nodes Per Cluster Usage",
		ResourceMetricTotalK8sNodes:         "Total K8s Nodes Usage",
		ResourceMetricNetworkLBs:            "Network Load Balancer Usage",
	}

	CommonResourceQuotaProps = GetCommonResourceQuotaProps()
)

func usageAlertWarningLabels(ctx context.Context, key *edgeproto.CloudletKey, alertname, warning string) map[string]string {
	labels := make(map[string]string)
	labels["alertname"] = alertname
	labels[AlertScopeTypeTag] = AlertScopeCloudlet
	labels[edgeproto.CloudletKeyTagName] = key.Name
	labels[edgeproto.CloudletKeyTagOrganization] = key.Organization
	labels["warning"] = warning
	return labels
}

// Raise the alarm when there are cloudlet resource usage warnings
func CloudletResourceUsageAlerts(ctx context.Context, key *edgeproto.CloudletKey, warnings []string) []edgeproto.Alert {
	alerts := []edgeproto.Alert{}
	for _, warning := range warnings {
		alert := edgeproto.Alert{}
		alert.State = "firing"
		alert.ActiveAt = dme.Timestamp{}
		ts := time.Now()
		alert.ActiveAt.Seconds = ts.Unix()
		alert.ActiveAt.Nanos = int32(ts.Nanosecond())
		alert.Labels = usageAlertWarningLabels(ctx, key, AlertCloudletResourceUsage, warning)
		alert.Annotations = make(map[string]string)
		alert.Annotations[AlertAnnotationTitle] = AlertCloudletResourceUsage
		alert.Annotations[AlertAnnotationDescription] = warning
		alerts = append(alerts, alert)
	}
	return alerts
}

// GetCommonResourceQuotaProps returns the common resource quota
// properties. This is for convenience, it is not required that
// every platform support these quotas.
func GetCommonResourceQuotaProps(additionalResources ...string) []edgeproto.InfraResource {
	props := []edgeproto.InfraResource{}
	for res, _ := range CommonCloudletResources {
		props = append(props, edgeproto.InfraResource{
			Name:        res,
			Description: ResourceQuotaDesc[res],
		})
	}
	for _, res := range additionalResources {
		props = append(props, edgeproto.InfraResource{
			Name:        res,
			Description: ResourceQuotaDesc[res],
		})
	}
	return props
}

func GetGPUCount(gpus []*edgeproto.GPUResource, optResMap map[string]string) uint64 {
	count := uint64(0)
	for _, gpu := range gpus {
		count += uint64(gpu.Count)
	}
	// deprecated GPU spec from optResMap
	count += GetOptResGPUCount(optResMap)
	return count
}

func GetOptResGPUCount(optResMap map[string]string) uint64 {
	if optResMap == nil {
		return 0
	}
	val, ok := optResMap["gpu"]
	if !ok {
		return 0
	}
	_, _, count, err := ParseOptResVal(val)
	if err != nil {
		// invalid spec
		return 0
	}
	return uint64(count)
}

func KuberentesResourcesGPUCount(kr *edgeproto.KubernetesResources) uint64 {
	if kr == nil || kr.GpuPool == nil {
		return 0
	}
	return GetGPUCount(kr.GpuPool.TotalGpus, kr.GpuPool.TotalOptRes)
}

func NodeResourcesGPUCount(nr *edgeproto.NodeResources) uint64 {
	if nr == nil {
		return 0
	}
	return GetGPUCount(nr.Gpus, nr.OptResMap)
}

func NodePoolResourcesGPUCount(npr *edgeproto.NodePoolResources) uint64 {
	if npr == nil {
		return 0
	}
	return GetGPUCount(npr.TotalGpus, npr.TotalOptRes)
}

func AppInstGpuCount(appInst *edgeproto.AppInst) uint64 {
	if appInst.KubernetesResources != nil {
		return KuberentesResourcesGPUCount(appInst.KubernetesResources)
	}
	if appInst.NodeResources != nil {
		return NodeResourcesGPUCount(appInst.NodeResources)
	}
	return 0
}

// ParseOptResVal decodes an optional resource spec string of
// format "pci:1" or "vgpu:A100:2" into its respective parts
// of type, spec(alias), and count.
func ParseOptResVal(resStr string) (string, string, int, error) {
	typ := ""
	spec := ""
	count := 0
	values := strings.Split(resStr, ":")
	if len(values) == 1 {
		return typ, spec, count, fmt.Errorf("missing mandatory resource count for %s, ex: optresmap=gpu=gpu:1", resStr)
	}
	var countStr string
	var err error
	if len(values) == 2 {
		typ = values[0]
		countStr = values[1]
	} else if len(values) == 3 {
		typ = values[0]
		spec = values[1]
		countStr = values[2]
	} else {
		return typ, spec, count, fmt.Errorf("invalid optresmap value %s, should be of form gpu:1 or pci:T4:2", resStr)
	}
	if count, err = strconv.Atoi(countStr); err != nil {
		return typ, spec, count, fmt.Errorf("non-numeric resource count %s in optres value %s", values[1], resStr)
	}
	return typ, spec, count, nil
}

type ValidateGPUOptions struct {
	requiresMemory bool
}

type ValidateGPUOp func(*ValidateGPUOptions)

func WithRequiresGPUMemory() ValidateGPUOp {
	return func(opts *ValidateGPUOptions) {
		opts.requiresMemory = true
	}
}

// ValidateGPUs validates GPU resources
func ValidateGPUs(gpus []*edgeproto.GPUResource, ops ...ValidateGPUOp) error {
	opts := &ValidateGPUOptions{}
	for _, opt := range ops {
		opt(opts)
	}
	for _, gpu := range gpus {
		if gpu.ModelId == "" {
			return errors.New("gpu model id cannot be empty")
		}
		if gpu.Count == 0 {
			// just assume 1, as more than 1 is likely not supported
			gpu.Count = 1
		}
		if gpu.Vendor == "" {
			modelid := strings.ToLower(gpu.ModelId)
			if strings.HasPrefix(modelid, GPUVendorAMD) {
				gpu.Vendor = GPUVendorAMD
			} else if strings.HasPrefix(modelid, GPUVendorNVIDIA) {
				gpu.Vendor = GPUVendorNVIDIA
			} else {
				return fmt.Errorf("gpu vendor for model %q is empty and cannot be inferred from model ID", gpu.ModelId)
			}
		}
		if opts.requiresMemory && gpu.Memory == 0 {
			return errors.New("gpu memory cannot be 0")
		}
	}
	return nil
}

// ValidateInfraGPUs validates the GPU resources validates
// gpu information provided by the edge-site specific
// platform.
func ValidateInfraGPUs(gpus []*edgeproto.GPUResource) error {
	return ValidateGPUs(gpus, WithRequiresGPUMemory())
}
