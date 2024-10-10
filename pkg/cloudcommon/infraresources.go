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
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
)

var (
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

func ValidateCloudletResourceQuotas(ctx context.Context, quotaProps []edgeproto.InfraResource, curRes map[string]*edgeproto.InfraResource, resourceQuotas []edgeproto.ResourceQuota) error {
	log.SpanLog(ctx, log.DebugLevelApi, "validate cloudlet resource quotas", "curResources", curRes, "quotas", resourceQuotas)
	resPropsMap := make(map[string]struct{})
	resPropsNames := []string{}
	for _, prop := range quotaProps {
		resPropsMap[prop.Name] = struct{}{}
		resPropsNames = append(resPropsNames, prop.Name)
	}
	for resName, _ := range CommonCloudletResources {
		resPropsMap[resName] = struct{}{}
		resPropsNames = append(resPropsNames, resName)
	}
	sort.Strings(resPropsNames)
	for _, resQuota := range resourceQuotas {
		if _, ok := resPropsMap[resQuota.Name]; !ok {
			return fmt.Errorf("Invalid quota name: %s, valid names are %s", resQuota.Name, strings.Join(resPropsNames, ", "))
		}
		if curRes == nil {
			continue
		}
		infraRes, ok := curRes[resQuota.Name]
		if !ok {
			continue
		}
		if infraRes.InfraMaxValue > 0 && resQuota.Value > infraRes.InfraMaxValue {
			return fmt.Errorf("Resource quota %s exceeded max supported value: %d", resQuota.Name, infraRes.InfraMaxValue)
		}
		// Note: not a failure if currently used value exceeds quota.
		// It just means no more resources can be consumed until
		// current value drops below quota.
		// Also, curRes has the current value as reported by the
		// infrastructure. But not all infras may report the current
		// usage.
	}
	return nil
}

var GPUResourceLimitName = "nvidia.com/gpu"

func GetGPUCount(optResMap map[string]string) uint64 {
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
	return GetGPUCount(kr.GpuPool.TotalOptRes)
}

func NodeResourcesGPUCount(nr *edgeproto.NodeResources) uint64 {
	if nr == nil {
		return 0
	}
	return GetGPUCount(nr.OptResMap)
}

func NodePoolResourcesGPUCount(npr *edgeproto.NodePoolResources) uint64 {
	if npr == nil {
		return 0
	}
	return GetGPUCount(npr.TotalOptRes)
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
