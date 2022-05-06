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

package awseks

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	awsgen "github.com/edgexr/edge-cloud-infra/crm-platforms/aws/aws-generic"
	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/vault"
)

type AwsEksPlatform struct {
	awsGenPf *awsgen.AwsGenericPlatform
}

type AwsEksResources struct {
	K8sClustersUsed           uint64
	MaxK8sNodesPerClusterUsed uint64
	TotalK8sNodesUsed         uint64
	NetworkLBsUsed            uint64
}

func (o *AwsEksPlatform) GetFeatures() *platform.Features {
	return &platform.Features{
		SupportsMultiTenantCluster:    true,
		SupportsKubernetesOnly:        true,
		KubernetesRequiresWorkerNodes: true,
		IPAllocatedPerService:         true,
	}
}

func (a *AwsEksPlatform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	return a.awsGenPf.GatherCloudletInfo(ctx, a.awsGenPf.GetAwsFlavorMatchPattern(), info)
}

// CreateClusterPrerequisites does nothing for now, but for outpost may need to create a vpc
func (a *AwsEksPlatform) CreateClusterPrerequisites(ctx context.Context, clusterName string) error {
	return nil
}

// RunClusterCreateCommand creates a kubernetes cluster on AWS
func (a *AwsEksPlatform) RunClusterCreateCommand(ctx context.Context, clusterName string, numNodes uint32, flavor string) error {
	log.DebugLog(log.DebugLevelInfra, "RunClusterCreateCommand", "clusterName", clusterName, "numNodes:", numNodes, "NodeFlavor", flavor)
	// Can not create a managed cluster if numNodes is 0
	region := a.awsGenPf.GetAwsRegion()
	out, err := infracommon.Sh(a.awsGenPf.AccountAccessVars).Command("eksctl", "create", "--region", region, "cluster", "--name", clusterName, "--node-type", flavor, "--nodes", fmt.Sprintf("%d", numNodes), "--managed").CombinedOutput()
	if err != nil {
		log.DebugLog(log.DebugLevelInfra, "Create eks cluster failed", "clusterName", clusterName, "out", string(out), "err", err)
		return fmt.Errorf("Create eks cluster failed: %s - %v", string(out), err)
	}
	return nil
}

// RunClusterDeleteCommand removes the kubernetes cluster on AWS
func (a *AwsEksPlatform) RunClusterDeleteCommand(ctx context.Context, clusterName string) error {
	log.DebugLog(log.DebugLevelInfra, "RunClusterDeleteCommand", "clusterName:", clusterName)
	out, err := infracommon.Sh(a.awsGenPf.AccountAccessVars).Command("eksctl", "delete", "cluster", "--name", clusterName).CombinedOutput()
	if err != nil {
		log.DebugLog(log.DebugLevelInfra, "Delete eks cluster failed", "clusterName", clusterName, "out", string(out), "err", err)
		return fmt.Errorf("Delete eks cluster failed: %s - %v", string(out), err)
	}
	return nil
}

// GetCredentials retrieves kubeconfig credentials from AWS
func (a *AwsEksPlatform) GetCredentials(ctx context.Context, clusterName string) error {
	log.DebugLog(log.DebugLevelInfra, "GetCredentials", "clusterName:", clusterName)
	out, err := infracommon.Sh(a.awsGenPf.AccountAccessVars).Command("eksctl", "utils", "write-kubeconfig", "--cluster", clusterName).CombinedOutput()
	if err != nil {
		log.DebugLog(log.DebugLevelInfra, "Error in write-kubeconfig", "out", string(out), "err", err)
		return fmt.Errorf("Error in write-kubeconfig: %s - %v", string(out), err)
	}
	return nil
}

func (a *AwsEksPlatform) SetProperties(props *infracommon.InfraProperties) error {
	a.awsGenPf = &awsgen.AwsGenericPlatform{Properties: props}
	return nil
}

func (a *AwsEksPlatform) GetProviderSpecificProps(ctx context.Context) (map[string]*edgeproto.PropertyInfo, error) {
	return a.awsGenPf.GetProviderSpecificProps(ctx)
}

func (a *AwsEksPlatform) Login(ctx context.Context) error {
	return nil
}

func (a *AwsEksPlatform) NameSanitize(clusterName string) string {
	return strings.NewReplacer(".", "").Replace(clusterName)
}

func (a *AwsEksPlatform) InitApiAccessProperties(ctx context.Context, accessApi platform.AccessApi, vars map[string]string) error {
	return nil
}

func (a *AwsEksPlatform) GetAccessData(ctx context.Context, cloudlet *edgeproto.Cloudlet, region string, vaultConfig *vault.Config, dataType string, arg []byte) (map[string]string, error) {
	log.SpanLog(ctx, log.DebugLevelApi, "AwsEks GetAccessData", "dataType", dataType)
	return a.awsGenPf.GetAccessData(ctx, cloudlet, region, vaultConfig, dataType, arg)
}

func (a *AwsEksPlatform) getClusterList(ctx context.Context) ([]awsgen.AWSCluster, error) {
	clusters := []awsgen.AWSCluster{}
	region := a.awsGenPf.GetAwsRegion()
	out, err := infracommon.Sh(a.awsGenPf.AccountAccessVars).Command(
		"eksctl", "get", "cluster",
		"--region", region,
		"--output", "json",
		"--verbose", "0",
	).CombinedOutput()
	if err != nil {
		log.DebugLog(log.DebugLevelInfra, "Failed to get eks cluster list", "out", string(out), "err", err)
		return nil, fmt.Errorf("Failed to get eks cluster list: %s - %v", string(out), err)
	}
	err = json.Unmarshal(out, &clusters)
	if err != nil {
		return nil, fmt.Errorf("cannot unmarshal eks cluster list, %s, %v", out, err)
	}

	return clusters, nil
}

func (a *AwsEksPlatform) getClusterNodeGroupList(ctx context.Context, clusterName string) ([]awsgen.AWSClusterNodeGroup, error) {
	nodegroups := []awsgen.AWSClusterNodeGroup{}
	region := a.awsGenPf.GetAwsRegion()
	out, err := infracommon.Sh(a.awsGenPf.AccountAccessVars).Command(
		"eksctl", "get", "nodegroup",
		"--cluster", clusterName,
		"--region", region,
		"--output", "json",
		"--verbose", "0",
	).CombinedOutput()
	if err != nil {
		log.DebugLog(log.DebugLevelInfra, "Failed to get eks cluster list", "out", string(out), "err", err)
		return nil, fmt.Errorf("Failed to get eks cluster list: %s - %v", string(out), err)
	}
	err = json.Unmarshal(out, &nodegroups)
	if err != nil {
		return nil, fmt.Errorf("cannot unmarshal eks cluster list, %s, %v", out, err)
	}

	return nodegroups, nil
}

func (a *AwsEksPlatform) GetCloudletInfraResourcesInfo(ctx context.Context) ([]edgeproto.InfraResource, error) {
	clusterList, err := a.getClusterList(ctx)
	if err != nil {
		return nil, err
	}
	k8sNodeCount := 0
	for _, cluster := range clusterList {
		nodeGroupList, err := a.getClusterNodeGroupList(ctx, cluster.Metadata.Name)
		if err != nil {
			return nil, err
		}
		for _, nodeGroup := range nodeGroupList {
			k8sNodeCount += nodeGroup.DesiredCapacity
		}
	}
	awsELB, err := a.awsGenPf.GetAWSELBs(ctx)
	if err != nil {
		return nil, err
	}
	eksSvcQuotas, err := a.awsGenPf.GetServiceQuotas(ctx, awsgen.AWSServiceCodeEKS)
	if err != nil {
		return nil, err
	}
	elbSvcQuotas, err := a.awsGenPf.GetServiceQuotas(ctx, awsgen.AWSServiceCodeELB)
	if err != nil {
		return nil, err
	}
	clusterListMax := uint64(0)
	clusterNodeGroupsMax := uint64(0)
	clusterNodesMax := uint64(0)
	networkLBMax := uint64(0)
	for _, eksSvcQuota := range eksSvcQuotas {
		switch eksSvcQuota.Code {
		case awsgen.AWSServiceQuotaClusters:
			clusterListMax = uint64(eksSvcQuota.Value)
		case awsgen.AWSServiceQuotaNodesPerNodeGroup:
			clusterNodesMax = uint64(eksSvcQuota.Value)
		case awsgen.AWSServiceQuotaNodeGroupsPerCluster:
			clusterNodeGroupsMax = uint64(eksSvcQuota.Value)
		}
	}
	clusterMaxTotalK8sNodes := uint64(0)
	if clusterNodeGroupsMax > 0 && clusterNodesMax > 0 {
		clusterMaxTotalK8sNodes = clusterNodeGroupsMax * clusterNodesMax
	}
	for _, elbSvcQuota := range elbSvcQuotas {
		switch elbSvcQuota.Code {
		case awsgen.AWSServiceQuotaNetworkLBPerRegion:
			networkLBMax = uint64(elbSvcQuota.Value)
		}
	}
	resInfo := []edgeproto.InfraResource{
		edgeproto.InfraResource{
			Name:          cloudcommon.ResourceK8sClusters,
			Value:         uint64(len(clusterList)),
			InfraMaxValue: clusterListMax,
		},
		edgeproto.InfraResource{
			Name: cloudcommon.ResourceMaxK8sNodesPerCluster,
			// We don't care about infra's max k8s nodes cluster deployed,
			// hence we don't fetch its value here
			InfraMaxValue: clusterNodesMax,
		},
		edgeproto.InfraResource{
			Name:          cloudcommon.ResourceTotalK8sNodes,
			Value:         uint64(k8sNodeCount),
			InfraMaxValue: clusterMaxTotalK8sNodes,
		},
		edgeproto.InfraResource{
			Name:          cloudcommon.ResourceNetworkLBs,
			Value:         uint64(len(awsELB.LoadBalancerDescriptions)),
			InfraMaxValue: networkLBMax,
		},
	}
	return resInfo, nil
}

func (a *AwsEksPlatform) GetCloudletResourceQuotaProps(ctx context.Context) (*edgeproto.CloudletResourceQuotaProps, error) {
	return &edgeproto.CloudletResourceQuotaProps{
		Properties: []edgeproto.InfraResource{
			edgeproto.InfraResource{
				Name:        cloudcommon.ResourceK8sClusters,
				Description: cloudcommon.ResourceQuotaDesc[cloudcommon.ResourceK8sClusters],
			},
			edgeproto.InfraResource{
				Name:        cloudcommon.ResourceMaxK8sNodesPerCluster,
				Description: cloudcommon.ResourceQuotaDesc[cloudcommon.ResourceMaxK8sNodesPerCluster],
			},
			edgeproto.InfraResource{
				Name:        cloudcommon.ResourceTotalK8sNodes,
				Description: cloudcommon.ResourceQuotaDesc[cloudcommon.ResourceTotalK8sNodes],
			},
			edgeproto.InfraResource{
				Name:        cloudcommon.ResourceNetworkLBs,
				Description: cloudcommon.ResourceQuotaDesc[cloudcommon.ResourceNetworkLBs],
			},
		},
	}, nil
}

func getAwsEksResources(ctx context.Context, cloudlet *edgeproto.Cloudlet, resources []edgeproto.VMResource) *AwsEksResources {
	var eksRes AwsEksResources
	// ClusterInstKey -> Node count
	uniqueClusters := make(map[edgeproto.ClusterInstKey]int)
	networkLBs := 0
	k8sNodeCount := 0
	for _, vmRes := range resources {
		if vmRes.Type == cloudcommon.ResourceTypeK8sLBSvc {
			networkLBs++
			continue
		}
		if vmRes.Type != cloudcommon.NodeTypeK8sClusterNode.String() {
			continue
		}
		k8sNodeCount++
		if _, ok := uniqueClusters[vmRes.Key]; !ok {
			uniqueClusters[vmRes.Key] = 1
		} else {
			uniqueClusters[vmRes.Key] += 1
		}
	}
	maxK8sNodesPerCluster := 0
	for _, v := range uniqueClusters {
		if v > maxK8sNodesPerCluster {
			maxK8sNodesPerCluster = v
		}
	}
	eksRes.K8sClustersUsed = uint64(len(uniqueClusters))
	eksRes.MaxK8sNodesPerClusterUsed = uint64(maxK8sNodesPerCluster)
	eksRes.TotalK8sNodesUsed = uint64(k8sNodeCount)
	eksRes.NetworkLBsUsed = uint64(networkLBs)
	log.SpanLog(ctx, log.DebugLevelApi, "AwsEks getAwsEksResources", "cloudletKey", cloudlet.Key, "resources", eksRes)
	return &eksRes
}

// called by controller, make sure it doesn't make any calls to infra API
func (a *AwsEksPlatform) GetClusterAdditionalResources(ctx context.Context, cloudlet *edgeproto.Cloudlet, vmResources []edgeproto.VMResource, infraResMap map[string]edgeproto.InfraResource) map[string]edgeproto.InfraResource {
	log.SpanLog(ctx, log.DebugLevelApi, "AwsEks GetClusterAdditionalResources", "cloudletKey", cloudlet.Key)
	// resource name -> resource units
	cloudletRes := map[string]string{
		cloudcommon.ResourceK8sClusters:           "",
		cloudcommon.ResourceMaxK8sNodesPerCluster: "",
		cloudcommon.ResourceTotalK8sNodes:         "",
		cloudcommon.ResourceNetworkLBs:            "",
	}
	resInfo := make(map[string]edgeproto.InfraResource)
	for resName, resUnits := range cloudletRes {
		resMax := uint64(0)
		if infraRes, ok := infraResMap[resName]; ok {
			resMax = infraRes.InfraMaxValue
		}
		resInfo[resName] = edgeproto.InfraResource{
			Name:          resName,
			InfraMaxValue: resMax,
			Units:         resUnits,
		}
	}

	eksRes := getAwsEksResources(ctx, cloudlet, vmResources)
	outInfo, ok := resInfo[cloudcommon.ResourceK8sClusters]
	if ok {
		outInfo.Value += eksRes.K8sClustersUsed
		resInfo[cloudcommon.ResourceK8sClusters] = outInfo
	}
	outInfo, ok = resInfo[cloudcommon.ResourceMaxK8sNodesPerCluster]
	if ok {
		outInfo.Value = eksRes.MaxK8sNodesPerClusterUsed
		resInfo[cloudcommon.ResourceMaxK8sNodesPerCluster] = outInfo
	}
	outInfo, ok = resInfo[cloudcommon.ResourceTotalK8sNodes]
	if ok {
		outInfo.Value = eksRes.TotalK8sNodesUsed
		resInfo[cloudcommon.ResourceTotalK8sNodes] = outInfo
	}
	outInfo, ok = resInfo[cloudcommon.ResourceNetworkLBs]
	if ok {
		outInfo.Value += eksRes.NetworkLBsUsed
		resInfo[cloudcommon.ResourceNetworkLBs] = outInfo
	}
	return resInfo
}

func (a *AwsEksPlatform) GetClusterAdditionalResourceMetric(ctx context.Context, cloudlet *edgeproto.Cloudlet, resMetric *edgeproto.Metric, resources []edgeproto.VMResource) error {
	eksRes := getAwsEksResources(ctx, cloudlet, resources)

	resMetric.AddIntVal(cloudcommon.ResourceMetricK8sClusters, eksRes.K8sClustersUsed)
	resMetric.AddIntVal(cloudcommon.ResourceMetricMaxK8sNodesPerCluster, eksRes.MaxK8sNodesPerClusterUsed)
	resMetric.AddIntVal(cloudcommon.ResourceMetricTotalK8sNodes, eksRes.TotalK8sNodesUsed)
	resMetric.AddIntVal(cloudcommon.ResourceMetricNetworkLBs, eksRes.NetworkLBsUsed)
	return nil
}
