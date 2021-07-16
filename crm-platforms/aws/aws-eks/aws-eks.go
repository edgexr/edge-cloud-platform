package awseks

import (
	"context"
	"fmt"
	"strings"

	awsgen "github.com/mobiledgex/edge-cloud-infra/crm-platforms/aws/aws-generic"
	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vault"
)

type AwsEksPlatform struct {
	awsGenPf *awsgen.AwsGenericPlatform
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
	return a.awsGenPf.GatherCloudletInfo(ctx, "", info)
}

// CreateClusterPrerequisites does nothing for now, but for outpost may need to create a vpc
func (a *AwsEksPlatform) CreateClusterPrerequisites(ctx context.Context, clusterName string) error {
	return nil
}

// RunClusterCreateCommand creates a kubernetes cluster on AWS
func (a *AwsEksPlatform) RunClusterCreateCommand(ctx context.Context, clusterName string, numNodes uint32, flavor string) error {
	log.DebugLog(log.DebugLevelInfra, "RunClusterCreateCommand", "clusterName", clusterName, "numNodes:", numNodes, "NodeFlavor", flavor)
	// Can not create a managed cluster if numNodes is 0
	var out []byte
	var err error
	region := a.awsGenPf.GetAwsRegion()
	if numNodes == 0 {
		out, err = infracommon.Sh(a.awsGenPf.AccountAccessVars).Command("eksctl", "create", "--region", region, "cluster", "--name", clusterName, "--node-type", flavor, "--nodes", fmt.Sprintf("%d", numNodes)).CombinedOutput()
	} else {
		out, err = infracommon.Sh(a.awsGenPf.AccountAccessVars).Command("eksctl", "create", "--region", region, "cluster", "--name", clusterName, "--node-type", flavor, "--nodes", fmt.Sprintf("%d", numNodes), "--managed").CombinedOutput()
	}
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
	out, err := infracommon.Sh(a.awsGenPf.AccountAccessVars).Command("eksctl", "utils", "write-kubeconfig", clusterName).CombinedOutput()
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

func (a *AwsEksPlatform) GetFlavorList(ctx context.Context) ([]*edgeproto.FlavorInfo, error) {
	return a.awsGenPf.GetFlavorList(ctx, "")
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
