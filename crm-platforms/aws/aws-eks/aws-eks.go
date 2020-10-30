package awseks

import (
	"context"
	"fmt"
	"strings"

	"github.com/codeskyblue/go-sh"
	awsgen "github.com/mobiledgex/edge-cloud-infra/crm-platforms/aws/aws-generic"
	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	pf "github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vault"
)

type AwsEksPlatform struct {
	awsGenPf *awsgen.AwsGenericPlatform
}

func (a *AwsEksPlatform) GatherCloudletInfo(ctx context.Context, vaultConfig *vault.Config, info *edgeproto.CloudletInfo) error {
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
		out, err = sh.Command("eksctl", "create", "--region", region, "cluster", "--name", clusterName, "--node-type", flavor, "--nodes", fmt.Sprintf("%d", numNodes)).CombinedOutput()
	} else {
		out, err = sh.Command("eksctl", "create", "--region", region, "cluster", "--name", clusterName, "--node-type", flavor, "--nodes", fmt.Sprintf("%d", numNodes), "--managed").CombinedOutput()
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
	out, err := sh.Command("eksctl", "delete", "cluster", "--name", clusterName).CombinedOutput()
	if err != nil {
		log.DebugLog(log.DebugLevelInfra, "Delete eks cluster failed", "clusterName", clusterName, "out", string(out), "err", err)
		return fmt.Errorf("Delete eks cluster failed: %s - %v", string(out), err)
	}
	return nil
}

// GetCredentials retrieves kubeconfig credentials from AWS
func (a *AwsEksPlatform) GetCredentials(ctx context.Context, clusterName string) error {
	log.DebugLog(log.DebugLevelInfra, "GetCredentials", "clusterName:", clusterName)
	out, err := sh.Command("eksctl", "utils", "write-kubeconfig", clusterName).CombinedOutput()
	if err != nil {
		log.DebugLog(log.DebugLevelInfra, "Error in write-kubeconfig", "out", string(out), "err", err)
		return fmt.Errorf("Error in write-kubeconfig: %s - %v", string(out), err)
	}
	return nil
}

func (a *AwsEksPlatform) SetProperties(props *infracommon.InfraProperties) {
	a.awsGenPf = &awsgen.AwsGenericPlatform{Properties: props}
}

func (a *AwsEksPlatform) GetFlavorList(ctx context.Context) ([]*edgeproto.FlavorInfo, error) {
	return a.awsGenPf.GetFlavorList(ctx, "")
}

func (a *AwsEksPlatform) GetProviderSpecificProps(ctx context.Context, pfconfig *pf.PlatformConfig, vaultConfig *vault.Config) (map[string]*edgeproto.PropertyInfo, error) {
	return a.awsGenPf.GetProviderSpecificProps(ctx, pfconfig, vaultConfig)
}

func (a *AwsEksPlatform) Login(ctx context.Context, vaultConfig *vault.Config) error {
	return nil
}

func (a *AwsEksPlatform) NameSanitize(clusterName string) string {
	return strings.NewReplacer(".", "").Replace(clusterName)
}
