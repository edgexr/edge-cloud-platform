package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	sh "github.com/codeskyblue/go-sh"
	"github.com/mobiledgex/edge-cloud-infra/mexos"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vault"
	ssh "github.com/mobiledgex/golang-ssh"
)

type Platform struct {
	props       edgeproto.AzureProperties // AzureProperties should be moved to edge-cloud-infra
	config      platform.PlatformConfig
	vaultConfig *vault.Config
	commonPf    mexos.CommonPlatform
	envVars     map[string]*mexos.PropertyInfo
}

var azureProps = map[string]*mexos.PropertyInfo{
	"MEX_AZURE_LOCATION": &mexos.PropertyInfo{},
	"MEX_AZURE_USER":     &mexos.PropertyInfo{},
	"MEX_AZURE_PASS": &mexos.PropertyInfo{
		Secret: true,
	},
}

func (s *Platform) GetType() string {
	return "azure"
}

func (s *Platform) Init(ctx context.Context, platformConfig *platform.PlatformConfig, updateCallback edgeproto.CacheUpdateCallback) error {
	vaultConfig, err := vault.BestConfig(platformConfig.VaultAddr)
	if err != nil {
		return err
	}
	s.vaultConfig = vaultConfig

	if err := s.commonPf.InitInfraCommon(ctx, vaultConfig, platformConfig.EnvVars); err != nil {
		return err
	}

	s.envVars = azureProps
	mexos.SetPropsFromVars(ctx, s.envVars, platformConfig.EnvVars)

	s.config = *platformConfig
	s.props.Location = s.envVars["MEX_AZURE_LOCATION"].Value
	if s.props.Location == "" {
		return fmt.Errorf("Env variable MEX_AZURE_LOCATION not set")
	}
	/** resource group currently derived from cloudletName + cluster name
			s.props.ResourceGroup = s.envVars["MEX_AZURE_RESOURCE_GROUP"]
			if s.props.ResourceGroup == "" {
				return fmt.Errorf("Env variable MEX_AZURE_RESOURCE_GROUP not set")
	                }
	*/
	s.props.UserName = s.envVars["MEX_AZURE_USER"].Value
	if s.props.UserName == "" {
		return fmt.Errorf("Env variable MEX_AZURE_USER not set, check contents of MEXENV_URL")
	}
	s.props.Password = s.envVars["MEX_AZURE_PASS"].Value
	if s.props.Password == "" {
		return fmt.Errorf("Env variable MEX_AZURE_PASS not set, check contents of MEXENV_URL")
	}

	return nil
}

type AZName struct {
	LocalizedValue string
	Value          string
}

type AZLimit struct {
	CurrentValue string
	Limit        string
	LocalName    string
	Name         AZName
}

type AZFlavor struct {
	Disk  int
	Name  string
	RAM   int
	VCPUs int
}

func (s *Platform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "GetLimits (Azure)")
	if err := s.AzureLogin(ctx); err != nil {
		return err
	}

	var limits []AZLimit
	out, err := sh.Command("az", "vm", "list-usage", "--location", s.props.Location, sh.Dir("/tmp")).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("cannot get limits from azure, %s, %s", out, err.Error())
		return err
	}
	err = json.Unmarshal(out, &limits)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return err
	}
	for _, l := range limits {
		if l.LocalName == "Total Regional vCPUs" {
			vcpus, err := strconv.Atoi(l.Limit)
			if err != nil {
				err = fmt.Errorf("failed to parse azure output, %s", err.Error())
				return err
			}
			info.OsMaxVcores = uint64(vcpus)
			info.OsMaxRam = uint64(4 * vcpus)
			info.OsMaxVolGb = uint64(500 * vcpus)
			break
		}
	}

	/*
	 * We will not support all Azure flavors, only selected ones:
	 * https://azure.microsoft.com/en-in/pricing/details/virtual-machines/series/
	 */
	var vmsizes []AZFlavor
	out, err = sh.Command("az", "vm", "list-sizes",
		"--location", s.props.Location,
		"--query", "[].{"+
			"Name:name,"+
			"VCPUs:numberOfCores,"+
			"RAM:memoryInMb, Disk:resourceDiskSizeInMb"+
			"}[?starts_with(Name,'Standard_DS')]|[?ends_with(Name,'v2')]",
		sh.Dir("/tmp")).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("cannot get vm-sizes from azure, %s, %s", out, err.Error())
		return err
	}
	err = json.Unmarshal(out, &vmsizes)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return err
	}
	for _, f := range vmsizes {
		info.Flavors = append(
			info.Flavors,
			&edgeproto.FlavorInfo{
				Name:  f.Name,
				Vcpus: uint64(f.VCPUs),
				Ram:   uint64(f.RAM),
				Disk:  uint64(f.Disk),
			},
		)
	}
	return nil
}

func (s *Platform) GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst) (ssh.Client, error) {
	return &pc.LocalClient{}, nil
}

func (s *Platform) GetNodePlatformClient(ctx context.Context, node *edgeproto.CloudletMgmtNode) (ssh.Client, error) {
	return &pc.LocalClient{}, nil
}

func (s *Platform) ListCloudletMgmtNodes(ctx context.Context, clusterInsts []edgeproto.ClusterInst) ([]edgeproto.CloudletMgmtNode, error) {
	return []edgeproto.CloudletMgmtNode{}, nil
}
