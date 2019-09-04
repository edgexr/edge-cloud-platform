package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	sh "github.com/codeskyblue/go-sh"
	"github.com/mobiledgex/edge-cloud-infra/mexos"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

type Platform struct {
	props  edgeproto.AzureProperties // AzureProperties should be moved to edge-cloud-infra
	config platform.PlatformConfig
}

func (s *Platform) GetType() string {
	return "azure"
}

func (s *Platform) Init(ctx context.Context, platformConfig *platform.PlatformConfig, updateCallback edgeproto.CacheUpdateCallback) error {
	if err := mexos.InitInfraCommon(ctx, platformConfig.VaultAddr); err != nil {
		return err
	}
	s.config = *platformConfig
	s.props.Location = os.Getenv("MEX_AZURE_LOCATION")
	if s.props.Location == "" {
		return fmt.Errorf("Env variable MEX_AZURE_LOCATION not set")
	}
	/** resource group currently derived from cloudletName + cluster name
			s.props.ResourceGroup = os.Getenv("MEX_AZURE_RESOURCE_GROUP")
			if s.props.ResourceGroup == "" {
				return fmt.Errorf("Env variable MEX_AZURE_RESOURCE_GROUP not set")
	                }
	*/
	s.props.UserName = os.Getenv("MEX_AZURE_USER")
	if s.props.UserName == "" {
		return fmt.Errorf("Env variable MEX_AZURE_USER not set, check contents of MEXENV_URL")
	}
	s.props.Password = os.Getenv("MEX_AZURE_PASS")
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
	if err := s.AzureLogin(ctx, ); err != nil {
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

func (s *Platform) GetPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst) (pc.PlatformClient, error) {
	return &pc.LocalClient{}, nil
}
