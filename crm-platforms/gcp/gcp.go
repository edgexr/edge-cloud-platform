package gcp

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
	"github.com/mobiledgex/edge-cloud/vault"
)

var GCPServiceAccount string //temp

type Platform struct {
	props        edgeproto.GcpProperties // GcpProperties needs to move to edge-cloud-infra
	config       platform.PlatformConfig
	vaultConfig  *vault.Config
	clusterCache *edgeproto.ClusterInstInfoCache
}

type GCPQuotas struct {
	Limit  float64
	Metric string
}

type GCPQuotasList struct {
	Quotas GCPQuotas
}

type GCPFlavor struct {
	GuestCPUs                    int
	MaximumPersistentDisksSizeGb string
	MemoryMb                     int
	Name                         string
}

func (s *Platform) GetType() string {
	return "gcp"
}

func (s *Platform) Init(ctx context.Context, platformConfig *platform.PlatformConfig, updateCallback edgeproto.CacheUpdateCallback) error {
	vaultConfig, err := vault.BestConfig(platformConfig.VaultAddr)
	if err != nil {
		return err
	}
	s.vaultConfig = vaultConfig

	if err := mexos.InitInfraCommon(ctx, vaultConfig); err != nil {
		return err
	}
	s.config = *platformConfig
	s.props.Project = os.Getenv("MEX_GCP_PROJECT")
	if s.props.Project == "" {
		//default
		s.props.Project = "still-entity-201400"
	}
	s.props.Zone = os.Getenv("MEX_GCP_ZONE")
	if s.props.Zone == "" {
		return fmt.Errorf("Env variable MEX_GCP_ZONE not set")
	}
	s.props.ServiceAccount = os.Getenv("MEX_GCP_SERVICE_ACCOUNT")
	if s.props.ServiceAccount == "" {
		return fmt.Errorf("Env variable MEX_GCP_SERVICE_ACCOUNT not set")
	}
	s.props.GcpAuthKeyUrl = os.Getenv("MEX_GCP_AUTH_KEY_PATH")
	if s.props.GcpAuthKeyUrl == "" {
		//default it
		s.props.GcpAuthKeyUrl = "/secret/data/cloudlet/gcp/auth_key.json"
		log.SpanLog(ctx, log.DebugLevelMexos, "MEX_GCP_AUTH_KEY_PATH defaulted", "value", s.props.GcpAuthKeyUrl)
	}
	return nil
}

func (s *Platform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "GetLimits (GCP)")
	err := s.GCPLogin(ctx)
	if err != nil {
		return err
	}
	var quotas []GCPQuotasList

	filter := fmt.Sprintf("name=(%s) AND quotas.metric=(CPUS, DISKS_TOTAL_GB)", s.props.Zone)
	flatten := "quotas[]"
	format := "json(quotas.metric,quotas.limit)"

	out, err := sh.Command("gcloud", "compute", "regions", "list",
		"--project", s.props.Project, "--filter", filter, "--flatten", flatten,
		"--format", format, sh.Dir("/tmp")).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("cannot get resource quotas from gcp, %s, %s", out, err.Error())
		return err
	}
	err = json.Unmarshal(out, &quotas)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal, %s, %v", out, err)
		return err
	}
	for _, q := range quotas {
		if q.Quotas.Metric == "CPUS" {
			info.OsMaxVcores = uint64(q.Quotas.Limit)
			info.OsMaxRam = uint64(3.75 * float32(q.Quotas.Limit))
		} else if q.Quotas.Metric == "DISKS_TOTAL_GB" {
			info.OsMaxVolGb = uint64(q.Quotas.Limit)
		} else {
			err = fmt.Errorf("unexpected Quotas metric: %s", q.Quotas.Metric)
			return err
		}
	}

	var machinetypes []GCPFlavor
	filter = fmt.Sprintf("zone=(%s) AND name:(standard)", s.props.Zone)
	format = "json(name,guestCpus,memoryMb,maximumPersistentDisksSizeGb)"

	out, err = sh.Command("gcloud", "compute", "machine-types", "list",
		"--project", s.props.Project, "--filter", filter,
		"--format", format, sh.Dir("/tmp")).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("cannot get machine-types from gcp, %s, %s", out, err.Error())
		return err
	}
	err = json.Unmarshal(out, &machinetypes)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal, %s, %v", out, err)
		return err
	}
	for _, m := range machinetypes {
		disk, err := strconv.Atoi(m.MaximumPersistentDisksSizeGb)
		if err != nil {
			err = fmt.Errorf("failed to parse gcp output, %s", err.Error())
			return err
		}
		info.Flavors = append(
			info.Flavors,
			&edgeproto.FlavorInfo{
				Name:  m.Name,
				Vcpus: uint64(m.GuestCPUs),
				Ram:   uint64(m.MemoryMb),
				Disk:  uint64(disk),
			},
		)
	}
	return nil
}

func (s *Platform) GetPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst) (pc.PlatformClient, error) {
	return &pc.LocalClient{}, nil
}
