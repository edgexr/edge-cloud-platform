package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	sh "github.com/codeskyblue/go-sh"
	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

const GcpMaxClusterNameLen int = 40

type GCPPlatform struct {
	commonPf *infracommon.CommonPlatform
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

func (g *GCPPlatform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "GatherCloudletInfo")
	err := g.Login(ctx)
	if err != nil {
		return err
	}
	var quotas []GCPQuotasList

	filter := fmt.Sprintf("name=(%s) AND quotas.metric=(CPUS, DISKS_TOTAL_GB)", g.GetGcpZone())
	flatten := "quotas[]"
	format := "json(quotas.metric,quotas.limit)"

	log.SpanLog(ctx, log.DebugLevelInfra, "list regions", "filter", filter)
	out, err := sh.Command("gcloud", "compute", "regions", "list",
		"--project", g.GetGcpProject(), "--filter", filter, "--flatten", flatten,
		"--format", format, sh.Dir("/tmp")).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("cannot get resource quotas from gcp, %s, %s", out, err.Error())
		return err
	}
	err = json.Unmarshal(out, &quotas)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "list regions unmarshal fail", "out", string(out), "err", err)
		err = fmt.Errorf("cannot unmarshal list regions output")
		return err
	}
	if len(quotas) == 0 {
		return fmt.Errorf("No quotas found for zone: %s -- check that zone is valid", g.GetGcpZone())
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
	filter = fmt.Sprintf("zone:(%s) AND name:(standard)", g.GetGcpZone())
	format = "json(name,guestCpus,memoryMb,maximumPersistentDisksSizeGb)"
	log.SpanLog(ctx, log.DebugLevelInfra, "list compute machine-types", "filter", filter, "format", format)
	out, err = sh.Command("gcloud", "compute", "machine-types", "list",
		"--project", g.GetGcpProject(), "--filter", filter,
		"--format", format, sh.Dir("/tmp")).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("cannot get machine-types from gcp, %s, %s", out, err.Error())
		return err
	}
	err = json.Unmarshal(out, &machinetypes)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "compute machines-type list unmarshal fail", "out", string(out), "err", err)
		err = fmt.Errorf("compute machines-type list output")
		return err
	}
	for _, m := range machinetypes {
		disk, err := strconv.Atoi(m.MaximumPersistentDisksSizeGb)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to parse machine types", "out", string(out), "err", err)
			err = fmt.Errorf("failed to parse gcp machine types output")
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

// GCPLogin logs into google cloud
func (g *GCPPlatform) Login(ctx context.Context) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "doing GcpLogin", "vault url", g.GetGcpAuthKeyUrl())
	filename := "/tmp/auth_key.json"
	err := infracommon.GetVaultDataToFile(g.commonPf.VaultConfig, g.GetGcpAuthKeyUrl(), filename)
	if err != nil {
		return fmt.Errorf("unable to write auth file %s: %s", filename, err.Error())
	}
	defer os.Remove(filename)
	out, err := sh.Command("gcloud", "auth", "activate-service-account", "--key-file", filename).CombinedOutput()
	log.SpanLog(ctx, log.DebugLevelInfra, "gcp login", "out", string(out), "err", err)
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "GCP login OK")
	return nil
}

func (g *GCPPlatform) NameSanitize(clusterName string) string {
	clusterName = strings.NewReplacer(".", "").Replace(clusterName)
	if len(clusterName) > GcpMaxClusterNameLen {
		clusterName = clusterName[:GcpMaxClusterNameLen]
	}
	return clusterName
}

func (g *GCPPlatform) SetCommonPlatform(cpf *infracommon.CommonPlatform) {
	g.commonPf = cpf
}
