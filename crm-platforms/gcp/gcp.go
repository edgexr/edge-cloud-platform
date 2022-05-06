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

package gcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	sh "github.com/codeskyblue/go-sh"
	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

const GcpMaxClusterNameLen int = 40

type GCPPlatform struct {
	properties  *infracommon.InfraProperties
	accessVars  map[string]string
	authKeyJSON string
	gcpRegion   string
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

func (o *GCPPlatform) GetFeatures() *platform.Features {
	return &platform.Features{
		SupportsMultiTenantCluster:    true,
		SupportsKubernetesOnly:        true,
		KubernetesRequiresWorkerNodes: true,
		IPAllocatedPerService:         true,
	}
}

func (g *GCPPlatform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "GatherCloudletInfo")
	err := g.Login(ctx)
	if err != nil {
		return err
	}
	var quotas []GCPQuotasList

	filter := fmt.Sprintf("name=(%s) AND quotas.metric=(CPUS, DISKS_TOTAL_GB)", g.gcpRegion)
	flatten := "quotas[]"
	format := "json(quotas.metric,quotas.limit)"

	log.SpanLog(ctx, log.DebugLevelInfra, "list regions", "filter", filter)
	out, err := infracommon.Sh(g.accessVars).Command("gcloud", "compute", "regions", "list",
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
	out, err = infracommon.Sh(g.accessVars).Command("gcloud", "compute", "machine-types", "list",
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
	log.SpanLog(ctx, log.DebugLevelInfra, "doing GcpLogin")
	filename := "/tmp/auth_key.json"
	err := ioutil.WriteFile(filename, []byte(g.authKeyJSON), 0644)
	if err != nil {
		return fmt.Errorf("unable to write auth file %s: %s", filename, err.Error())
	}
	defer os.Remove(filename)
	out, err := infracommon.Sh(g.accessVars).Command("gcloud", "auth", "activate-service-account", "--key-file", filename).CombinedOutput()
	log.SpanLog(ctx, log.DebugLevelInfra, "gcp login", "out", string(out), "err", err)
	if err != nil {
		return err
	}
	err = g.SetProject(ctx, g.GetGcpProject())
	if err != nil {
		return err
	}
	err = g.SetZone(ctx, g.GetGcpZone())
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

func (g *GCPPlatform) SetProperties(props *infracommon.InfraProperties) error {
	g.properties = props
	var err error
	g.gcpRegion, err = g.GetGcpRegionFromZone(g.GetGcpZone())
	return err
}

func (g *GCPPlatform) GetRootLBClients(ctx context.Context) (map[string]ssh.Client, error) {
	return nil, nil
}
