package gcp

import (
	"context"
	"fmt"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vault"
)

const gcpVaultPath string = "/secret/data/cloudlet/gcp/credentials"

var gcpProps = map[string]*edgeproto.PropertyInfo{
	"MEX_GCP_PROJECT": {
		Name:        "GCP Project Name",
		Description: "Name of the GCP project",
		Value:       "still-entity-201400",
	},
	"MEX_GCP_ZONE": {
		Name:        "GCP Zone Name",
		Description: "Name of the GCP zone",
		Mandatory:   true,
	},
	"MEX_GCP_SERVICE_ACCOUNT": {
		Name:        "GCP Service Account Name",
		Description: "Name of the GCP service account",
		Mandatory:   true,
		Secret:      true,
		Internal:    true,
	},
	"MEX_GCP_AUTH_KEY_PATH": {
		Name:        "GCP Auth Key Path",
		Description: "Path of the GCP auth key",
		Value:       "/secret/data/cloudlet/gcp/auth_key.json",
		Internal:    true,
	},
}

func (g *GCPPlatform) GetK8sProviderSpecificProps() map[string]*edgeproto.PropertyInfo {
	return gcpProps
}

func (g *GCPPlatform) GetGcpAuthKeyUrl() string {
	val, _ := g.commonPf.Properties.GetValue("MEX_GCP_AUTH_KEY_PATH")
	return val
}

func (g *GCPPlatform) GetGcpZone() string {
	val, _ := g.commonPf.Properties.GetValue("MEX_GCP_ZONE")
	return val
}

func (g *GCPPlatform) GetGcpProject() string {
	val, _ := g.commonPf.Properties.GetValue("MEX_GCP_PROJECT")
	return val
}

func (g *GCPPlatform) InitApiAccessProperties(ctx context.Context, region string, vaultConfig *vault.Config, vars map[string]string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "InitApiAccessProperties")
	err := infracommon.InternVaultEnv(ctx, vaultConfig, gcpVaultPath)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "Failed to intern vault data for API access", "err", err)
		err = fmt.Errorf("cannot intern vault data from vault %s", err.Error())
		return err
	}
	return nil
}
