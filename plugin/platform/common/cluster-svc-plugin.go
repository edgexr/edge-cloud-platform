package common

import (
	"context"
	"fmt"

	"github.com/mobiledgex/edge-cloud-infra/autoprov/autorules"
	"github.com/mobiledgex/edge-cloud-infra/version"
	"github.com/mobiledgex/edge-cloud/edgeproto"
)

type ClusterSvc struct{}

func (s *ClusterSvc) GetAppInstConfigs(ctx context.Context, clusterInst *edgeproto.ClusterInst, appInst *edgeproto.AppInst, policy *edgeproto.AutoScalePolicy) ([]*edgeproto.ConfigFile, error) {
	if policy == nil {
		return nil, fmt.Errorf("no auto-scale policy specified for GetAppInstConfigs")
	}
	file, err := autorules.GetAutoScaleRules(ctx, policy)
	if err != nil {
		return nil, err
	}
	policyConfig := &edgeproto.ConfigFile{
		Kind:   edgeproto.AppConfigHelmYaml,
		Config: file,
	}
	configs := []*edgeproto.ConfigFile{policyConfig}
	return configs, nil
}

func (s *ClusterSvc) GetVersionProperties() map[string]string {
	return version.InfraBuildProps("InfraClusterSvc")
}
