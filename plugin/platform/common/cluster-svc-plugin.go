package common

import (
	"context"

	"github.com/mobiledgex/edge-cloud-infra/alerts"
	"github.com/mobiledgex/edge-cloud-infra/autoprov/autorules"
	"github.com/mobiledgex/edge-cloud-infra/version"
	"github.com/mobiledgex/edge-cloud/edgeproto"
)

type ClusterSvc struct{}

func (s *ClusterSvc) GetAppInstConfigs(ctx context.Context, clusterInst *edgeproto.ClusterInst, appInst *edgeproto.AppInst, policy *edgeproto.AutoScalePolicy, settings *edgeproto.Settings, userAlerts []edgeproto.UserAlert) ([]*edgeproto.ConfigFile, error) {
	var configs []*edgeproto.ConfigFile
	if policy != nil {
		file, err := autorules.GetAutoScaleRules(ctx, policy, settings)
		if err != nil {
			return nil, err
		}
		policyConfig := &edgeproto.ConfigFile{
			Kind:   edgeproto.AppConfigHelmYaml,
			Config: file,
		}
		configs = append(configs, policyConfig)
	}

	if len(userAlerts) > 0 {
		file, err := alerts.GetAlertRules(ctx, appInst, userAlerts)
		if err != nil {
			return nil, err
		}
		alertsConfig := &edgeproto.ConfigFile{
			Kind:   edgeproto.AppConfigHelmYaml,
			Config: file,
		}
		configs = append(configs, alertsConfig)
	}
	return configs, nil
}

func (s *ClusterSvc) GetVersionProperties() map[string]string {
	return version.InfraBuildProps("InfraClusterSvc")
}
