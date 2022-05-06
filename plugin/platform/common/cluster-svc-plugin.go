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

package common

import (
	"context"

	"github.com/edgexr/edge-cloud-infra/alerts"
	"github.com/edgexr/edge-cloud-infra/autoprov/autorules"
	"github.com/edgexr/edge-cloud-infra/version"
	"github.com/edgexr/edge-cloud/edgeproto"
)

type ClusterSvc struct{}

func (s *ClusterSvc) GetAppInstConfigs(ctx context.Context, clusterInst *edgeproto.ClusterInst, appInst *edgeproto.AppInst, policy *edgeproto.AutoScalePolicy, settings *edgeproto.Settings, userAlerts []edgeproto.AlertPolicy) ([]*edgeproto.ConfigFile, error) {
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
