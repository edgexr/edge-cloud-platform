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

package autorules

import (
	"context"
	"fmt"
	"time"

	"github.com/edgexr/edge-cloud/cloud-resource-manager/prommgmt"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/prometheus/common/model"
)

func GetAutoUndeployRules(ctx context.Context, settings edgeproto.Settings, appKey *edgeproto.AppKey, policy *edgeproto.AutoProvPolicy) *prommgmt.RuleGroup {
	if policy.UndeployClientCount == 0 {
		return nil
	}
	grp := prommgmt.NewRuleGroup("autoprov-feature", policy.Key.Organization)

	rule := prommgmt.Rule{}
	rule.Alert = cloudcommon.AlertAutoUndeploy
	rule.Expr = `envoy_cluster_upstream_cx_active{` +
		edgeproto.AppKeyTagName + `="` + appKey.Name + `",` +
		edgeproto.AppKeyTagVersion + `="` + appKey.Version + `",` +
		edgeproto.AppKeyTagOrganization + `="` + appKey.Organization +
		`"} <= ` + fmt.Sprintf("%d", policy.UndeployClientCount)
	forSec := int64(policy.UndeployIntervalCount) * int64(settings.AutoDeployIntervalSec)
	rule.For = model.Duration(time.Second * time.Duration(forSec))
	grp.Rules = append(grp.Rules, rule)

	return grp
}
