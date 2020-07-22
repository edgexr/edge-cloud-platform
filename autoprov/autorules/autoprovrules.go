package autorules

import (
	"context"
	"fmt"
	"time"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/prommgmt"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
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
