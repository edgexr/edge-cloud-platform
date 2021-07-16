package alerts

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"text/template"

	"github.com/mobiledgex/edge-cloud-infra/promutils"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/prommgmt"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/util"
	"github.com/prometheus/common/model"
)

var MEXPrometheusUserAlertsT = `additionalPrometheusRules:
- name: userdefinedalerts
  groups:
  - name: useralerts.rules
    rules:
    [[- range .ClusterAlerts ]]
    - alert: [[ .Name ]]
      expr: [[ .RuleExpression ]]
      for: [[ .TriggerTimeString ]]
      labels:
        severity: [[ .Severity ]]
        type: "User Defined"
        [[- range $key, $value := .Labels ]]
        [[ $key ]]: "[[ $value ]]"
        [[- end ]]
      [[- if gt (len .Annotations) 0 ]]
      annotations:
        [[- range $key, $value := .Annotations ]]
        [[ $key ]]: "[[ $value ]]"
        [[- end ]]
      [[- end ]]
    [[- end ]]
`

// alert definition for prometheus cluster
type PrometheusClusterAlert struct {
	Name              string
	RuleExpression    string
	Severity          string
	TriggerTimeString string
	Labels            map[string]string
	Annotations       map[string]string
}

type AlertArgs struct {
	ClusterAlerts []*PrometheusClusterAlert
}

// Walk the alerts and create a prometheus alert structure from them
func getAlertRulesArgs(ctx context.Context, appInst *edgeproto.AppInst, alerts []edgeproto.UserAlert) AlertArgs {
	alertArgs := AlertArgs{ClusterAlerts: []*PrometheusClusterAlert{}}

	// filter the prom query to only include mexAppName
	labelFilter := `{label_mexAppName="` + util.DNSSanitize(appInst.Key.AppKey.Name) +
		`",label_mexAppVersion="` + util.DNSSanitize(appInst.Key.AppKey.Version) + `"}`

	for ii := range alerts {
		// if this is an envoy-based alert, skip it
		if alerts[ii].ActiveConnLimit != 0 {
			continue
		}
		promAlert := PrometheusClusterAlert{
			Name:              alerts[ii].Key.Name,
			Severity:          alerts[ii].Severity,
			TriggerTimeString: alerts[ii].TriggerTime.TimeDuration().String(),
			Labels:            util.CopyStringMap(alerts[ii].Labels),
			Annotations:       util.CopyStringMap(alerts[ii].Annotations),
		}

		// Create a prometheus expression for the alert rule
		expressions := []string{}
		if alerts[ii].CpuUtilizationLimit != 0 {
			cpuQuery := promutils.GetPromQueryWithK8sLabels(labelFilter, promutils.PromQCpuPod)
			exp := fmt.Sprintf("%s > %d", cpuQuery, alerts[ii].CpuUtilizationLimit)
			expressions = append(expressions, exp)
		}
		if alerts[ii].MemUtilizationLimit != 0 {
			memQuery := promutils.GetPromQueryWithK8sLabels(labelFilter, promutils.PromQMemPercentPod)
			exp := fmt.Sprintf("%s > %d", memQuery, alerts[ii].MemUtilizationLimit)
			expressions = append(expressions, exp)
		}
		if alerts[ii].DiskUtilizationLimit != 0 {
			diskQuery := promutils.GetPromQueryWithK8sLabels(labelFilter, promutils.PromQDiskPercentPod)
			exp := fmt.Sprintf("%s > %d", diskQuery, alerts[ii].DiskUtilizationLimit)
			expressions = append(expressions, exp)
		}
		promAlert.RuleExpression = strings.Join(expressions, " and ")
		promAlert.Labels[cloudcommon.AlertScopeTypeTag] = cloudcommon.AlertScopeApp
		promAlert.Labels[cloudcommon.AlertTypeLabel] = cloudcommon.AlertTypeUserDefined
		// Add all the appinst labels
		promAlert.Labels = util.AddMaps(promAlert.Labels, appInst.Key.GetTags())

		log.SpanLog(ctx, log.DebugLevelInfo, "Adding Prometheus user alert rule", "appInst", appInst,
			"alert", promAlert)

		alertArgs.ClusterAlerts = append(alertArgs.ClusterAlerts, &promAlert)
	}
	return alertArgs
}

func GetAlertRules(ctx context.Context, appInst *edgeproto.AppInst, alerts []edgeproto.UserAlert) (string, error) {
	// no user defined alerts
	if len(alerts) == 0 {
		return "", nil
	}
	// change delims because Prometheus triggers off of golang delims
	t := template.Must(template.New("policy").Delims("[[", "]]").Parse(MEXPrometheusUserAlertsT))
	args := getAlertRulesArgs(ctx, appInst, alerts)
	buf := bytes.Buffer{}
	err := t.Execute(&buf, &args)
	if err != nil {
		return "", err
	}
	log.SpanLog(ctx, log.DebugLevelInfo, "User Alert config", "config", buf.String())
	return buf.String(), nil
}

// Get a set of cloudlet prometheus alerts for user-defined alerts on a given appInst
func GetCloudletAlertRules(ctx context.Context, appInst *edgeproto.AppInst, alerts []edgeproto.UserAlert) *prommgmt.RuleGroup {
	grp := prommgmt.NewRuleGroup("user-alerts", appInst.Key.AppKey.Organization)

	for ii, _ := range alerts {
		if alerts[ii].ActiveConnLimit == 0 {
			continue
		}
		rule := prommgmt.Rule{}
		rule.Alert = alerts[ii].Key.Name
		rule.Expr = `envoy_cluster_upstream_cx_active{` +
			edgeproto.AppKeyTagName + `="` + appInst.Key.AppKey.Name + `",` +
			edgeproto.AppKeyTagVersion + `="` + appInst.Key.AppKey.Version + `",` +
			edgeproto.AppKeyTagOrganization + `="` + appInst.Key.AppKey.Organization +
			`"} > ` + fmt.Sprintf("%d", alerts[ii].ActiveConnLimit)
		rule.For = model.Duration(alerts[ii].TriggerTime)

		// add labels
		rule.Labels = util.CopyStringMap(alerts[ii].Labels)
		rule.Labels[cloudcommon.AlertScopeTypeTag] = cloudcommon.AlertScopeApp
		rule.Labels[cloudcommon.AlertTypeLabel] = cloudcommon.AlertTypeUserDefined
		rule.Labels[cloudcommon.AlertSeverityLabel] = alerts[ii].Severity
		rule.Labels = util.AddMaps(rule.Labels, appInst.Key.GetTags())
		rule.Annotations = util.CopyStringMap(alerts[ii].Annotations)

		log.SpanLog(ctx, log.DebugLevelInfo, "Adding Cloudlet Prometheus user alert rule", "appInst", appInst,
			"rule", rule)
		grp.Rules = append(grp.Rules, rule)
	}
	if len(grp.Rules) == 0 {
		return nil
	}

	return grp
}
