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

package alerts

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"text/template"

	"github.com/edgexr/edge-cloud-infra/promutils"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/prommgmt"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/util"
	"github.com/prometheus/common/model"
)

var MEXPrometheusUserAlertsT = `additionalPrometheusRules:
- name: userdefinedalerts
  groups:
  - name: useralerts.rules
    rules:
    [[- range .ClusterAlerts ]]
    - alert: [[ .Rule.Alert ]]
      expr: [[ .Rule.Expr ]]
      for: [[ .TriggerTimeString ]]
      labels:
        [[- range $key, $value := .Rule.Labels ]]
        [[ $key ]]: "[[ $value ]]"
        [[- end ]]
      [[- if gt (len .Rule.Annotations) 0 ]]
      annotations:
        [[- range $key, $value := .Rule.Annotations ]]
        [[ $key ]]: "[[ $value ]]"
        [[- end ]]
      [[- end ]]
    [[- end ]]
`

// alert definition for prometheus cluster
type PrometheusClusterAlert struct {
	prommgmt.Rule
	TriggerTimeString string
}

type AlertArgs struct {
	ClusterAlerts []*PrometheusClusterAlert
}

// Walk the alerts and create a prometheus alert structure from them
func getAlertRulesArgs(ctx context.Context, appInst *edgeproto.AppInst, alerts []edgeproto.AlertPolicy) AlertArgs {
	alertArgs := AlertArgs{ClusterAlerts: []*PrometheusClusterAlert{}}

	// filter the prom query to only include mexAppName
	labelFilter := `{label_mexAppName="` + util.DNSSanitize(appInst.Key.AppKey.Name) +
		`",label_mexAppVersion="` + util.DNSSanitize(appInst.Key.AppKey.Version) + `"}`

	for ii := range alerts {
		// if this is an envoy-based alert, skip it
		if alerts[ii].ActiveConnLimit != 0 {
			continue
		}
		rule := getPromAlertFromEdgeprotoAlert(appInst, &alerts[ii])
		promAlert := PrometheusClusterAlert{
			Rule:              rule,
			TriggerTimeString: alerts[ii].TriggerTime.TimeDuration().String(),
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
		promAlert.Rule.Expr = strings.Join(expressions, " and ")

		log.SpanLog(ctx, log.DebugLevelInfo, "Adding Prometheus user alert rule", "appInst", appInst,
			"alert", promAlert)

		alertArgs.ClusterAlerts = append(alertArgs.ClusterAlerts, &promAlert)
	}
	return alertArgs
}

func GetAlertRules(ctx context.Context, appInst *edgeproto.AppInst, alerts []edgeproto.AlertPolicy) (string, error) {
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
func GetCloudletAlertRules(ctx context.Context, appInst *edgeproto.AppInst, alerts []edgeproto.AlertPolicy) *prommgmt.RuleGroup {
	grp := prommgmt.NewRuleGroup("user-alerts", appInst.Key.AppKey.Organization)

	for ii, _ := range alerts {
		if alerts[ii].ActiveConnLimit == 0 {
			continue
		}
		rule := getPromAlertFromEdgeprotoAlert(appInst, &alerts[ii])
		rule.Expr = `envoy_cluster_upstream_cx_active{` +
			edgeproto.AppKeyTagName + `="` + appInst.Key.AppKey.Name + `",` +
			edgeproto.AppKeyTagVersion + `="` + appInst.Key.AppKey.Version + `",` +
			edgeproto.AppKeyTagOrganization + `="` + appInst.Key.AppKey.Organization +
			`"} > ` + fmt.Sprintf("%d", alerts[ii].ActiveConnLimit)

		log.SpanLog(ctx, log.DebugLevelInfo, "Adding Cloudlet Prometheus user alert rule", "appInst", appInst,
			"rule", rule)
		grp.Rules = append(grp.Rules, rule)
	}
	if len(grp.Rules) == 0 {
		return nil
	}

	return grp
}

func getPromAlertFromEdgeprotoAlert(appInst *edgeproto.AppInst, alert *edgeproto.AlertPolicy) prommgmt.Rule {
	rule := prommgmt.Rule{}
	rule.Alert = alert.Key.Name
	rule.For = model.Duration(alert.TriggerTime)

	// add labels
	rule.Labels = util.CopyStringMap(alert.Labels)
	rule.Labels[cloudcommon.AlertScopeTypeTag] = cloudcommon.AlertScopeApp
	rule.Labels[cloudcommon.AlertTypeLabel] = cloudcommon.AlertTypeUserDefined
	rule.Labels[cloudcommon.AlertSeverityLabel] = alert.Severity
	rule.Labels = util.AddMaps(rule.Labels, appInst.Key.GetTags())
	rule.Annotations = util.CopyStringMap(alert.Annotations)
	// Add title annotation if one doesn't exist - our notification templates rely on it being present
	if _, found := rule.Annotations[cloudcommon.AlertAnnotationTitle]; !found {
		rule.Annotations[cloudcommon.AlertAnnotationTitle] = alert.Key.Name
	}
	// description annotation overwrites description in the definition
	if _, found := rule.Annotations[cloudcommon.AlertAnnotationDescription]; !found {
		rule.Annotations[cloudcommon.AlertAnnotationDescription] = getAlertPolicyDescription(alert)
	}
	return rule
}

func getAlertPolicyDescription(in *edgeproto.AlertPolicy) string {
	if in.Description != "" {
		return in.Description
	}
	// collect all configured thresholds
	defaultDescription := []string{}
	if in.CpuUtilizationLimit != 0 {
		cpuStr := fmt.Sprintf("CPU Utilization > %d%%", in.CpuUtilizationLimit)
		defaultDescription = append(defaultDescription, cpuStr)
	}
	if in.MemUtilizationLimit != 0 {
		memStr := fmt.Sprintf("Memory Utilization > %d%%", in.MemUtilizationLimit)
		defaultDescription = append(defaultDescription, memStr)
	}
	if in.DiskUtilizationLimit != 0 {
		diskStr := fmt.Sprintf("Disk Utilization > %d%%", in.DiskUtilizationLimit)
		defaultDescription = append(defaultDescription, diskStr)
	}
	if in.ActiveConnLimit != 0 {
		connStr := fmt.Sprintf("Number of active connections > %d", in.ActiveConnLimit)
		defaultDescription = append(defaultDescription, connStr)
	}
	return strings.Join(defaultDescription, " and ")
}
