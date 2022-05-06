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
	"testing"

	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/testutil"
	"github.com/stretchr/testify/require"
)

var TestClusterUserDefAlertsRules = `additionalPrometheusRules:
- name: userdefinedalerts
  groups:
  - name: useralerts.rules
    rules:
    - alert: testAlert1
      expr: max(kube_pod_labels{label_mexAppName="pillimogo",label_mexAppVersion="100"})by(label_mexAppName,label_mexAppVersion,pod)*on(pod)group_right(label_mexAppName,label_mexAppVersion)(sum(rate(container_cpu_usage_seconds_total{image!=""}[1m])) by (pod) / ignoring (pod) group_left sum(machine_cpu_cores) * 100 ) > 80 and max(kube_pod_labels{label_mexAppName="pillimogo",label_mexAppVersion="100"})by(label_mexAppName,label_mexAppVersion,pod)*on(pod)group_right(label_mexAppName,label_mexAppVersion)(sum(container_memory_working_set_bytes{image!=""})by(pod) / ignoring (pod) group_left sum( machine_memory_bytes{}) * 100) > 70 and max(kube_pod_labels{label_mexAppName="pillimogo",label_mexAppVersion="100"})by(label_mexAppName,label_mexAppVersion,pod)*on(pod)group_right(label_mexAppName,label_mexAppVersion)(sum(container_fs_usage_bytes{image!=""})by(pod) / ignoring (pod) group_left sum(container_fs_limit_bytes{device=~"^/dev/[sv]d[a-z][1-9]$",id="/"})*100) > 70
      for: 30s
      labels:
        app: "Pillimo Go!"
        apporg: "AtlanticInc"
        appver: "1.0.0"
        cloudlet: "San Jose Site"
        cloudletorg: "UFGT Inc."
        cluster: "Pillimos"
        clusterorg: "AtlanticInc"
        federatedorg: ""
        scope: "Application"
        severity: "warning"
        type: "UserDefined"
      annotations:
        description: "Sample description"
        title: "testAlert1"
    - alert: testAlert3
      expr: max(kube_pod_labels{label_mexAppName="pillimogo",label_mexAppVersion="100"})by(label_mexAppName,label_mexAppVersion,pod)*on(pod)group_right(label_mexAppName,label_mexAppVersion)(sum(rate(container_cpu_usage_seconds_total{image!=""}[1m])) by (pod) / ignoring (pod) group_left sum(machine_cpu_cores) * 100 ) > 100
      for: 30s
      labels:
        app: "Pillimo Go!"
        apporg: "AtlanticInc"
        appver: "1.0.0"
        cloudlet: "San Jose Site"
        cloudletorg: "UFGT Inc."
        cluster: "Pillimos"
        clusterorg: "AtlanticInc"
        federatedorg: ""
        scope: "Application"
        severity: "error"
        testLabel1: "testValue1"
        testLabel2: "testValue2"
        type: "UserDefined"
      annotations:
        description: "CPU Utilization > 100%"
        testAnnotation1: "description1"
        testAnnotation2: "description2"
        title: "testAlert3"
    - alert: testAlert4
      expr: max(kube_pod_labels{label_mexAppName="pillimogo",label_mexAppVersion="100"})by(label_mexAppName,label_mexAppVersion,pod)*on(pod)group_right(label_mexAppName,label_mexAppVersion)(sum(rate(container_cpu_usage_seconds_total{image!=""}[1m])) by (pod) / ignoring (pod) group_left sum(machine_cpu_cores) * 100 ) > 80 and max(kube_pod_labels{label_mexAppName="pillimogo",label_mexAppVersion="100"})by(label_mexAppName,label_mexAppVersion,pod)*on(pod)group_right(label_mexAppName,label_mexAppVersion)(sum(container_memory_working_set_bytes{image!=""})by(pod) / ignoring (pod) group_left sum( machine_memory_bytes{}) * 100) > 80
      for: 30s
      labels:
        app: "Pillimo Go!"
        apporg: "AtlanticInc"
        appver: "1.0.0"
        cloudlet: "San Jose Site"
        cloudletorg: "UFGT Inc."
        cluster: "Pillimos"
        clusterorg: "AtlanticInc"
        federatedorg: ""
        scope: "Application"
        severity: "warning"
        type: "UserDefined"
      annotations:
        description: "CPU Utilization > 80% and Memory Utilization > 80%"
        title: "testAlert4"
    - alert: testAlert5
      expr: max(kube_pod_labels{label_mexAppName="pillimogo",label_mexAppVersion="100"})by(label_mexAppName,label_mexAppVersion,pod)*on(pod)group_right(label_mexAppName,label_mexAppVersion)(sum(rate(container_cpu_usage_seconds_total{image!=""}[1m])) by (pod) / ignoring (pod) group_left sum(machine_cpu_cores) * 100 ) > 80 and max(kube_pod_labels{label_mexAppName="pillimogo",label_mexAppVersion="100"})by(label_mexAppName,label_mexAppVersion,pod)*on(pod)group_right(label_mexAppName,label_mexAppVersion)(sum(container_memory_working_set_bytes{image!=""})by(pod) / ignoring (pod) group_left sum( machine_memory_bytes{}) * 100) > 80
      for: 30s
      labels:
        app: "Pillimo Go!"
        apporg: "AtlanticInc"
        appver: "1.0.0"
        cloudlet: "San Jose Site"
        cloudletorg: "UFGT Inc."
        cluster: "Pillimos"
        clusterorg: "AtlanticInc"
        federatedorg: ""
        scope: "Application"
        severity: "warning"
        type: "UserDefined"
      annotations:
        description: "Custom Description"
        title: "CustomAlertName"
`

// TestAutoScaleT primarily checks that AutoScale template parsing works, because
// otherwise cluster-svc could crash during runtime if template has an issue.
func TestAutoScaleT(t *testing.T) {
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	clusterInst := testutil.ClusterInstData[0]

	policy := edgeproto.AutoScalePolicy{}
	policy.Key.Organization = clusterInst.Key.Organization
	policy.Key.Name = "test-policy"
	policy.TriggerTimeSec = 120

	clusterInst.AutoScalePolicy = policy.Key.Name

	userAlerts := testutil.AlertPolicyData
	settings := edgeproto.GetDefaultSettings()

	configExpected := `additionalPrometheusRules:
- name: autoscalepolicy
  groups:
  - name: autoscale.rules
    rules:
    - expr: |-
        1 - avg by (node) (
          rate(node_cpu_seconds_total{job="node-exporter",mode="idle"}[60s])
        * on (namespace, pod) group_left(node)
          node_namespace_pod:kube_pod_info:)
      record: node:node_cpu_utilisation:avg
    - expr: sum(node:node_cpu_utilisation:avg unless (kube_node_spec_taint{effect="NoSchedule"} * on(node) kube_node_spec_taint))
      record: 'total_worker_node_cpu_utilisation'
    - expr: max_over_time(total_worker_node_cpu_utilisation[120s])
      record: 'stabilized_max_total_worker_node_cpu_utilisation'

    - expr: 'instance:node_memory_utilisation:ratio * on(namespace, pod) group_left(node) node_namespace_pod:kube_pod_info:'
      record: 'node:node_memory_utilisation:ratio'
    - expr: sum by (node) (avg_over_time(node:node_memory_utilisation:ratio[60s]))
      record: 'node_memory_utilisation:ratio:avg'
    - expr: sum(node_memory_utilisation:ratio:avg unless (kube_node_spec_taint{effect="NoSchedule"} * on(node) kube_node_spec_taint))
      record: 'total_worker_node_mem_utilisation'
    - expr: max_over_time(total_worker_node_mem_utilisation[120s])
      record: 'stabilized_max_total_worker_node_mem_utilisation'
`
	testClusterRulesT(t, ctx, &clusterInst, &policy, settings, userAlerts, configExpected, TestClusterUserDefAlertsRules)

	policy.StabilizationWindowSec = 300
	settings.ClusterAutoScaleAveragingDurationSec = 30

	configExpected = `additionalPrometheusRules:
- name: autoscalepolicy
  groups:
  - name: autoscale.rules
    rules:
    - expr: |-
        1 - avg by (node) (
          rate(node_cpu_seconds_total{job="node-exporter",mode="idle"}[30s])
        * on (namespace, pod) group_left(node)
          node_namespace_pod:kube_pod_info:)
      record: node:node_cpu_utilisation:avg
    - expr: sum(node:node_cpu_utilisation:avg unless (kube_node_spec_taint{effect="NoSchedule"} * on(node) kube_node_spec_taint))
      record: 'total_worker_node_cpu_utilisation'
    - expr: max_over_time(total_worker_node_cpu_utilisation[300s])
      record: 'stabilized_max_total_worker_node_cpu_utilisation'

    - expr: 'instance:node_memory_utilisation:ratio * on(namespace, pod) group_left(node) node_namespace_pod:kube_pod_info:'
      record: 'node:node_memory_utilisation:ratio'
    - expr: sum by (node) (avg_over_time(node:node_memory_utilisation:ratio[30s]))
      record: 'node_memory_utilisation:ratio:avg'
    - expr: sum(node_memory_utilisation:ratio:avg unless (kube_node_spec_taint{effect="NoSchedule"} * on(node) kube_node_spec_taint))
      record: 'total_worker_node_mem_utilisation'
    - expr: max_over_time(total_worker_node_mem_utilisation[300s])
      record: 'stabilized_max_total_worker_node_mem_utilisation'
`
	testClusterRulesT(t, ctx, &clusterInst, &policy, settings, userAlerts, configExpected, TestClusterUserDefAlertsRules)
}

func testClusterRulesT(t *testing.T, ctx context.Context, clusterInst *edgeproto.ClusterInst, policy *edgeproto.AutoScalePolicy, settings *edgeproto.Settings, alerts []edgeproto.AlertPolicy, expectedAutoProvRules string, expectedAlertPoliciesRules string) {
	clusterSvc := ClusterSvc{}
	appInst := testutil.AppInstData[0]

	configs, err := clusterSvc.GetAppInstConfigs(ctx, clusterInst, &appInst, policy, settings, alerts)
	require.Nil(t, err)
	require.Equal(t, 2, len(configs))
	require.Equal(t, expectedAutoProvRules, configs[0].Config)
	require.Equal(t, expectedAlertPoliciesRules, configs[1].Config)
}
