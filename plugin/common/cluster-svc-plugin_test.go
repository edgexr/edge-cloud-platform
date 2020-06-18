package common

import (
	"context"
	"io/ioutil"
	"testing"

	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/testutil"
	"github.com/stretchr/testify/require"
)

// TestAutoScaleT primarily checks that AutoScale template parsing works, because
// otherwise cluster-svc could crash during runtime if template has an issue.
func TestAutoScaleT(t *testing.T) {
	log.InitTracer("")
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	clusterInst := testutil.ClusterInstData[0]

	policy := edgeproto.AutoScalePolicy{}
	policy.Key.Organization = clusterInst.Key.Organization
	policy.Key.Name = "test-policy"
	policy.MinNodes = 1
	policy.MaxNodes = 5
	policy.ScaleUpCpuThresh = 80
	policy.ScaleDownCpuThresh = 20
	policy.TriggerTimeSec = 60

	clusterInst.AutoScalePolicy = policy.Key.Name

	configExpected := `additionalPrometheusRules:
- name: autoscalepolicy
  groups:
  - name: autoscale.rules
    rules:
    - expr: 1 - avg(rate(node_cpu_seconds_total{job="node-exporter",mode="idle"}[1m]))
      record: :node_cpu_utilisation:avg1m
    - expr: |-
        1 - avg by (node) (
          rate(node_cpu_seconds_total{job="node-exporter",mode="idle"}[1m])
        * on (namespace, pod) group_left(node)
          node_namespace_pod:kube_pod_info:)
      record: node:node_cpu_utilisation:avg1m
    - expr: sum(node:node_cpu_utilisation:avg1m{node=~"mex-k8s-node-.*"} > bool 0.80)
      record: 'node_cpu_high_count'
    - expr: sum(node:node_cpu_utilisation:avg1m{node=~"mex-k8s-node-.*"} < bool 0.20)
      record: 'node_cpu_low_count'
    - expr: count(kube_node_info) - count(kube_node_spec_taint)
      record: 'node_count'
    - alert: AutoScaleUp
      expr: node_cpu_high_count == node_count and node_count < 5
      for: 60s
      labels:
        severity: none
      annotations:
        message: High cpu greater than 80% for all nodes
        nodecount: '{{ with query "node_count" }}{{ . | first | value | humanize }}{{ end }}'
    - alert: AutoScaleDown
      expr: node_cpu_low_count > 0 and node_count > 1
      for: 60s
      labels:
        severity: none
      annotations:
        message: Low cpu less than 20% for some nodes
        lowcpunodecount: '{{ $value }}'
        nodecount: '{{ with query "node_count" }}{{ . | first | value | humanize }}{{ end }}'
        minnodes: '1'
`
	testAutoScaleT(t, ctx, &clusterInst, &policy, configExpected)

	policy.MinNodes = 5
	policy.MaxNodes = 7
	policy.ScaleUpCpuThresh = 5
	policy.ScaleDownCpuThresh = 1

	configExpected = `additionalPrometheusRules:
- name: autoscalepolicy
  groups:
  - name: autoscale.rules
    rules:
    - expr: 1 - avg(rate(node_cpu_seconds_total{job="node-exporter",mode="idle"}[1m]))
      record: :node_cpu_utilisation:avg1m
    - expr: |-
        1 - avg by (node) (
          rate(node_cpu_seconds_total{job="node-exporter",mode="idle"}[1m])
        * on (namespace, pod) group_left(node)
          node_namespace_pod:kube_pod_info:)
      record: node:node_cpu_utilisation:avg1m
    - expr: sum(node:node_cpu_utilisation:avg1m{node=~"mex-k8s-node-.*"} > bool 0.05)
      record: 'node_cpu_high_count'
    - expr: sum(node:node_cpu_utilisation:avg1m{node=~"mex-k8s-node-.*"} < bool 0.01)
      record: 'node_cpu_low_count'
    - expr: count(kube_node_info) - count(kube_node_spec_taint)
      record: 'node_count'
    - alert: AutoScaleUp
      expr: node_cpu_high_count == node_count and node_count < 7
      for: 60s
      labels:
        severity: none
      annotations:
        message: High cpu greater than 5% for all nodes
        nodecount: '{{ with query "node_count" }}{{ . | first | value | humanize }}{{ end }}'
    - alert: AutoScaleDown
      expr: node_cpu_low_count > 0 and node_count > 5
      for: 60s
      labels:
        severity: none
      annotations:
        message: Low cpu less than 1% for some nodes
        lowcpunodecount: '{{ $value }}'
        nodecount: '{{ with query "node_count" }}{{ . | first | value | humanize }}{{ end }}'
        minnodes: '5'
`
	testAutoScaleT(t, ctx, &clusterInst, &policy, configExpected)
}

func testAutoScaleT(t *testing.T, ctx context.Context, clusterInst *edgeproto.ClusterInst, policy *edgeproto.AutoScalePolicy, expected string) {
	clusterSvc := ClusterSvc{}
	appInst := edgeproto.AppInst{}

	configs, err := clusterSvc.GetAppInstConfigs(ctx, clusterInst, &appInst, policy)
	require.Nil(t, err)
	require.Equal(t, 1, len(configs))
	ioutil.WriteFile("foo", []byte(configs[0].Config), 0644)

	require.Equal(t, expected, configs[0].Config)
}
