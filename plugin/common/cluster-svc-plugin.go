package common

import (
	"bytes"
	"context"
	"fmt"
	"text/template"

	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
)

type ClusterSvc struct{}

// If an auto-scale profile is set, we add two measurements and two alerts.
// The measurements count the number of nodes that are above the high cpu
// threshold and below the low cpu threshold. These measurements assume
// the master node is not schedulable and other nodes are schedulable, which
// may not be true if custom taints are used.
// The scale up alert fires when all nodes are above the high cpu threshold,
// and there are less than the max number of nodes.
// The scale down alert files when any node is below the low cpu threshold,
// and there are more than the min number of nodes.
var MEXPrometheusAutoScaleT = `additionalPrometheusRules:
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
    - expr: sum(node:node_cpu_utilisation:avg1m{node=~"[[.NodePrefix]].*"} > bool .[[.ScaleUpCpuThresh]])
      record: 'node_cpu_high_count'
    - expr: sum(node:node_cpu_utilisation:avg1m{node=~"[[.NodePrefix]].*"} < bool .[[.ScaleDownCpuThresh]])
      record: 'node_cpu_low_count'
    - expr: count(kube_node_info) - count(kube_node_spec_taint)
      record: 'node_count'
    - alert: [[.AutoScaleUpName]]
      expr: node_cpu_high_count == node_count and node_count < [[.MaxNodes]]
      for: [[.TriggerTimeSec]]s
      labels:
        severity: none
      annotations:
        message: High cpu greater than [[.ScaleUpCpuThresh]]% for all nodes
        [[.NodeCountName]]: '{{ with query "node_count" }}{{ . | first | value | humanize }}{{ end }}'
    - alert: [[.AutoScaleDownName]]
      expr: node_cpu_low_count > 0 and node_count > [[.MinNodes]]
      for: [[.TriggerTimeSec]]s
      labels:
        severity: none
      annotations:
        message: Low cpu less than [[.ScaleDownCpuThresh]]% for some nodes
        [[.LowCpuNodeCountName]]: '{{ $value }}'
        [[.NodeCountName]]: '{{ with query "node_count" }}{{ . | first | value | humanize }}{{ end }}'
        [[.MinNodesName]]: '[[.MinNodes]]'
`

type AutoScaleArgs struct {
	AutoScalePolicy     string
	AutoScaleUpName     string
	AutoScaleDownName   string
	ScaleUpCpuThresh    uint32
	ScaleDownCpuThresh  uint32
	TriggerTimeSec      uint32
	MaxNodes            int
	MinNodes            int
	NodeCountName       string
	LowCpuNodeCountName string
	MinNodesName        string
	NodePrefix          string // master node must have different prefix
}

func (s *ClusterSvc) GetAppInstConfigs(ctx context.Context, clusterInst *edgeproto.ClusterInst, appInst *edgeproto.AppInst, policy *edgeproto.AutoScalePolicy) ([]*edgeproto.ConfigFile, error) {
	if policy == nil {
		return nil, fmt.Errorf("no auto-scale policy specified for GetAppInstConfigs")
	}
	// change delims because Prometheus triggers off of golang delims
	t := template.Must(template.New("policy").Delims("[[", "]]").Parse(MEXPrometheusAutoScaleT))
	args := AutoScaleArgs{
		AutoScalePolicy:     policy.Key.Name,
		AutoScaleUpName:     cloudcommon.AlertAutoScaleUp,
		AutoScaleDownName:   cloudcommon.AlertAutoScaleDown,
		ScaleUpCpuThresh:    policy.ScaleUpCpuThresh,
		ScaleDownCpuThresh:  policy.ScaleDownCpuThresh,
		TriggerTimeSec:      policy.TriggerTimeSec,
		MaxNodes:            int(policy.MaxNodes),
		MinNodes:            int(policy.MinNodes),
		NodeCountName:       cloudcommon.AlertKeyNodeCount,
		LowCpuNodeCountName: cloudcommon.AlertKeyLowCpuNodeCount,
		MinNodesName:        cloudcommon.AlertKeyMinNodes,
		NodePrefix:          cloudcommon.MexNodePrefix,
	}
	buf := bytes.Buffer{}
	err := t.Execute(&buf, &args)
	if err != nil {
		return nil, err
	}
	policyConfig := &edgeproto.ConfigFile{
		Kind:   edgeproto.AppConfigHelmYaml,
		Config: buf.String(),
	}
	configs := []*edgeproto.ConfigFile{policyConfig}
	return configs, nil
}
