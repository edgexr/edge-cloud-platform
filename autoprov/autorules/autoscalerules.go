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
	"bytes"
	"context"
	"fmt"
	"text/template"

	"github.com/edgexr/edge-cloud/edgeproto"
)

// If an auto-scale profile is set, we add measurements to track cpu and memory
// usage for worker nodes only, averaged over the Averaging duration (to avoid
// usage spikes and dips), and stabilized over the Stabilization duration (to
// smooth transitions and avoid oscillation).
//
// Notes on the measurements:
// To avoid measuring cpu/mem from the master node which does not run pods,
// we sum metrics on nodes without the "NoSchedule" taint:
// expr: sum(node:node_cpu_utilisation:avg1m unless (kube_node_spec_taint{effect="NoSchedule"} * on(node) kube_node_spec_taint))
// Multiplying the vector with itself gets rid of all the other labels
// except "node", so that "unless" can be used to filter out NoSchedule nodes
// from node:node_cpu_utilisation:avg
var MEXPrometheusAutoScaleT = `additionalPrometheusRules:
- name: autoscalepolicy
  groups:
  - name: autoscale.rules
    rules:
    - expr: |-
        1 - avg by (node) (
          rate(node_cpu_seconds_total{job="node-exporter",mode="idle"}[[.AveragingSec]])
        * on (namespace, pod) group_left(node)
          node_namespace_pod:kube_pod_info:)
      record: node:node_cpu_utilisation:avg
    - expr: sum(node:node_cpu_utilisation:avg unless (kube_node_spec_taint{effect="NoSchedule"} * on(node) kube_node_spec_taint))
      record: 'total_worker_node_cpu_utilisation'
    - expr: max_over_time(total_worker_node_cpu_utilisation[[.StabilizationSec]])
      record: 'stabilized_max_total_worker_node_cpu_utilisation'

    - expr: 'instance:node_memory_utilisation:ratio * on(namespace, pod) group_left(node) node_namespace_pod:kube_pod_info:'
      record: 'node:node_memory_utilisation:ratio'
    - expr: sum by (node) (avg_over_time(node:node_memory_utilisation:ratio[[.AveragingSec]]))
      record: 'node_memory_utilisation:ratio:avg'
    - expr: sum(node_memory_utilisation:ratio:avg unless (kube_node_spec_taint{effect="NoSchedule"} * on(node) kube_node_spec_taint))
      record: 'total_worker_node_mem_utilisation'
    - expr: max_over_time(total_worker_node_mem_utilisation[[.StabilizationSec]])
      record: 'stabilized_max_total_worker_node_mem_utilisation'
`

type AutoScaleArgs struct {
	AutoScalePolicy  string
	AveragingSec     string
	StabilizationSec string
}

func GetAutoScaleRules(ctx context.Context, policy *edgeproto.AutoScalePolicy, settings *edgeproto.Settings) (string, error) {
	// backwards compatibility derives new fields from old fields
	stwin := policy.StabilizationWindowSec
	if stwin == 0 {
		stwin = policy.TriggerTimeSec
		if stwin == 0 {
			stwin = edgeproto.DefaultStabilizationWindowSec
		}
	}
	avgwin := settings.ClusterAutoScaleAveragingDurationSec
	// change delims because Prometheus triggers off of golang delims
	t := template.Must(template.New("policy").Delims("[[", "]]").Parse(MEXPrometheusAutoScaleT))
	args := AutoScaleArgs{
		AutoScalePolicy:  policy.Key.Name,
		AveragingSec:     fmt.Sprintf("[%ds]", avgwin),
		StabilizationSec: fmt.Sprintf("[%ds]", stwin),
	}
	buf := bytes.Buffer{}
	err := t.Execute(&buf, &args)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}
