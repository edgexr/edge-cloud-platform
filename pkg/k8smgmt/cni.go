// Copyright 2025 EdgeXR, Inc
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

package k8smgmt

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	ssh "github.com/edgexr/golang-ssh"
	v1 "k8s.io/api/core/v1"
)

func InstallCilium(ctx context.Context, client ssh.Client, names *KconfNames, clusterName string, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	kubeNames := &KubeNames{}
	chartSpec := HelmChartSpec{
		ImagePath: "https://helm.cilium.io:cilium/cilium",
		URLPath:   "https://helm.cilium.io/",
		ChartName: "cilium",
		RepoName:  "cilium",
		ChartRef:  "cilium/cilium",
	}
	err := helmRepoAdd(ctx, client, kubeNames, &chartSpec)
	if err != nil {
		return err
	}
	err = helmRepoUpdate(ctx, client, kubeNames, &chartSpec)
	if err != nil {
		return err
	}
	cmd := fmt.Sprintf("helm %s install cilium %s --version 1.18.3 --namespace kube-system --wait", names.KconfArg, chartSpec.ChartRef)
	log.SpanLog(ctx, log.DebugLevelInfra, "installing cilium", "cmd", cmd)
	out, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error installing cilium, %s, %s, %v", cmd, out, err)
	}
	// restart unmanaged pods as part of helm install. See:
	// https://docs.cilium.io/en/stable/installation/k8s-install-helm/#restart-unmanaged-pods
	cmd = fmt.Sprintf("kubectl %s get pods -A -o json", names.KconfArg)
	out, err = client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error getting pods, %s, %s, %v", cmd, out, err)
	}
	podsList := v1.PodList{}
	if err := json.Unmarshal([]byte(out), &podsList); err != nil {
		return fmt.Errorf("failed to unmarshal pods info, %s", err)
	}
	for _, pod := range podsList.Items {
		if pod.Spec.HostNetwork {
			continue
		}
		cmd = fmt.Sprintf("kubectl %s delete pod %s -n %s", names.KconfArg, pod.Name, pod.Namespace)
		log.SpanLog(ctx, log.DebugLevelInfra, "deleting unmanaged pods after cilium install", "cmd", cmd)
		out, err := client.Output(cmd)
		if err != nil {
			return fmt.Errorf("error deleting unmanaged pod, %s, %s, %v", cmd, out, err)
		}
	}
	return nil
}
