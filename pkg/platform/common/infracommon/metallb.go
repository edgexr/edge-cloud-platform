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

package infracommon

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	ssh "github.com/edgexr/golang-ssh"
)

// metalLb usually installs here but can be configured in a different NS
var DefaultMetalLbNamespace = "metallb-system"

var maxMetalLbWaitTime = 5 * time.Minute

type MetalConfigmapParams struct {
	AddressRanges     []string
	DisableAutoAssign bool
}

var MetalLbAddressPool = `apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: default-pool
  namespace: metallb-system
spec:
  addresses:
  {{- range .AddressRanges}}
  - {{.}}
  {{- end}}
  {{- if .DisableAutoAssign}}
  autoAssign: false
  {{- end}}
---
apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata:
  name: default-l2
  namespace: metallb-system
spec:
  ipAddressPools:
  - default-pool
`

func InstallAndConfigMetalLbIfNotInstalled(ctx context.Context, client ssh.Client, names *k8smgmt.KconfNames, clusterName string, clusterInst *edgeproto.ClusterInst, params *MetalConfigmapParams, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "InstallAndConfigMetalLbIfNotInstalled", "clusterInst", clusterInst)
	installed, err := IsMetalLbInstalled(ctx, client, names, clusterName, clusterInst, DefaultMetalLbNamespace)
	if err != nil {
		return err
	}
	if !installed {
		if updateCallback != nil {
			updateCallback(edgeproto.UpdateTask, "Installing MetalLB")
		}
		if err := InstallMetalLb(ctx, client, names, clusterName, clusterInst); err != nil {
			return err
		}
		if updateCallback != nil {
			updateCallback(edgeproto.UpdateTask, "Waiting for MetalLB pods...")
		}
		if err := VerifyMetalLbRunning(ctx, client, names, clusterName, clusterInst, DefaultMetalLbNamespace); err != nil {
			return err
		}
		if err := ConfigureMetalLb(ctx, client, names, clusterName, clusterInst, params); err != nil {
			return err
		}
	}
	if updateCallback != nil {
		updateCallback(edgeproto.UpdateTask, "MetalLB ready")
	}
	return nil
}

func VerifyMetalLbRunning(ctx context.Context, client ssh.Client, names *k8smgmt.KconfNames, clusterName string, _ *edgeproto.ClusterInst, metalLbNameSpace string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "VerifyMetalLbRunning", "clusterInst", clusterName, "metalLbNameSpace", metalLbNameSpace)
	start := time.Now()
	podStatus := k8smgmt.PodStatus{}
	nodes, err := k8smgmt.GetNodes(ctx, client, names.KconfArg)
	if err != nil {
		return err
	}
	numPods := 1 + len(nodes) // controller and speaker per node
	for {
		done, err := podStatus.Check(ctx, client, names.KconfArg, metalLbNameSpace, "app=metallb", k8smgmt.WaitRunning, start, numPods)
		if err != nil {
			return fmt.Errorf("MetalLB pod status error - %v", err)
		}
		if done {
			log.SpanLog(ctx, log.DebugLevelInfra, "MetalLB OK")
			break
		}
		elapsed := time.Since(start)
		if elapsed >= (maxMetalLbWaitTime) {
			// for now we will return no errors when we time out.  In future we will use some other state or status
			// field to reflect this and employ health checks to track these appinsts
			log.SpanLog(ctx, log.DebugLevelInfra, "MetalLB startup wait timed out")
			err := fmt.Errorf("MetalLB startup wait timed out")
			if len(podStatus.Statuses) > 0 {
				err = fmt.Errorf("%w: %s", err, strings.Join(podStatus.Statuses, "; "))
			}
			return err
		}
		time.Sleep(1 * time.Second)
	}

	cmd := fmt.Sprintf("kubectl %s -n %s wait --for condition=ready pod --selector=component=controller --timeout=60s", names.KconfArg, metalLbNameSpace)
	out, err := client.Output(cmd)
	if err != nil {
		log.InfoLog("error getting controller pod", "err", err, "out", out)
		return fmt.Errorf("MetalLB controller wait timed out")
	}
	return nil
}

func IsMetalLbInstalled(ctx context.Context, client ssh.Client, names *k8smgmt.KconfNames, clusterName string, _ *edgeproto.ClusterInst, metalLbNameSpace string) (bool, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "IsMetalLbInstalled", "clusterInst", clusterName, "metalLbNameSpace", metalLbNameSpace)
	cmd := fmt.Sprintf("kubectl %s get deployment -n %s controller", names.KconfArg, metalLbNameSpace)
	out, err := client.Output(cmd)
	if err != nil {
		if strings.Contains(out, "NotFound") {
			log.SpanLog(ctx, log.DebugLevelInfra, "metalLb is not installed on the cluster")
			return false, nil
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "unexpected error looking for metalLb", "out", out, "err", err)
			return false, fmt.Errorf("Unexpected error looking for metalLb: %s - %v", out, err)
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "metalLb is already installed on the cluster")
	return true, nil
}

func InstallMetalLb(ctx context.Context, client ssh.Client, names *k8smgmt.KconfNames, clusterName string, _ *edgeproto.ClusterInst) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "InstallMetalLb", "clusterInst", clusterName)
	cmds := []string{
		fmt.Sprintf("kubectl %s create -f https://raw.githubusercontent.com/metallb/metallb/v0.15.2/config/manifests/metallb-native.yaml", names.KconfArg),
	}
	for _, cmd := range cmds {
		log.SpanLog(ctx, log.DebugLevelInfra, "installing metallb", "cmd", cmd)
		out, err := client.Output(cmd)
		if err != nil {
			return fmt.Errorf("failed to run metalLb cmd %s, %s, %v", cmd, out, err)
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "ok, installed metallb")
	return nil
}

func ConfigureMetalLb(ctx context.Context, client ssh.Client, names *k8smgmt.KconfNames, clusterName string, _ *edgeproto.ClusterInst, params *MetalConfigmapParams) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "ConfigureMetalLb", "clusterInst", clusterName, "params", params)
	configBuf, err := ExecTemplate("MetalLbAddressPool", MetalLbAddressPool, params)
	if err != nil {
		return err
	}
	fileName := clusterName + "-metalLbPoolConfig.yaml"
	err = pc.WriteFile(client, fileName, configBuf.String(), "configMap", pc.NoSudo)
	if err != nil {
		return fmt.Errorf("WriteTemplateFile failed for metal config map: %s", err)
	}
	// Sometimes the webhook is not ready even though the pods are
	// running. Allow for one retry.
	for ii := 0; ; ii++ {
		cmd := fmt.Sprintf("kubectl %s apply -f %s", names.KconfArg, fileName)
		log.SpanLog(ctx, log.DebugLevelInfra, "installing metallb addr pool config", "cmd", cmd)
		out, err := client.Output(cmd)
		if err != nil {
			if ii < 2 && strings.Contains(out, "failed calling webhook") {
				// give some time for webhook to be ready
				log.SpanLog(ctx, log.DebugLevelInfra, "webhook not ready yet, will retry", "try", ii, "cmd", cmd, "out", out, "err", err)
				time.Sleep(2 * time.Second)
				continue
			}
			return fmt.Errorf("can't configure metallb %s, %s, %v", cmd, out, err)
		} else {
			break
		}
	}
	return nil
}
