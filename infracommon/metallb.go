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

	"github.com/edgexr/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

// metalLb usually installs here but can be configured in a different NS
var DefaultMetalLbNamespace = "metallb-system"

var maxMetalLbWaitTime = 5 * time.Minute

type MetalConfigmapParams struct {
	AddressRanges []string
}

var MetalLbConfigMap = `apiVersion: v1
kind: ConfigMap
metadata:
  namespace: metallb-system
  name: config
data:
  config: |
    address-pools:
    - name: default
      protocol: layer2
      addresses:
      {{- range .AddressRanges}}
       - {{.}}
      {{- end}}
`

func InstallAndConfigMetalLbIfNotInstalled(ctx context.Context, client ssh.Client, clusterInst *edgeproto.ClusterInst, addressRanges []string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "InstallAndConfigMetalLbIfNotInstalled", "clusterInst", clusterInst)
	installed, err := IsMetalLbInstalled(ctx, client, clusterInst, DefaultMetalLbNamespace)
	if err != nil {
		return err
	}
	if !installed {
		if err := InstallMetalLb(ctx, client, clusterInst); err != nil {
			return err
		}
		if err := ConfigureMetalLb(ctx, client, clusterInst, addressRanges); err != nil {
			return err
		}
	}
	if err := VerifyMetalLbRunning(ctx, client, clusterInst, DefaultMetalLbNamespace); err != nil {
		return err
	}
	return nil
}

func VerifyMetalLbRunning(ctx context.Context, client ssh.Client, clusterInst *edgeproto.ClusterInst, metalLbNameSpace string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "VerifyMetalLbRunning", "clusterInst", clusterInst, "metalLbNameSpace", metalLbNameSpace)
	kconfEnv := "KUBECONFIG=" + k8smgmt.GetKconfName(clusterInst)
	start := time.Now()
	for {
		done, err := k8smgmt.CheckPodsStatus(ctx, client, kconfEnv, metalLbNameSpace, "app=metallb", k8smgmt.WaitRunning, start)
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
			return fmt.Errorf("MetalLB startup wait timed out")
		}
		time.Sleep(1 * time.Second)
	}
	return nil
}

func IsMetalLbInstalled(ctx context.Context, client ssh.Client, clusterInst *edgeproto.ClusterInst, metalLbNameSpace string) (bool, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "IsMetalLbInstalled", "clusterInst", clusterInst, "metalLbNameSpace", metalLbNameSpace)
	kconf := k8smgmt.GetKconfName(clusterInst)
	cmd := fmt.Sprintf("kubectl get deployment -n %s controller --kubeconfig=%s", metalLbNameSpace, kconf)
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

func InstallMetalLb(ctx context.Context, client ssh.Client, clusterInst *edgeproto.ClusterInst) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "InstallMetalLb", "clusterInst", clusterInst)
	kconf := k8smgmt.GetKconfName(clusterInst)
	cmds := []string{
		fmt.Sprintf("kubectl create -f https://raw.githubusercontent.com/metallb/metallb/v0.10.2/manifests/namespace.yaml --kubeconfig=%s", kconf),
		fmt.Sprintf("kubectl create -f https://raw.githubusercontent.com/metallb/metallb/v0.10.2/manifests/metallb.yaml --kubeconfig=%s", kconf),
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

func ConfigureMetalLb(ctx context.Context, client ssh.Client, clusterInst *edgeproto.ClusterInst, addressRanges []string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "ConfigureMetalLb", "clusterInst", clusterInst, "addressRanges", addressRanges)
	MetalConfigmapParams := MetalConfigmapParams{
		AddressRanges: addressRanges,
	}
	configBuf, err := ExecTemplate("metalLbConfigMap", MetalLbConfigMap, MetalConfigmapParams)
	if err != nil {
		return err
	}
	dir := k8smgmt.GetNormalizedClusterName(clusterInst)
	err = pc.CreateDir(ctx, client, dir, pc.NoOverwrite, pc.NoSudo)
	if err != nil {
		return err
	}
	fileName := dir + "/metalLbConfigMap.yaml"
	err = pc.WriteFile(client, fileName, configBuf.String(), "configMap", pc.NoSudo)
	if err != nil {
		return fmt.Errorf("WriteTemplateFile failed for metal config map: %s", err)
	}
	kconf := k8smgmt.GetKconfName(clusterInst)
	cmd := fmt.Sprintf("kubectl apply -f %s --kubeconfig=%s", fileName, kconf)
	log.SpanLog(ctx, log.DebugLevelInfra, "installing metallb config", "cmd", cmd)
	out, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("can't add configure metallb %s, %s, %v", cmd, out, err)
	}
	return nil
}
