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

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	ssh "github.com/edgexr/golang-ssh"
)

//CopyKubeConfig copies over kubeconfig from the cluster
func CopyKubeConfig(ctx context.Context, rootLBClient ssh.Client, clusterInst *edgeproto.ClusterInst, rootLBName, masterIP string) error {
	kconfname := k8smgmt.GetKconfName(clusterInst)
	log.SpanLog(ctx, log.DebugLevelInfra, "attempt to get kubeconfig from k8s master", "masterIP", masterIP, "dest", kconfname)
	client, err := rootLBClient.AddHop(masterIP, 22)
	if err != nil {
		return err
	}
	_, err = client.Output("ls " + kconfname)
	if err == nil {
		// already exists
		log.SpanLog(ctx, log.DebugLevelInfra, "kubeconfig already exists on rootLB")
		return nil
	}

	// fetch kubeconfig from master node
	cmd := "cat ~/.kube/config"
	out, err := client.Output(cmd)
	if err != nil || out == "" {
		return fmt.Errorf("failed to get kubeconfig from master node %s, %s, %v", cmd, out, err)
	}

	// save it in rootLB
	err = pc.WriteFile(rootLBClient, kconfname, out, "kconf file", pc.NoSudo)
	if err != nil {
		return fmt.Errorf("can't write kubeconfig to %s, %v", kconfname, err)
	}

	//TODO generate per proxy password and record in vault
	//port, serr := StartKubectlProxy(mf, rootLB, name, kconfname)
	//if serr != nil {
	//	return serr
	//}
	return nil
}
