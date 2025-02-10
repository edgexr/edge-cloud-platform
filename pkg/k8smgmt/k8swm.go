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
	"fmt"
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	ssh "github.com/edgexr/golang-ssh"
)

// WorkloadMgr handles deploying instances. It only deploys the
// application definition, it does not manage namespaces,
// network policies, resource quotas, or other policies.
// It should manage deployments and services.
// Currently ingress objects are managed outside of the workload
// manager but this may change in the future.
type WorkloadMgr interface {
	// Create or Update an AppInst on a Cluster
	ApplyAppInstWorkload(ctx context.Context, accessAPI platform.AccessApi, client ssh.Client, names *KubeNames, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, ops ...AppInstOp) error
	// Delete an AppInst on a Cluster
	DeleteAppInstWorkload(ctx context.Context, accessAPI platform.AccessApi, client ssh.Client, names *KubeNames, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, ops ...AppInstOp) error
}

type K8SWorkloadMgr struct{}

func (s *K8SWorkloadMgr) ApplyAppInstWorkload(ctx context.Context, accessAPI platform.AccessApi, client ssh.Client, names *KubeNames, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, ops ...AppInstOp) (reterr error) {
	opts := GetAppInstOptions(ops)
	if err := WriteDeploymentManifestToFile(ctx, accessAPI, client, names, app, appInst); err != nil {
		return err
	}
	configDir := GetConfigDirName(names)

	defer func() {
		if reterr == nil || opts.Undo {
			return
		}
		// undo changes
		ctx = context.WithValue(ctx, cloudcommon.ContextKeyUndo, true)
		log.SpanLog(ctx, log.DebugLevelInfra, "undoing createOrUpdateAppInst due to failure", "err", reterr)
		undoErr := s.DeleteAppInstWorkload(ctx, accessAPI, client, names, clusterInst, app, appInst, WithAppInstUndo())
		log.SpanLog(ctx, log.DebugLevelInfra, "undo createOrUpdateAppInst done", "undoErr", undoErr)
	}()

	// Kubernetes provides 3 styles of object management.
	// We use the Declarative Object configuration style, to be able to
	// update and prune.
	// Note that "kubectl create" does NOT fall under this style.
	// Only "apply" and "delete" should be used. All configuration files
	// for an AppInst must be stored in their own directory.

	// Selector selects which objects to consider for pruning.
	kconfArg := names.GetTenantKconfArg()
	selector := fmt.Sprintf("-l %s=%s", ConfigLabel, getConfigLabel(names))
	cmd := fmt.Sprintf("kubectl %s apply -f %s --prune %s", kconfArg, configDir, selector)
	log.SpanLog(ctx, log.DebugLevelInfra, "running kubectl", "cmd", cmd)
	out, err := client.Output(cmd)
	if err != nil && strings.Contains(string(out), `pruning nonNamespaced object /v1, Kind=Namespace: namespaces "kube-system" is forbidden: this namespace may not be deleted`) {
		// odd error that occurs on Azure, probably due to some system
		// object they have in their k8s cluster setup. Ignore it
		// since it doesn't affect the other aspects of the apply.
		err = nil
	}
	if err != nil {
		return fmt.Errorf("error running kubectl command %s: %s, %v", cmd, out, err)
	}
	if opts.Wait {
		err := WaitForAppInst(ctx, client, names, app, WaitRunning)
		if err != nil {
			return err
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "done kubectl")
	return nil
}

func (s *K8SWorkloadMgr) DeleteAppInstWorkload(ctx context.Context, accessAPI platform.AccessApi, client ssh.Client, names *KubeNames, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, ops ...AppInstOp) (reterr error) {
	if err := WriteDeploymentManifestToFile(ctx, accessAPI, client, names, app, appInst); err != nil {
		return err
	}
	undo := false
	if ctx.Value(cloudcommon.ContextKeyUndo) != nil {
		undo = true
	}

	kconfArg := names.GetTenantKconfArg()
	configDir := GetConfigDirName(names)
	configName := getConfigFileName(names, appInst, DeploymentManifestSuffix)
	file := configDir + "/" + configName
	cmd := fmt.Sprintf("kubectl %s delete -f %s", kconfArg, file)
	log.SpanLog(ctx, log.DebugLevelInfra, "deleting appinst", "name", names.AppInstName, "cmd", cmd)
	out, err := client.Output(cmd)
	if err != nil {
		if strings.Contains(string(out), "not found") {
			log.SpanLog(ctx, log.DebugLevelInfra, "delete appinst workload ignoring not found error", "name", names.AppName, "err", err)
		} else if undo {
			log.SpanLog(ctx, log.DebugLevelInfra, "delete appinst workload ignoring error because undo", "name", names.AppName, "err", err)
		} else {
			return fmt.Errorf("error deleting kubernetes app, %s, %s, %s, %v", names.AppName, cmd, out, err)
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "deleted deployment", "name", names.AppName)
	//Note wait for deletion of appinst can be done here in a generic place, but wait for creation is split
	// out in each platform specific task so that we can optimize the time taken for create by allowing the
	// wait to be run in parallel with other tasks
	err = WaitForAppInst(ctx, client, names, app, WaitDeleted)
	if err != nil {
		if undo {
			log.SpanLog(ctx, log.DebugLevelInfra, "ignoring wait delete failed error because undo", "err", err)
		} else {
			return err
		}
	}
	// delete manifest file
	return CleanupManifest(ctx, client, names, appInst, DeploymentManifestSuffix)
}
