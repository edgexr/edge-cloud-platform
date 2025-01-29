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

package k8smgmt

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	ssh "github.com/edgexr/golang-ssh"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
)

const WaitDeleted string = "WaitDeleted"
const WaitRunning string = "WaitRunning"

const DefaultNamespace string = "default"

// This is half of the default controller AppInst timeout
var maxWait = 15 * time.Minute

// max time waiting for a load balancer ip
var maxLoadBalancerIPWait = 2 * time.Minute

// How long to wait on create if there are no resources
var createWaitNoResources = 10 * time.Second

var applyManifest = "apply"
var createManifest = "create"

const PolicyManifestSuffix = "-policy"
const DeploymentManifestSuffix = ""

var podStateRegString = "(\\S+)\\s+(\\S+)\\s+(\\S+)\\s+(.*)\\s*"
var podStateReg = regexp.MustCompile(podStateRegString)

type AppInstOptions struct {
	Undo bool
	Wait bool
	WM   WorkloadMgr
}

type AppInstOp func(*AppInstOptions)

// WithAppInstNoWait don't wait for pods to reach expected state,
// typically used if caller wants to run the wait separately in
// parallel with other tasks.
func WithAppInstNoWait() AppInstOp {
	return func(opts *AppInstOptions) {
		opts.Wait = false
	}
}

// WithAppInstUndo indicates the action is undoing a previous action,
// so don't trigger any further undos.
func WithAppInstUndo() AppInstOp {
	return func(opts *AppInstOptions) {
		opts.Undo = true
	}
}

func WithWorkloadManager(wm WorkloadMgr) AppInstOp {
	return func(opts *AppInstOptions) {
		opts.WM = wm
	}
}

func GetAppInstOptions(ops []AppInstOp) *AppInstOptions {
	opts := &AppInstOptions{
		Wait: true, // by default, we wait for pods
	}
	for _, op := range ops {
		op(opts)
	}
	if opts.WM == nil {
		opts.WM = &K8SWorkloadMgr{}
	}
	return opts
}

func LbServicePortToString(p *v1.ServicePort) string {
	proto := p.Protocol
	port := p.Port
	return edgeproto.ProtoPortToString(string(proto), port)
}

func CheckPodsStatus(ctx context.Context, client ssh.Client, kConfArg, namespace, selector, waitFor string, startTimer time.Time) (bool, error) {
	done := false
	log.SpanLog(ctx, log.DebugLevelInfra, "check pods status", "namespace", namespace, "selector", selector)
	cmd := fmt.Sprintf("kubectl %s get pods -n %s --selector=%s -o json", kConfArg, namespace, selector)
	out, err := client.Output(cmd)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "error getting pods", "err", err, "out", out)
		return done, fmt.Errorf("error getting pods: %v", err)
	}
	podList := v1.PodList{}
	if err := json.Unmarshal([]byte(out), &podList); err != nil {
		return done, fmt.Errorf("failed to unmarshal pods info, %s", err)
	}
	podCount := len(podList.Items)

	statuses := []string{}
	failReason := false
	allPodsRunning := false
	if len(podList.Items) > 0 {
		allPodsRunning = true
		for _, pod := range podList.Items {
			phase := string(pod.Status.Phase)
			// Running state is set if at least one container is
			// Ready, but we want to wait until all containers are
			// Ready.
			runningCount := 0
			reasons := []string{}
			for _, st := range pod.Status.ContainerStatuses {
				if st.State.Running != nil {
					runningCount++
				} else {
					allPodsRunning = false
					reason := "unknown"
					if st.State.Waiting != nil {
						reason = st.State.Waiting.Reason
					} else if st.State.Terminated != nil {
						reason = st.State.Terminated.Reason
					}
					if reason == "Unschedulable" {
						failReason = true
					}
					reasons = append(reasons, fmt.Sprintf("container %s: %s", st.Name, reason))
				}
			}
			status := fmt.Sprintf("pod %s: %s (%d/%d), %s", pod.Name, phase, runningCount, len(pod.Status.ContainerStatuses), strings.Join(reasons, ", "))
			phase += fmt.Sprintf("(%d/%d)", runningCount, len(pod.Status.ContainerStatuses))
			statuses = append(statuses, status)
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "wait for AppInst", "selector", selector, "status", statuses)

	if waitFor == WaitDeleted {
		if podCount == 0 {
			log.SpanLog(ctx, log.DebugLevelInfra, "all pods gone", "selector", selector)
			done = true
		}
	} else {
		if podCount == 0 {
			// race condition, may not find anything if run before pods show up
			if time.Since(startTimer) > createWaitNoResources {
				// still no resources, likely a failure
				// check replicasets for status
				// TODO: check deployment for status if no
				// replicasets
				st, stErr := CheckReplicaSetStatus(ctx, client, kConfArg, namespace, selector)
				if stErr != nil {
					log.SpanLog(ctx, log.DebugLevelInfra, "no pods found and failed to check replicaset status, %s", err)
					return false, fmt.Errorf("no pods found")
				} else {
					return false, fmt.Errorf("no pods found, replicaset statuses: %s", st)
				}
			}
			log.SpanLog(ctx, log.DebugLevelInfra, "not delete, but no pods found, assume command run before pods deployed", "selector", selector)
			return false, nil
		}
		if failReason {
			return false, fmt.Errorf("invalid pod state, %s", strings.Join(statuses, "; "))
		}
		if allPodsRunning {
			log.SpanLog(ctx, log.DebugLevelInfra, "all pods up", "selector", selector)
			done = true
		}
	}
	return done, nil
}

func CheckReplicaSetStatus(ctx context.Context, client ssh.Client, kConfArg, namespace, selector string) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "check replicaset status", "namespace", namespace, "selector", selector)
	cmd := fmt.Sprintf("kubectl %s get replicaset -n %s --selector=%s -o json", kConfArg, namespace, selector)
	out, err := client.Output(cmd)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "error getting replicaset", "err", err, "out", out)
		return "", err
	}
	rsList := appsv1.ReplicaSetList{}
	if err := json.Unmarshal([]byte(out), &rsList); err != nil {
		return "", fmt.Errorf("failed to unmarshal replicaset info, %s", err)
	}
	if len(rsList.Items) == 0 {
		return "", fmt.Errorf("no replicasets found")
	}
	statuses := []string{}
	for _, rs := range rsList.Items {
		conditions := rs.Status.Conditions
		if len(conditions) > 0 {
			cond := conditions[len(conditions)-1]
			status := fmt.Sprintf("%s: %s", rs.GetName(), cond.Message)
			statuses = append(statuses, status)
		}
	}
	return strings.Join(statuses, ","), nil
}

// WaitForAppInst waits for pods to either start or result in an error if WaitRunning specified,
// or if WaitDeleted is specified then wait for them to all disappear.
func WaitForAppInst(ctx context.Context, client ssh.Client, names *KubeNames, app *edgeproto.App, waitFor string) error {
	// wait half as long as the total controller wait time, which includes all tasks
	log.SpanLog(ctx, log.DebugLevelInfra, "waiting for appinst pods", "appName", app.Key.Name, "maxWait", maxWait, "waitFor", waitFor)
	start := time.Now()
	kconfArg := names.GetTenantKconfArg()

	// it might be nicer to pull the state directly rather than parsing it, but the states displayed
	// are a combination of states and reasons, e.g. ErrImagePull is not actually a state, so it's
	// just easier to parse the summarized output from kubectl which combines states and reasons
	objs, _, err := cloudcommon.DecodeK8SYaml(app.DeploymentManifest)
	if err != nil {
		log.InfoLog("unable to decode k8s yaml", "err", err)
		return err
	}
	var name string
	for ii, _ := range objs {
		for {
			name = ""
			namespace := ""
			switch obj := objs[ii].(type) {
			case *appsv1.Deployment:
				name = obj.ObjectMeta.Name
				namespace = obj.ObjectMeta.Namespace
			case *appsv1.DaemonSet:
				name = obj.ObjectMeta.Name
				namespace = obj.ObjectMeta.Namespace
			case *appsv1.StatefulSet:
				name = obj.ObjectMeta.Name
				namespace = obj.ObjectMeta.Namespace
			}
			if name == "" {
				break
			}
			if namespace == "" {
				if names.InstanceNamespace != "" {
					namespace = names.InstanceNamespace
				} else {
					namespace = DefaultNamespace
				}
			}
			selector := fmt.Sprintf("%s=%s", MexAppLabel, name)
			done, err := CheckPodsStatus(ctx, client, kconfArg, namespace, selector, waitFor, start)
			if err != nil {
				return err
			}
			if done {
				break
			}
			if err := ctx.Err(); err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "context error, aborting wait for appinst", "app", app.Key, "err", err)
				return err
			}
			elapsed := time.Since(start)
			if elapsed >= (maxWait) {
				// for now we will return no errors when we time out.  In future we will use some other state or status
				// field to reflect this and employ health checks to track these appinsts
				log.InfoLog("AppInst wait timed out", "appName", app.Key.Name)
				break
			}
			time.Sleep(2 * time.Second)
		}
	}
	return nil
}

func UpdateLoadBalancerPortMap(ctx context.Context, client ssh.Client, names *KubeNames, portMap map[string]string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "UpdateLoadBalancerPortMap", "names", names)

	services, err := GetServices(ctx, client, names)
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "UpdateLoadBalancerPortMap", "names.InstanceNamespace", names.InstanceNamespace)

	for _, s := range services {
		lbip := ""
		// It is possible to have ports for internal services that may overlap but not exposed externally. Skip services not part of this app.
		if !names.ContainsService(s.Name) {
			continue
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "service name match found in kubenames", "svc name", s.Name)
		if names.InstanceNamespace != "" {
			svcNamespace := s.ObjectMeta.Namespace
			if svcNamespace != names.InstanceNamespace {
				continue
			}
			log.SpanLog(ctx, log.DebugLevelInfra, "UpdateLoadBalancerPortMap match", "svcNamespace", svcNamespace)
		}
		for _, ing := range s.Status.LoadBalancer.Ingress {
			if strings.Contains(ing.IP, "pending") || ing.IP == "" {
				continue
			}
			lbip = ing.IP
			break
		}
		if lbip == "" {
			// it could be old cluster where we just patch "External IPs"
			for _, extIp := range s.Spec.ExternalIPs {
				if strings.Contains(extIp, "pending") || extIp == "" {
					continue
				}
				lbip = extIp
			}
		}
		if lbip == "" {
			continue
		}
		ports := s.Spec.Ports
		for _, p := range ports {
			portString := LbServicePortToString(&p)
			portMap[portString] = lbip
			log.SpanLog(ctx, log.DebugLevelInfra, "UpdateLoadBalancerPortMap settting for ", "portString", portString, "lbip", lbip)
		}
	}
	return nil
}

func PopulateAppInstLoadBalancerIps(ctx context.Context, client ssh.Client, names *KubeNames, appinst *edgeproto.AppInst) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "PopulateAppInstLoadBalancerIps", "appInst", appinst.Key.String(), "maxLoadBalancerIPWait", maxLoadBalancerIPWait)
	appinst.InternalPortToLbIp = make(map[string]string)
	start := time.Now()
	for {
		err := UpdateLoadBalancerPortMap(ctx, client, names, appinst.InternalPortToLbIp)
		if err != nil {
			return err
		}
		allPortsHaveIp := true
		// see if all services have an LB IP and update
		for _, mappedPort := range appinst.MappedPorts {
			portString, err := edgeproto.AppInternalPortToString(&mappedPort)
			if err != nil {
				return err
			}
			lbip, ok := appinst.InternalPortToLbIp[portString]
			if ok {
				log.SpanLog(ctx, log.DebugLevelInfra, "found load balancer ip for port", "portString", portString, "lbip", lbip, "names.InstanceNamespace", names.InstanceNamespace)
				appinst.InternalPortToLbIp[portString] = lbip
			} else {
				log.SpanLog(ctx, log.DebugLevelInfra, "did not find load balancer ip for port", "portString", portString)
				allPortsHaveIp = false
			}
		}
		if allPortsHaveIp {
			log.SpanLog(ctx, log.DebugLevelInfra, "All ports successfully got external IPS")
			return nil
		} else {
			elapsed := time.Since(start)
			if elapsed >= (maxLoadBalancerIPWait) {
				log.SpanLog(ctx, log.DebugLevelInfra, "AppInst service lbip wait timed out", "appInst", appinst.Key.String())
				return fmt.Errorf("Timed out waiting for Load Balancer IPs for appinst")
			}
			log.SpanLog(ctx, log.DebugLevelInfra, "Not all ports have external IPs, wait and try again")
			time.Sleep(time.Second * 1)
		}
	}
}

func GetConfigDirName(names *KubeNames) string {
	dir := names.ClusterName
	if names.InstanceNamespace != "" {
		dir += "." + names.InstanceNamespace
	}
	return dir
}

func EnsureConfigDir(ctx context.Context, client ssh.Client, names *KubeNames) error {
	configDir := GetConfigDirName(names)
	return pc.CreateDir(ctx, client, configDir, pc.NoOverwrite, pc.NoSudo)
}

func RemoveConfigDir(ctx context.Context, client ssh.Client, names *KubeNames) error {
	configDir := GetConfigDirName(names)
	return pc.DeleteDir(ctx, client, configDir, pc.NoSudo)
}

func getConfigFileName(names *KubeNames, appInst *edgeproto.AppInst, suffix string) string {
	if appInst.CompatibilityVersion < cloudcommon.AppInstCompatibilityUniqueNameKeyConfig {
		// backwards compatibility, may clobber other instances
		// using the same app definition in multi-tenant clusters.
		return names.AppName + names.AppOrg + names.AppVersion + ".yaml"
	} else if appInst.CompatibilityVersion < cloudcommon.AppInstCompatibilityRegionScopeName {
		appInstName := cloudcommon.GetAppInstCloudletScopedName(appInst)
		return appInstName + names.AppInstOrg + ".yaml"
	}
	return names.AppInstName + names.AppInstOrg + suffix + ".yaml"
}

// CreateAllNamespaces creates all the namespaces the app will use. It does not create a manifest for
// the namespaces, just allows the basic dependencies can be defined against
// them. Manifest definition can later be used to update the namespaces.
func CreateAllNamespaces(ctx context.Context, client ssh.Client, names *KubeNames) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateAllNamespaces", "names", names)
	namespaces := names.DeveloperDefinedNamespaces
	if names.InstanceNamespace != "" {
		namespaces = append(namespaces, names.InstanceNamespace)
	}
	for _, n := range namespaces {
		if n == DefaultNamespace {
			continue
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "Creating Namespace", "name", n)
		err := EnsureNamespace(ctx, client, names.GetKConfNames(), n)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "kubectl create namespace failed", "namespace", n, "err", err)
			return err
		}
	}
	return nil
}

func GenerateAppInstPolicyManifest(ctx context.Context, names *KubeNames, app *edgeproto.App, appInst *edgeproto.AppInst) (string, error) {
	mf := ""
	if names.MultiTenantRestricted {
		// Mulit-tenant cluster, add network policy
		np, err := GetNetworkPolicy(ctx, app, appInst, names)
		if err != nil {
			return "", err
		}
		mf = AddManifest(mf, np)
		// For now, ResourceQuota is only for multi-tenancy.
		// It is pretty strict, in that any deployment that
		// does not define resource limits will not be allowed
		// to be deployed. We can evaluate later if it should
		// also be applied in a non-multi-tenant context.
		rq, err := GetResourceQuota(ctx, names, appInst.KubernetesResources)
		if err != nil {
			return "", err
		}
		mf = AddManifest(mf, rq)
	}
	return mf, nil
}

func GenerateAppInstManifest(ctx context.Context, accessApi platform.AccessApi, names *KubeNames, app *edgeproto.App, appInst *edgeproto.AppInst) (string, error) {
	mf, err := cloudcommon.GetDeploymentManifest(ctx, accessApi, app.DeploymentManifest)
	if err != nil {
		return "", err
	}
	mf, err = MergeEnvVars(ctx, accessApi, app, appInst, mf, names.ImagePullSecrets, names, appInst.KubernetesResources)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to merge env vars", "error", err)
		return "", fmt.Errorf("error merging environment variables config file: %s", err)
	}
	return mf, nil
}

func WriteDeploymentManifestToFile(ctx context.Context, accessApi platform.AccessApi, client ssh.Client, names *KubeNames, app *edgeproto.App, appInst *edgeproto.AppInst) error {
	mf, err := GenerateAppInstManifest(ctx, accessApi, names, app, appInst)
	if err != nil {
		return err
	}
	return WriteManifest(ctx, client, names, appInst, DeploymentManifestSuffix, mf)
}

// ApplyAppInstPolicy creates and applies a manifest that contains
// policies like the NetworkPolicy and ResourceQuota. To be able
// apply ResourceQuota restrictions to the AppInst, it must be
// applied before the AppInst is deployed.
func ApplyAppInstPolicy(ctx context.Context, client ssh.Client, names *KubeNames, app *edgeproto.App, appInst *edgeproto.AppInst, action cloudcommon.Action) error {
	policyManifest, err := GenerateAppInstPolicyManifest(ctx, names, app, appInst)
	if err != nil {
		return err
	}
	if policyManifest == "" {
		return nil
	}

	// ensure manifest is present on delete as well, in case
	// CCRM container was restarted and manifest is no longer present.
	err = WriteManifest(ctx, client, names, appInst, PolicyManifestSuffix, policyManifest)
	if err != nil {
		return err
	}
	err = ApplyManifest(ctx, client, names, appInst, PolicyManifestSuffix, action)
	if err != nil {
		return err
	}
	if action == cloudcommon.Delete {
		if err := CleanupManifest(ctx, client, names, appInst, PolicyManifestSuffix); err != nil {
			return err
		}
	}
	return nil
}

func createOrUpdateAppInst(ctx context.Context, accessApi platform.AccessApi, client ssh.Client, names *KubeNames, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, action string, ops ...AppInstOp) (reterr error) {
	opts := GetAppInstOptions(ops)
	if action == createManifest && names.InstanceNamespace != "" {
		err := EnsureNamespace(ctx, client, names.GetKConfNames(), names.InstanceNamespace)
		if err != nil {
			return err
		}
	}
	if err := ApplyAppInstPolicy(ctx, client, names, app, appInst, cloudcommon.Create); err != nil {
		return err
	}

	if err := opts.WM.ApplyAppInstWorkload(ctx, accessApi, client, names, clusterInst, app, appInst, ops...); err != nil {
		return err
	}
	return nil
}

func CreateAppInst(ctx context.Context, accessApi platform.AccessApi, client ssh.Client, names *KubeNames, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, ops ...AppInstOp) error {
	return createOrUpdateAppInst(ctx, accessApi, client, names, clusterInst, app, appInst, createManifest, ops...)
}

func UpdateAppInst(ctx context.Context, accessApi platform.AccessApi, client ssh.Client, names *KubeNames, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, ops ...AppInstOp) error {
	return createOrUpdateAppInst(ctx, accessApi, client, names, clusterInst, app, appInst, applyManifest, ops...)
}

func DeleteAppInst(ctx context.Context, accessApi platform.AccessApi, client ssh.Client, names *KubeNames, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, ops ...AppInstOp) (reterr error) {
	opts := GetAppInstOptions(ops)
	err := opts.WM.DeleteAppInstWorkload(ctx, accessApi, client, names, clusterInst, app, appInst, ops...)
	if err != nil {
		return err
	}
	err = ApplyAppInstPolicy(ctx, client, names, app, appInst, cloudcommon.Delete)
	if err != nil {
		return err
	}

	if names.InstanceNamespace != "" {
		// clean up namespace
		if err = DeleteNamespace(ctx, client, names.GetKConfNames(), names.InstanceNamespace); err != nil {
			return err
		}
		if err = RemoveTenantKubeconfig(ctx, client, names); err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to clean up tenant kubeconfig", "err", err)
		}
		// delete the config dir
		configDir := GetConfigDirName(names)
		err := pc.DeleteDir(ctx, client, configDir, pc.NoSudo)
		if err != nil {
			return fmt.Errorf("Unable to delete config dir %s - %v", configDir, err)
		}
	}
	return nil
}

func GetAppInstRuntime(ctx context.Context, client ssh.Client, names *KubeNames, app *edgeproto.App, appInst *edgeproto.AppInst) (*edgeproto.AppInstRuntime, error) {
	rt := &edgeproto.AppInstRuntime{}
	rt.ContainerIds = make([]string, 0)

	objs, _, err := cloudcommon.DecodeK8SYaml(app.DeploymentManifest)
	if err != nil {
		return nil, err
	}
	kconfArg := names.GetTenantKconfArg()
	var name string
	for ii, _ := range objs {
		name = ""
		namespace := ""
		switch obj := objs[ii].(type) {
		case *appsv1.Deployment:
			name = obj.ObjectMeta.Name
			namespace = obj.ObjectMeta.Namespace
		case *appsv1.DaemonSet:
			name = obj.ObjectMeta.Name
			namespace = obj.ObjectMeta.Namespace
		case *appsv1.StatefulSet:
			name = obj.ObjectMeta.Name
			namespace = obj.ObjectMeta.Namespace
		}
		if name == "" {
			continue
		}
		if namespace == "" {
			if names.InstanceNamespace != "" {
				namespace = names.InstanceNamespace
			} else {
				namespace = DefaultNamespace
			}
		}

		// Returns list of pods and its containers in the format: "<Namespace>/<PodName>/<ContainerName>"

		// Get list of all running pods.
		// NOTE: Parsing status from json output doesn't give correct value as observed with kubectl version 1.18
		//       Hence, look at table output and then get list of running pods and use this to fetch container names
		cmd := fmt.Sprintf("kubectl %s get pods -n %s --no-headers --sort-by=.metadata.name --selector=%s=%s "+
			"| awk '{if ($3 == \"Running\") print $1}'",
			kconfArg, namespace, MexAppLabel, name)
		out, err := client.Output(cmd)
		if err != nil {
			return nil, fmt.Errorf("error getting kubernetes pods, %s, %s, %s", cmd, out, err.Error())
		}
		podNames := strings.Split(out, "\n")
		for _, podName := range podNames {
			podName = strings.TrimSpace(podName)
			if podName == "" {
				continue
			}
			cmd = fmt.Sprintf("kubectl %s get pod %s -n %s -o json | jq -r '.spec.containers[] | .name'",
				kconfArg, podName, namespace)
			out, err = client.Output(cmd)
			if err != nil {
				return nil, fmt.Errorf("error getting kubernetes pod %q containers, %s, %s, %s", podName, cmd, out, err.Error())
			}
			contNames := strings.Split(out, "\n")
			for _, contName := range contNames {
				contName = strings.TrimSpace(contName)
				if contName == "" {
					continue
				}
				rt.ContainerIds = append(rt.ContainerIds, namespace+"/"+podName+"/"+contName)
			}
		}
	}

	return rt, nil
}

func GetContainerCommand(ctx context.Context, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, req *edgeproto.ExecRequest) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetContainerCommand", "app", app, "containerId", req.ContainerId)

	// If no container specified, pick the first one in the AppInst.
	// Note that some deployments may not require a container id.
	if req.ContainerId == "" {
		if appInst.RuntimeInfo.ContainerIds == nil ||
			len(appInst.RuntimeInfo.ContainerIds) == 0 {
			return "", fmt.Errorf("no containers to run command in")
		}
		req.ContainerId = appInst.RuntimeInfo.ContainerIds[0]
	}
	podName := ""
	containerName := ""
	namespace := DefaultNamespace
	parts := strings.Split(req.ContainerId, "/")
	if len(parts) == 1 {
		// old way
		podName = parts[0]
	} else if len(parts) == 2 {
		// new way
		podName = parts[0]
		containerName = parts[1]
	} else if len(parts) == 3 {
		// namespace also included
		namespace = parts[0]
		podName = parts[1]
		containerName = parts[2]
	} else {
		return "", fmt.Errorf("invalid containerID, expected to be of format <namespace>/<PodName>/<ContainerName>")
	}
	names, err := GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return "", fmt.Errorf("failed to get kube names, %v", err)
	}
	kconfArg := names.GetTenantKconfArg()
	if req.Cmd != nil {
		containerCmd := ""
		if containerName != "" {
			containerCmd = fmt.Sprintf("-c %s ", containerName)
		}
		cmdStr := fmt.Sprintf("kubectl %s exec -n %s -it %s%s -- %s",
			kconfArg, namespace, containerCmd, podName, req.Cmd.Command)
		return cmdStr, nil
	}
	if req.Log != nil {
		cmdStr := fmt.Sprintf("kubectl %s logs -n %s ", kconfArg, namespace)
		if req.Log.Since != "" {
			_, perr := time.ParseDuration(req.Log.Since)
			if perr == nil {
				cmdStr += fmt.Sprintf("--since=%s ", req.Log.Since)
			} else {
				cmdStr += fmt.Sprintf("--since-time=%s ", req.Log.Since)
			}
		}
		if req.Log.Tail != 0 {
			cmdStr += fmt.Sprintf("--tail=%d ", req.Log.Tail)
		}
		if req.Log.Timestamps {
			cmdStr += "--timestamps=true "
		}
		if req.Log.Follow {
			cmdStr += "-f "
		}
		cmdStr += podName
		if containerName != "" {
			cmdStr += " -c " + containerName
		} else {
			cmdStr += " --all-containers"
		}
		return cmdStr, nil
	}
	return "", fmt.Errorf("no command or log specified with the exec request")
}
