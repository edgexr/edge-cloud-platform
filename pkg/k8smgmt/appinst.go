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

var podStateRegString = "(\\S+)\\s+(\\S+)\\s+(\\S+)\\s+(.*)\\s*"
var podStateReg = regexp.MustCompile(podStateRegString)

func LbServicePortToString(p *v1.ServicePort) string {
	proto := p.Protocol
	port := p.Port
	return edgeproto.ProtoPortToString(string(proto), port)
}

func CheckPodsStatus(ctx context.Context, client ssh.Client, kConfArg, namespace, selector, waitFor string, startTimer time.Time) (bool, error) {
	done := false
	log.SpanLog(ctx, log.DebugLevelInfra, "check pods status", "namespace", namespace, "selector", selector)
	// custom columns will show <none> if there is nothing to display
	cmd := fmt.Sprintf("kubectl %s get pods --no-headers -n %s --selector=%s -o=custom-columns='Name:metadata.name,Status:status.phase,Reason:status.conditions[].reason,Message:status.conditions[].message'", kConfArg, namespace, selector)
	out, err := client.Output(cmd)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "error getting pods", "err", err, "out", out)
		return done, fmt.Errorf("error getting pods: %v", err)
	}
	lines := strings.Split(out, "\n")
	// there are potentially multiple pods in the lines loop, we will quit processing this obj
	// only when they are all up, i.e. no non-
	podCount := 0
	runningCount := 0

	for _, line := range lines {
		if line == "" {
			continue
		}
		if strings.Contains(line, "No resources found") {
			// If creating, pods may not have taken
			// effect yet. If deleting, may already
			// be removed.
			if waitFor == WaitRunning && time.Since(startTimer) > createWaitNoResources {
				return done, fmt.Errorf("no resources found for %s on create: %s", createWaitNoResources, line)
			}
			break
		} else if podStateReg.MatchString(line) {
			// there can be multiple pods, one per line. If all
			// of them are running we can quit the loop
			podCount++
			matches := podStateReg.FindStringSubmatch(line)
			podName := matches[1]
			podState := matches[2]
			reason := matches[3]
			message := matches[4]
			switch podState {
			case "Running":
				log.SpanLog(ctx, log.DebugLevelInfra, "pod is running", "podName", podName)
				runningCount++
			case "Pending":
				if reason == "Unschedulable" {
					log.SpanLog(ctx, log.DebugLevelInfra, "pod cannot be scheduled", "podName", podName, "message", message)
					return done, fmt.Errorf("Run container failed, pod could not be scheduled, message: %s", message)
				}
				fallthrough
			case "ContainerCreating":
				fallthrough
			case "CreateContainerConfigError": // this can be a transient state for some deployments
				log.SpanLog(ctx, log.DebugLevelInfra, "still waiting for pod", "podName", podName, "state", podState)
			case "Terminating":
				log.SpanLog(ctx, log.DebugLevelInfra, "pod is terminating", "podName", podName, "state", podState)
			default:
				log.SpanLog(ctx, log.DebugLevelInfra, "pod state unhandled", "podName", podName, "state", podState, "out", out)
				if podState == "Failed" && waitFor == WaitDeleted {
					// Failed state can happen momentarily when
					// pod's container is in state Terminated,
					// before it's actually removed. If we hit this
					// while waiting for a delete, let it try again
					continue
				}
				if strings.Contains(podState, "Init") {
					// Init state cannot be matched exactly, e.g. Init:0/2
					log.SpanLog(ctx, log.DebugLevelInfra, "pod in init state", "podName", podName, "state", podState)
				} else {
					// try to find out what error was
					// TODO: pull events and send
					// them back as status updates
					// rather than sending back
					// full "describe" dump
					cmd := fmt.Sprintf("kubectl %s describe pod -n %s --selector=%s", kConfArg, namespace, selector)
					out, derr := client.Output(cmd)
					if derr == nil {
						return done, fmt.Errorf("Run container failed, pod state: %s - %s", podState, out)
					}
					return done, fmt.Errorf("Pod is unexpected state: %s", podState)
				}
			}
		} else {
			return done, fmt.Errorf("unable to parse kubectl output: [%s]", line)
		}
	}
	if waitFor == WaitDeleted {
		if podCount == 0 {
			log.SpanLog(ctx, log.DebugLevelInfra, "all pods gone", "selector", selector)
			done = true
		}
	} else {
		if podCount == 0 {
			// race condition, may not find anything if run before pods show up
			log.SpanLog(ctx, log.DebugLevelInfra, "not delete, but no pods found, assume command run before pods deployed", "selector", selector)
			return false, nil
		}
		if podCount == runningCount {
			log.SpanLog(ctx, log.DebugLevelInfra, "all pods up", "selector", selector)
			done = true
		}
	}
	return done, nil
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
				if names.MultitenantNamespace != "" {
					namespace = names.MultitenantNamespace
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
			elapsed := time.Since(start)
			if elapsed >= (maxWait) {
				// for now we will return no errors when we time out.  In future we will use some other state or status
				// field to reflect this and employ health checks to track these appinsts
				log.InfoLog("AppInst wait timed out", "appName", app.Key.Name)
				break
			}
			time.Sleep(1 * time.Second)
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
	log.SpanLog(ctx, log.DebugLevelInfra, "UpdateLoadBalancerPortMap", "names.MultitenantNamespace", names.MultitenantNamespace)

	for _, s := range services {
		lbip := ""
		// It is possible to have ports for internal services that may overlap but not exposed externally. Skip services not part of this app.
		if !names.ContainsService(s.Name) {
			continue
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "service name match found in kubenames", "svc name", s.Name)
		if names.MultitenantNamespace != "" {
			svcNamespace := s.ObjectMeta.Namespace
			if svcNamespace != names.MultitenantNamespace {
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
				log.SpanLog(ctx, log.DebugLevelInfra, "found load balancer ip for port", "portString", portString, "lbip", lbip, "names.MultitenantNamespace", names.MultitenantNamespace)
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

func getConfigDirName(names *KubeNames) string {
	dir := names.ClusterName
	if names.MultitenantNamespace != "" {
		dir += "." + names.MultitenantNamespace
	}
	return dir
}

func getConfigFileName(names *KubeNames, appInst *edgeproto.AppInst) string {
	if appInst.CompatibilityVersion < cloudcommon.AppInstCompatibilityUniqueNameKeyConfig {
		// backwards compatibility, may clobber other instances
		// using the same app definition in multi-tenant clusters.
		return names.AppName + names.AppOrg + names.AppVersion + ".yaml"
	} else if appInst.CompatibilityVersion < cloudcommon.AppInstCompatibilityRegionScopeName {
		appInstName := cloudcommon.GetAppInstCloudletScopedName(appInst)
		return appInstName + names.AppInstOrg + ".yaml"
	}
	return names.AppInstName + names.AppInstOrg + ".yaml"
}

func getIngressFileName(names *KubeNames) string {
	return names.AppInstName + names.AppInstOrg + "-ingress.yaml"
}

// CreateAllNamespaces creates all the namespaces the app will use. It does not create a manifest for
// the namespaces, just allows the basic dependencies can be defined against
// them. Manifest definition can later be used to update the namespaces.
func CreateAllNamespaces(ctx context.Context, client ssh.Client, names *KubeNames) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateAllNamespaces", "names", names)
	namespaces := names.DeveloperDefinedNamespaces
	if names.MultitenantNamespace != "" {
		namespaces = append(namespaces, names.MultitenantNamespace)
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

func WriteDeploymentManifestToFile(ctx context.Context, accessApi platform.AccessApi, client ssh.Client, names *KubeNames, app *edgeproto.App, appInst *edgeproto.AppInst) error {
	mf, err := cloudcommon.GetDeploymentManifest(ctx, accessApi, app.DeploymentManifest)
	if err != nil {
		return err
	}
	if names.MultitenantNamespace != "" {
		// Mulit-tenant cluster, add network policy
		np, err := GetNetworkPolicy(ctx, app, appInst, names)
		if err != nil {
			return err
		}
		mf = AddManifest(mf, np)
	}
	mf, err = MergeEnvVars(ctx, accessApi, app, appInst, mf, names.ImagePullSecrets, names, appInst.KubernetesResources)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to merge env vars", "error", err)
		return fmt.Errorf("error merging environment variables config file: %s", err)
	}
	configDir := getConfigDirName(names)
	configName := getConfigFileName(names, appInst)
	err = pc.CreateDir(ctx, client, configDir, pc.NoOverwrite, pc.NoSudo)
	if err != nil {
		return err
	}
	file := configDir + "/" + configName
	log.SpanLog(ctx, log.DebugLevelInfra, "writing config file", "file", file, "kubeManifest", mf)
	err = pc.WriteFile(client, file, mf, "K8s Deployment", pc.NoSudo)
	if err != nil {
		return err
	}

	return nil
}

func createOrUpdateAppInst(ctx context.Context, accessApi platform.AccessApi, client ssh.Client, names *KubeNames, app *edgeproto.App, appInst *edgeproto.AppInst, _ *edgeproto.Flavor, action string) error {
	if action == createManifest && names.MultitenantNamespace != "" {
		err := EnsureNamespace(ctx, client, names.GetKConfNames(), names.MultitenantNamespace)
		if err != nil {
			return err
		}
	}

	if err := WriteDeploymentManifestToFile(ctx, accessApi, client, names, app, appInst); err != nil {
		return err
	}
	configDir := getConfigDirName(names)

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
	log.SpanLog(ctx, log.DebugLevelInfra, "running kubectl", "action", action, "cmd", cmd)
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
	log.SpanLog(ctx, log.DebugLevelInfra, "done kubectl", "action", action)
	return nil

}

func CreateAppInst(ctx context.Context, accessApi platform.AccessApi, client ssh.Client, names *KubeNames, app *edgeproto.App, appInst *edgeproto.AppInst, appInstFlavor *edgeproto.Flavor) error {
	return createOrUpdateAppInst(ctx, accessApi, client, names, app, appInst, appInstFlavor, createManifest)
}

func UpdateAppInst(ctx context.Context, accessApi platform.AccessApi, client ssh.Client, names *KubeNames, app *edgeproto.App, appInst *edgeproto.AppInst, appInstFlavor *edgeproto.Flavor) error {
	err := createOrUpdateAppInst(ctx, accessApi, client, names, app, appInst, appInstFlavor, applyManifest)
	if err != nil {
		return err
	}
	return WaitForAppInst(ctx, client, names, app, WaitRunning)
}

func DeleteAppInst(ctx context.Context, accessApi platform.AccessApi, client ssh.Client, names *KubeNames, app *edgeproto.App, appInst *edgeproto.AppInst) error {
	if err := WriteDeploymentManifestToFile(ctx, accessApi, client, names, app, appInst); err != nil {
		return err
	}
	kconfArg := names.GetTenantKconfArg()
	configDir := getConfigDirName(names)
	configName := getConfigFileName(names, appInst)
	file := configDir + "/" + configName
	cmd := fmt.Sprintf("kubectl %s delete -f %s", kconfArg, file)
	log.SpanLog(ctx, log.DebugLevelInfra, "deleting app", "name", names.AppName, "cmd", cmd)
	out, err := client.Output(cmd)
	if err != nil {
		if strings.Contains(string(out), "not found") {
			log.SpanLog(ctx, log.DebugLevelInfra, "app not found, cannot delete", "name", names.AppName)
		} else {
			return fmt.Errorf("error deleting kuberknetes app, %s, %s, %s, %v", names.AppName, cmd, out, err)
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "deleted deployment", "name", names.AppName)
	//Note wait for deletion of appinst can be done here in a generic place, but wait for creation is split
	// out in each platform specific task so that we can optimize the time taken for create by allowing the
	// wait to be run in parallel with other tasks
	err = WaitForAppInst(ctx, client, names, app, WaitDeleted)
	if err != nil {
		return err
	}
	// remove manifest file since directory contains all AppInst manifests for
	// the ClusterInst.
	log.SpanLog(ctx, log.DebugLevelInfra, "remove app manifest", "name", names.AppName, "file", file)
	err = pc.DeleteFile(client, file, pc.NoSudo)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "error deleting manifest", "file", file, "err", err)
	}
	if names.MultitenantNamespace != "" {
		// clean up namespace
		if err = DeleteNamespace(ctx, client, names.GetKConfNames(), names.MultitenantNamespace); err != nil {
			return err
		}
		if err = RemoveTenantKubeconfig(ctx, client, names); err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to clean up tenant kubeconfig", "err", err)
		}
		// delete the config dir
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
			if names.MultitenantNamespace != "" {
				namespace = names.MultitenantNamespace
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
