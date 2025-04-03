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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"text/template"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/deploygen"
	"github.com/edgexr/edge-cloud-platform/pkg/deployvars"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	ssh "github.com/edgexr/golang-ssh"
	yaml "github.com/mobiledgex/yaml/v2"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const MexAppLabel = "mex-app"
const ConfigLabel = "config"

// TestReplacementVars are used to syntax check app envvars
var TestReplacementVars = deployvars.DeploymentReplaceVars{
	Deployment: deployvars.CrmReplaceVars{
		ClusterIp:    "99.99.99.99",
		CloudletName: "dummyCloudlet",
		ClusterName:  "dummyCluster",
		CloudletOrg:  "dummyCloudletOrg",
		AppOrg:       "dummyAppOrg",
		DnsZone:      "dummy.net",
	},
}

func addEnvVars(ctx context.Context, template *v1.PodTemplateSpec, envVars []v1.EnvVar, appEnvVars *v1.ConfigMap, appSecretVars *v1.Secret) {
	// walk the containers and append environment variables to each
	for j, _ := range template.Spec.Containers {
		template.Spec.Containers[j].Env = append(template.Spec.Containers[j].Env, envVars...)
		if appEnvVars != nil {
			addEnvFromConfigMap(&template.Spec.Containers[j], appEnvVars)
		}
		if appSecretVars != nil {
			addEnvFromSecret(&template.Spec.Containers[j], appSecretVars)
		}
	}
}

func addEnvFromConfigMap(container *v1.Container, configMap *v1.ConfigMap) {
	container.EnvFrom = append(container.EnvFrom, v1.EnvFromSource{
		ConfigMapRef: &v1.ConfigMapEnvSource{
			LocalObjectReference: v1.LocalObjectReference{
				Name: configMap.ObjectMeta.Name,
			},
		},
	})
}

func addEnvFromSecret(container *v1.Container, secret *v1.Secret) {
	container.EnvFrom = append(container.EnvFrom, v1.EnvFromSource{
		SecretRef: &v1.SecretEnvSource{
			LocalObjectReference: v1.LocalObjectReference{
				Name: secret.ObjectMeta.Name,
			},
		},
	})
}

func addImagePullSecret(ctx context.Context, template *v1.PodTemplateSpec, secretNames []string) {
	for _, secretName := range secretNames {
		found := false
		for _, s := range template.Spec.ImagePullSecrets {
			if s.Name == secretName {
				found = true
				break
			}
		}
		if !found {
			var newSecret v1.LocalObjectReference
			newSecret.Name = secretName
			log.SpanLog(ctx, log.DebugLevelInfra, "adding imagePullSecret", "secretName", secretName)
			template.Spec.ImagePullSecrets = append(template.Spec.ImagePullSecrets, newSecret)
		}
	}
}

func addMexLabel(meta *metav1.ObjectMeta, label string) {
	// Add a label so we can lookup the pods created by this
	// deployment. Pods names are used for shell access.
	meta.Labels[MexAppLabel] = label
}

// Add app details to the deployment as labels
// these labels will be picked up by Prometheus and added to the metrics
func addAppInstLabels(meta *metav1.ObjectMeta, appInst *edgeproto.AppInst) {
	labels := cloudcommon.GetAppInstLabels(appInst)
	for k, v := range labels.Map() {
		meta.Labels[k] = v
	}
}

// The config label marks all objects that are part of config files in the
// config dir. We use this with apply --prune -l config=configlabel to
// only prune objects that were created with the config label, and are no
// longer present in the configDir files.
// Only objects that are created via files in the configDir should have
// the config label. Typically this would be all the AppInsts in the
// Cluster (or namespace for multi-tenant clusters).
func getConfigLabel(names *KubeNames) string {
	if names.InstanceNamespace != "" {
		return names.InstanceNamespace
	}
	return names.ClusterName
}

type resourceQuotaArgs struct {
	Labels       map[string]string
	Name         string
	Namespace    string
	LimitsCPU    string
	LimitsMemory string
}

var k8sResourceQuotaTemplate = template.Must(template.New("resourcequota").Parse(`apiVersion: v1
kind: ResourceQuota
metadata:
{{- if .Labels }}
  labels:
{{- range $key, $value := .Labels }}
    {{ $key }}: {{ $value }}
{{- end }}
{{- end }}
  name: {{ .Name }}
  namespace: {{ .Namespace }}
spec:
  hard:
    limits.cpu: "{{ .LimitsCPU }}"
    limits.memory: {{ .LimitsMemory }}
`))

// GetResourceQuota returns a resource quota that limits the
// resources in the namespace for an appinst.
func GetResourceQuota(ctx context.Context, names *KubeNames, kr *edgeproto.KubernetesResources) (string, error) {
	namespace := names.InstanceNamespace
	if namespace == "" || kr == nil {
		return "", fmt.Errorf("ResourceQuota only valid for namespaced instances with Kubernetes Resources defined")
	}
	args := resourceQuotaArgs{}
	args.Name = namespace
	args.Namespace = namespace
	args.Labels = map[string]string{
		ConfigLabel: getConfigLabel(names),
	}
	res, err := getKubernetesResourceQuants(kr)
	if err != nil {
		return "", err
	}
	args.LimitsCPU = res.VCPUs.String()
	args.LimitsMemory = res.Memory.String()
	buf := bytes.Buffer{}
	err = k8sResourceQuotaTemplate.Execute(&buf, &args)
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}

type Resources struct {
	VCPUs  resource.Quantity
	Memory resource.Quantity
}

func getKubernetesResourceQuants(kr *edgeproto.KubernetesResources) (*Resources, error) {
	vcpus := edgeproto.NewUdec64(0, 0)
	ram := uint64(0)
	if kr.CpuPool != nil {
		vcpus.Add(&kr.CpuPool.TotalVcpus)
		ram += kr.CpuPool.TotalMemory
	}
	if kr.GpuPool != nil {
		vcpus.Add(&kr.GpuPool.TotalVcpus)
		ram += kr.GpuPool.TotalMemory
	}
	cpu, err := resource.ParseQuantity(vcpus.DecString())
	if err != nil {
		return nil, err
	}
	mem, err := resource.ParseQuantity(fmt.Sprintf("%dMi", ram))
	if err != nil {
		return nil, err
	}
	res := &Resources{
		VCPUs:  cpu,
		Memory: mem,
	}
	return res, nil
}

func addResourceLimits(template *v1.PodTemplateSpec, kr *edgeproto.KubernetesResources) error {
	res, err := getKubernetesResourceQuants(kr)
	if err != nil {
		return err
	}
	for j, _ := range template.Spec.Containers {
		resources := &template.Spec.Containers[j].Resources
		resources.Limits = v1.ResourceList{}
		resources.Limits[v1.ResourceCPU] = res.VCPUs
		resources.Limits[v1.ResourceMemory] = res.Memory
		resources.Requests = v1.ResourceList{}
		resources.Requests[v1.ResourceCPU] = res.VCPUs
		resources.Requests[v1.ResourceMemory] = res.Memory
	}
	return nil
}

func GetAppEnvVars(ctx context.Context, app *edgeproto.App, authApi cloudcommon.RegistryAuthApi, deploymentVars *deployvars.DeploymentReplaceVars) (*[]v1.EnvVar, error) {
	var envVars []v1.EnvVar
	for _, v := range app.Configs {
		if v.Kind == edgeproto.AppConfigEnvYaml {
			var curVars []v1.EnvVar
			cfg, err := cloudcommon.GetDeploymentManifest(ctx, authApi, v.Config)
			if err != nil {
				return nil, err
			}
			if deploymentVars != nil {
				cfg, err = deployvars.ReplaceDeploymentVars(cfg, app.TemplateDelimiter, deploymentVars)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelInfra, "failed to replace Crm variables",
						"EnvVars ", v.Config, "DeploymentVars", deploymentVars, "error", err)
					return nil, err
				}
			}
			err = yaml.Unmarshal([]byte(cfg), &curVars)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfra, "cannot unmarshal env vars", "kind", v.Kind,
					"config", cfg, "error", err)
				return nil, fmt.Errorf("cannot unmarshal env vars: %s - %v", cfg, err)
			} else {
				envVars = append(envVars, curVars...)
			}
		}
	}
	return &envVars, nil
}

// MergeEnvVars merges in all the environment variables into
// the manifest.
func MergeEnvVars(ctx context.Context, accessApi platform.AccessApi, app *edgeproto.App, appInst *edgeproto.AppInst, mf string, imagePullSecrets []string, names *KubeNames, kr *edgeproto.KubernetesResources) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "MergeEnvVars", "kubeManifest", mf)

	deploymentVars, varsFound := ctx.Value(deployvars.DeploymentReplaceVarsKey).(*deployvars.DeploymentReplaceVars)
	log.SpanLog(ctx, log.DebugLevelInfra, "MergeEnvVars", "deploymentVars", deploymentVars, "varsFound", varsFound)
	envVars, err := GetAppEnvVars(ctx, app, accessApi, deploymentVars)
	if err != nil {
		return "", err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "Merging environment variables", "envVars", envVars)
	// Fill in the Deployment Vars passed as a variable through the context
	if varsFound {
		mf, err = deployvars.ReplaceDeploymentVars(mf, app.TemplateDelimiter, deploymentVars)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "failed to replace Crm variables",
				"manifest", mf, "DeploymentVars", deploymentVars, "error", err)
			return "", err
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "Success to replace Crm variables",
			"manifest", mf, "DeploymentVars", deploymentVars)
	}

	//decode the objects so we can find the container objects, where we'll add the env vars
	objs, _, err := cloudcommon.DecodeK8SYaml(mf)
	if err != nil {
		return "", fmt.Errorf("invalid kubernetes deployment yaml, %s", err.Error())
	}

	var appEnvVars *v1.ConfigMap
	if len(app.EnvVars) > 0 {
		appEnvVarsFrom := names.AppName + names.AppVersion + "-envvars"
		appEnvVars = &v1.ConfigMap{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "ConfigMap",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: appEnvVarsFrom,
			},
			Data: app.EnvVars,
		}
		objs = append(objs, appEnvVars)
	}
	var appSecretVars *v1.Secret
	if len(app.SecretEnvVars) > 0 {
		secretVars, err := accessApi.GetAppSecretVars(ctx, &app.Key)
		if err != nil {
			return "", err
		}
		if len(secretVars) != len(app.SecretEnvVars) {
			return "", fmt.Errorf("failed to get the correct number of App secret vars from encrypted storage, expected %d but only got %d", len(app.SecretEnvVars), len(secretVars))
		}
		secretVarsFrom := names.AppName + names.AppVersion
		appSecretVars = &v1.Secret{
			TypeMeta: metav1.TypeMeta{
				APIVersion: "v1",
				Kind:       "Secret",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: secretVarsFrom,
			},
			StringData: secretVars,
		}
		objs = append(objs, appSecretVars)
	}

	//walk the objects
	var template *v1.PodTemplateSpec
	var name string
	for i, _ := range objs {
		// convert obj to generic metaObject to set labels on every obj
		var metaObj metav1.Object
		if obj, ok := objs[i].(metav1.Object); ok {
			metaObj = obj
		} else if acc, ok := objs[i].(metav1.ObjectMetaAccessor); ok {
			metaObj = acc.GetObjectMeta()
		}
		if metaObj != nil {
			labels := metaObj.GetLabels()
			if labels == nil {
				labels = make(map[string]string)
			}
			// config label is used to mark for pruning
			labels[ConfigLabel] = getConfigLabel(names)
			metaObj.SetLabels(labels)
		}

		template = nil
		name = ""
		switch obj := objs[i].(type) {
		case *appsv1.Deployment:
			template = &obj.Spec.Template
			name = obj.ObjectMeta.Name
			obj.Spec.Replicas = getDefaultReplicas(app, names, *obj.Spec.Replicas)
		case *appsv1.DaemonSet:
			template = &obj.Spec.Template
			name = obj.ObjectMeta.Name
		case *appsv1.StatefulSet:
			template = &obj.Spec.Template
			name = obj.ObjectMeta.Name
			obj.Spec.Replicas = getDefaultReplicas(app, names, *obj.Spec.Replicas)
		}
		if template == nil {
			continue
		}
		addEnvVars(ctx, template, *envVars, appEnvVars, appSecretVars)
		addMexLabel(&template.ObjectMeta, name)
		// Add labels for all the appKey data
		addAppInstLabels(&template.ObjectMeta, appInst)
		if imagePullSecrets != nil {
			addImagePullSecret(ctx, template, imagePullSecrets)
		}
		if names.MultiTenantRestricted && appInst.KubernetesResources != nil {
			if err := addResourceLimits(template, appInst.KubernetesResources); err != nil {
				return "", err
			}
		}
		gpuCountsByVendor := map[string]int{}
		if kr.GpuPool != nil {
			for _, gpu := range kr.GpuPool.TotalGpus {
				gpuCountsByVendor[gpu.Vendor]++
			}
			// Deprecrated optresmap gpus
			if optResGpuCount := cloudcommon.GetOptResGPUCount(kr.GpuPool.TotalOptRes); optResGpuCount > 0 {
				// generic gpu specs from opt res map were treated as
				// nvidia gpus.
				gpuCountsByVendor[cloudcommon.GPUVendorNVIDIA] += int(optResGpuCount)
			}
		}
		if len(gpuCountsByVendor) > 0 {
			// just set GPU resource limit for manifest generated by our
			// deployment generator. For custom deployment manifest, developer
			// will specify GPU resource limit if they need it
			_, ok := template.ObjectMeta.Labels[deploygen.MexDeployGenLabel]
			if !ok {
				continue
			}
			for vendor, gpuCount := range gpuCountsByVendor {
				gpuResName := GetResourceNameForGpuVendor(vendor)
				if gpuResName == "" {
					return "", fmt.Errorf("no Kubernetes resource name defined for gpu maker %s", vendor)
				}
				gpuCountQty := resource.NewQuantity(int64(gpuCount), resource.DecimalSI)
				for j, _ := range template.Spec.Containers {
					// This assumes just one container, as for deploygen
					// generated manifest will only have one container
					resources := &template.Spec.Containers[j].Resources
					if len(resources.Limits) == 0 {
						resources.Limits = v1.ResourceList{}
					}
					resName := v1.ResourceName(gpuResName)
					resources.Limits[resName] = *gpuCountQty
				}
			}
		}
	}

	//marshal the objects back together and return as one string
	mf, err = cloudcommon.EncodeK8SYaml(objs)
	if err != nil {
		return "", err
	}
	return mf, nil
}

func AddManifest(mf, addmf string) string {
	if strings.TrimSpace(addmf) == "" {
		return mf
	}
	if mf == "" {
		return addmf
	}
	return mf + "---\n" + addmf
}

func getDefaultReplicas(app *edgeproto.App, names *KubeNames, curReplica int32) *int32 {
	val := int32(1)
	if curReplica != 0 {
		val = curReplica
	}
	if names.InstanceNamespace != "" && app.ServerlessConfig != nil {
		val = int32(app.ServerlessConfig.MinReplicas)
	}
	return &val
}

func WaitForDeploymentReady(ctx context.Context, client ssh.Client, names *KconfNames, name, namespace string, retry int, retryDelay time.Duration) error {
	nsArg := ""
	if namespace != "" {
		nsArg = "-n " + namespace
	}
	dep := appsv1.Deployment{}
	cmd := fmt.Sprintf("kubectl %s %s get deployment %s -o json", names.KconfArg, nsArg, name)
	for ii := 0; ii < retry; ii++ {
		out, err := client.Output(cmd)
		if err != nil {
			return fmt.Errorf("failed to check if deployment %s is ready: %s, %s", name, string(out), err)
		}
		err = json.Unmarshal([]byte(out), &dep)
		if err != nil {
			return fmt.Errorf("failed to unmarshal deployment json, %s", err)
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "wait deployment ready", "deployment", name, "namespace", namespace, "ready", fmt.Sprintf("%d/%d", dep.Status.ReadyReplicas, dep.Status.Replicas))
		if dep.Status.Replicas > 0 && dep.Status.Replicas == dep.Status.ReadyReplicas {
			return nil
		}
		time.Sleep(retryDelay)
	}
	return fmt.Errorf("failed to wait for deployment %s namespace %s to be ready (%d/%d)", name, namespace, dep.Status.ReadyReplicas, dep.Status.Replicas)
}

func ApplyManifest(ctx context.Context, client ssh.Client, names *KubeNames, appInst *edgeproto.AppInst, suffix string, action cloudcommon.Action) error {
	kconfArg := names.GetTenantKconfArg()
	configDir := GetConfigDirName(names)
	configName := getConfigFileName(names, appInst, suffix)
	file := configDir + "/" + configName

	var cmd string
	if action == cloudcommon.Create {
		cmd = fmt.Sprintf("kubectl %s apply -f %s", kconfArg, file)
	} else if action == cloudcommon.Delete {
		cmd = fmt.Sprintf("kubectl %s delete -f %s", kconfArg, file)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "applying manifest", "cmd", cmd)
	out, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("failed to apply manifest %q: %s, %s", cmd, out, err)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "applied manifest", "file", file)
	return nil
}

func WriteManifest(ctx context.Context, client ssh.Client, names *KubeNames, appInst *edgeproto.AppInst, suffix, contents string) error {
	configDir := GetConfigDirName(names)
	configName := getConfigFileName(names, appInst, suffix)
	err := pc.CreateDir(ctx, client, configDir, pc.NoOverwrite, pc.NoSudo)
	if err != nil {
		return err
	}
	file := configDir + "/" + configName
	log.SpanLog(ctx, log.DebugLevelInfra, "writing manifest file", "file", file, "contents", contents)
	return pc.WriteFile(client, file, contents, "manifest", pc.NoSudo)
}

func CleanupManifest(ctx context.Context, client ssh.Client, names *KubeNames, appInst *edgeproto.AppInst, suffix string) error {
	configDir := GetConfigDirName(names)
	configName := getConfigFileName(names, appInst, suffix)
	file := configDir + "/" + configName
	log.SpanLog(ctx, log.DebugLevelInfra, "remove manifest", "file", file)
	return pc.DeleteFile(client, file, pc.NoSudo)
}

func GetResourceNameForGpuVendor(gpuVendor string) string {
	switch gpuVendor {
	case cloudcommon.GPUVendorAMD:
		return cloudcommon.KubernetesAMDGPUResource
	case cloudcommon.GPUVendorNVIDIA:
		return cloudcommon.KubernetesNvidiaGPUResource
	}
	return ""
}
