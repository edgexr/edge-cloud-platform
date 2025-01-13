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
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
	ssh "github.com/edgexr/golang-ssh"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
)

type KubeNames struct {
	AppName                    string
	AppVersion                 string
	AppOrg                     string
	AppInstName                string
	AppInstOrg                 string
	HelmAppName                string
	AppURI                     string
	AppImage                   string
	AppRevision                string
	AppInstRevision            string
	ClusterName                string
	K8sNodeNameSuffix          string
	OperatorName               string
	ServiceNames               []string
	DeveloperDefinedNamespaces []string // namespaces included by developer in manifest
	KconfName                  string
	KconfArg                   string
	DeploymentType             string
	ImagePullSecrets           []string
	ImagePaths                 []string
	IsUriIPAddr                bool
	MultitenantNamespace       string // for apps launched in a multi-tenant cluster
	TenantKconfName            string
	TenantKconfArg             string
}

// In the case of single tenancy, there is only one kubeconfig
// file and KconfName and BaseKconfName are the same.
// In the case of multi-tenancy, KconfName is scoped to the tenant,
// while BaseKconfName grants full access.
type KconfNames struct {
	KconfName       string // full or tenant access
	KconfArg        string
	TenantKconfName string // full access
	TenantKconfArg  string
}

type KubeNamesOp func(k *KubeNames) error

func getKconfNameDeprecated(clusterName, cloudletOrg string) string {
	// This has a bug, it should have used the Cluster's Org
	// instead of the Cloudlet's Org. This means if two different
	// developers choose the same cluster name on the same cloudlet,
	// the kubeconfigs will overwrite each other.
	return fmt.Sprintf("%s.%s.kubeconfig", clusterName, cloudletOrg)
}

func GetKconfName(clusterInst *edgeproto.ClusterInst) string {
	if clusterInst.CompatibilityVersion >= cloudcommon.ClusterInstCompatibilityRegionScopeName {
		return fmt.Sprintf("%s.%s.kubeconfig", clusterInst.Key.Name, clusterInst.Key.Organization)
	} else {
		clusterName := cloudcommon.GetClusterInstCloudletScopedName(clusterInst)
		return getKconfNameDeprecated(clusterName, clusterInst.CloudletKey.Organization)
	}
}

func GetKconfArg(clusterInst *edgeproto.ClusterInst) string {
	return "--kubeconfig=" + GetKconfName(clusterInst)
}

func GetK8sNodeNameSuffix(clusterInst *edgeproto.ClusterInst) string {
	if clusterInst.CompatibilityVersion >= cloudcommon.ClusterInstCompatibilityRegionScopeName {
		cloudletName := clusterInst.CloudletKey.Name
		clusterName := clusterInst.Key.Name
		devName := clusterInst.Key.Organization
		return NormalizeName(cloudletName + "-" + clusterName + "-" + devName)
	} else {
		cloudletName := clusterInst.CloudletKey.Name
		clusterName := cloudcommon.GetClusterInstCloudletScopedName(clusterInst)
		devName := clusterInst.Key.Organization
		if devName != "" {
			return NormalizeName(cloudletName + "-" + clusterName + "-" + devName)
		}
		return NormalizeName(cloudletName + "-" + clusterName)
	}
}

// GetCloudletClusterName return the name of the cluster including cloudlet
func GetCloudletClusterName(cluster *edgeproto.ClusterInst) string {
	return GetK8sNodeNameSuffix(cluster)
}

func GetNamespace(appInst *edgeproto.AppInst) string {
	if appInst.CompatibilityVersion >= cloudcommon.AppInstCompatibilityRegionScopeName {
		return util.NamespaceSanitize(fmt.Sprintf("%s-%s", appInst.Key.Name, appInst.Key.Organization))
	} else if appInst.CompatibilityVersion >= cloudcommon.AppInstCompatibilityUniqueNameKey {
		name := cloudcommon.GetAppInstCloudletScopedName(appInst)
		return util.NamespaceSanitize(fmt.Sprintf("%s-%s", name, appInst.Key.Organization))
	} else {
		// Note that we use the virtual cluster name, not the real cluster name
		vclust := appInst.VClusterKey()
		return util.NamespaceSanitize(fmt.Sprintf("%s-%s-%s-%s", appInst.AppKey.Organization, appInst.AppKey.Name, appInst.AppKey.Version, vclust.Name))
	}
}

func NormalizeName(name string) string {
	return util.K8SSanitize(name)
}

// FixImagePath removes localhost and adds Docker Hub as needed.  For example,
// networkstatic/iperf3 becomes docker.io/networkstatic/iperf3
func FixImagePath(origImagePath string) string {
	newImagePath := origImagePath
	parts := strings.Split(origImagePath, "/")
	if parts[0] == "localhost" {
		newImagePath = strings.Replace(origImagePath, "localhost/", "", -1)
	} else {
		// Append default registry address for internal image paths
		if len(parts) < 2 || !strings.Contains(parts[0], ".") {
			newImagePath = cloudcommon.DockerHub + "/" + origImagePath
		}
	}
	return newImagePath
}

func GetNormalizedClusterName(clusterInst *edgeproto.ClusterInst) string {
	if clusterInst.CompatibilityVersion >= cloudcommon.ClusterInstCompatibilityRegionScopeName {
		return NormalizeName(clusterInst.Key.Name + clusterInst.Key.Organization)
	} else {
		clusterName := cloudcommon.GetClusterInstCloudletScopedName(clusterInst)
		return NormalizeName(clusterName + clusterInst.Key.Organization)
	}
}

// GetKubeNames udpates kubeNames with normalized strings for the included clusterinst, app, and appisnt
func GetKubeNames(clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, opts ...KubeNamesOp) (*KubeNames, error) {
	if clusterInst == nil {
		return nil, fmt.Errorf("nil cluster inst")
	}
	if app == nil {
		return nil, fmt.Errorf("nil app")
	}
	if appInst == nil {
		return nil, fmt.Errorf("nil app inst")
	}
	kubeNames := KubeNames{}
	for _, op := range opts {
		if err := op(&kubeNames); err != nil {
			return nil, err
		}
	}
	var appInstName string
	if appInst.CompatibilityVersion >= cloudcommon.AppInstCompatibilityRegionScopeName {
		appInstName = appInst.Key.Name
	} else {
		appInstName = cloudcommon.GetAppInstCloudletScopedName(appInst)
	}
	kubeNames.ClusterName = GetNormalizedClusterName(clusterInst)
	kubeNames.K8sNodeNameSuffix = GetK8sNodeNameSuffix(clusterInst)
	kubeNames.AppName = NormalizeName(app.Key.Name)
	kubeNames.AppVersion = NormalizeName(app.Key.Version)
	kubeNames.AppOrg = NormalizeName(app.Key.Organization)
	kubeNames.AppInstName = NormalizeName(appInstName)
	kubeNames.AppInstOrg = NormalizeName(appInst.Key.Organization)
	// Helm app name has to conform to DNS naming standards
	kubeNames.HelmAppName = util.DNSSanitize(app.Key.Name + "v" + app.Key.Version)
	kubeNames.AppURI = appInst.Uri
	kubeNames.AppRevision = app.Revision
	kubeNames.AppInstRevision = appInst.Revision
	kubeNames.AppImage = NormalizeName(app.ImagePath)
	kubeNames.OperatorName = NormalizeName(clusterInst.CloudletKey.Organization)
	kubeNames.KconfName = GetKconfName(clusterInst)
	kubeNames.KconfArg = "--kubeconfig=" + kubeNames.KconfName
	// if clusterInst is multi-tenant and AppInst is specified,
	// set up tenant kubeconfig
	if clusterInst.MultiTenant && appInstName != "" && !cloudcommon.IsSideCarApp(app) {
		kubeNames.MultitenantNamespace = GetNamespace(appInst)
		baseName := strings.TrimSuffix(kubeNames.KconfName, ".kubeconfig")
		kubeNames.TenantKconfName = fmt.Sprintf("%s.%s.kubeconfig", baseName, kubeNames.MultitenantNamespace)
		kubeNames.TenantKconfArg = "--kubeconfig=" + kubeNames.TenantKconfName
	}
	kubeNames.DeploymentType = app.Deployment
	if app.ImagePath != "" {
		kubeNames.ImagePaths = append(kubeNames.ImagePaths, app.ImagePath)
	}
	//get service names from the yaml
	if app.Deployment == cloudcommon.DeploymentTypeKubernetes {
		objs, _, err := cloudcommon.DecodeK8SYaml(app.DeploymentManifest)
		if err != nil {
			return nil, fmt.Errorf("invalid kubernetes deployment yaml, %s", err.Error())
		}
		var template *v1.PodTemplateSpec
		for _, o := range objs {
			log.DebugLog(log.DebugLevelInfra, "k8s obj", "obj", o)
			template = nil
			switch obj := o.(type) {
			case *v1.Service:
				svcName := obj.ObjectMeta.Name
				kubeNames.ServiceNames = append(kubeNames.ServiceNames, svcName)
			case *appsv1.Deployment:
				template = &obj.Spec.Template
			case *appsv1.DaemonSet:
				template = &obj.Spec.Template
			case *appsv1.StatefulSet:
				template = &obj.Spec.Template
			case *v1.Namespace:
				// if this is not a multi tenant case, any additional namespaces are from a developer manifest
				if kubeNames.MultitenantNamespace == "" {
					kubeNames.DeveloperDefinedNamespaces = append(kubeNames.DeveloperDefinedNamespaces, obj.Name)
				}
			}
			if template == nil {
				continue
			}
			containers := []v1.Container{}
			containers = append(containers, template.Spec.InitContainers...)
			containers = append(containers, template.Spec.Containers...)
			for _, cont := range containers {
				if cont.Image == "" {
					continue
				}
				kubeNames.ImagePaths = append(kubeNames.ImagePaths, cont.Image)
			}
		}
	} else if app.Deployment == cloudcommon.DeploymentTypeHelm {
		// for helm chart just make sure it's the same prefix
		kubeNames.ServiceNames = append(kubeNames.ServiceNames, kubeNames.AppName)
	} else if app.Deployment == cloudcommon.DeploymentTypeDocker {
		// for docker use the app name
		kubeNames.ServiceNames = append(kubeNames.ServiceNames, kubeNames.AppName)
		if app.DeploymentManifest != "" && !strings.HasSuffix(app.DeploymentManifest, ".zip") {
			containers, err := cloudcommon.DecodeDockerComposeYaml(app.DeploymentManifest)
			if err != nil {
				return nil, fmt.Errorf("invalid docker compose yaml, %s", err.Error())
			}
			for _, cont := range containers {
				kubeNames.ImagePaths = append(kubeNames.ImagePaths, FixImagePath(cont.Image))
			}
		}
	}
	return &kubeNames, nil
}

func (k *KubeNames) ContainsService(svc string) bool {
	for _, s := range k.ServiceNames {
		if strings.HasPrefix(svc, s) {
			return true
		}
	}
	return false
}

func (k *KubeNames) GetTenantKconfArg() string {
	if k.TenantKconfArg != "" {
		return k.TenantKconfArg
	}
	return k.KconfArg
}

func (k *KubeNames) GetKConfNames() *KconfNames {
	return &KconfNames{
		KconfName: k.KconfName,
		KconfArg:  k.KconfArg,
	}
}

// GetCloudletKConfNames gets the KConfNames for a single cluster
// acting as a cloudlet
func GetCloudletKConfNames(key *edgeproto.CloudletKey) *KconfNames {
	names := KconfNames{}
	names.KconfName = fmt.Sprintf("%s.%s.cloudlet-kubeconfig", key.Name, key.Organization)
	names.KconfArg = "--kubeconfig=" + names.KconfName
	return &names
}

func EnsureNamespace(ctx context.Context, client ssh.Client, names *KconfNames, namespace string) error {
	// this creates the yaml and applies it so there is no
	// failure if the namespace already exists.
	cmd := fmt.Sprintf("kubectl %s create ns %s --dry-run=client -o yaml | kubectl %s apply -f -", names.KconfArg, namespace, names.KconfArg)
	out, err := client.Output(cmd)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to ensure namespace", "name", namespace, "cmd", cmd, "out", out, "err", err)
		return fmt.Errorf("failed to create namespace %s: %s, %s", namespace, out, err)
	}
	return nil
}

func DeleteNamespace(ctx context.Context, client ssh.Client, names *KconfNames, namespace string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "deleting namespace", "name", namespace)
	cmd := fmt.Sprintf("kubectl %s delete namespace %s", names.KconfArg, namespace)
	out, err := client.Output(cmd)
	if err != nil {
		if !strings.Contains(out, "not found") {
			return fmt.Errorf("Error in deleting namespace: %s - %v", out, err)
		}
	}
	return nil
}
