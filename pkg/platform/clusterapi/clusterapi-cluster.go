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

package clusterapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"strconv"
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/metal3"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	ssh "github.com/edgexr/golang-ssh"
	infrav1 "github.com/metal3-io/cluster-api-provider-metal3/api/v1beta1"
	"github.com/mobiledgex/yaml/v2"
	"golang.org/x/crypto/bcrypt"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/cluster-api/api/core/v1beta2"
	clusterv1 "sigs.k8s.io/cluster-api/api/core/v1beta2"

	metal3provv1 "github.com/metal3-io/cluster-api-provider-metal3/api/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	bootstrapv1 "sigs.k8s.io/cluster-api/api/bootstrap/kubeadm/v1beta2"
	controlplanev1 "sigs.k8s.io/cluster-api/api/controlplane/kubeadm/v1beta2"
)

var kamajiControlPlaneTemplate *template.Template

const DebugUserPassword = "DebugUserPassword"

func init() {
	// register supporting CRD schemes to global scheme
	_ = apiextensionsv1.AddToScheme(scheme.Scheme)
	_ = clusterv1.AddToScheme(scheme.Scheme)
	_ = infrav1.AddToScheme(scheme.Scheme)
	_ = controlplanev1.AddToScheme(scheme.Scheme)
	_ = bootstrapv1.AddToScheme(scheme.Scheme)
	kamajiControlPlaneTemplate = template.Must(template.New("kcp").Parse(kamajiControlPlaneTemplateString))
}

func (s *ClusterAPI) GetCredentials(ctx context.Context, clusterName string, clusterInst *edgeproto.ClusterInst) ([]byte, error) {
	names, err := s.ensureCAPIKubeconfig(ctx, s.getClient())
	if err != nil {
		return nil, err
	}
	return s.getCredentials(ctx, s.getClient(), names, clusterName)
}

func (s *ClusterAPI) getCredentials(ctx context.Context, client ssh.Client, names *k8smgmt.KconfNames, clusterName string) ([]byte, error) {
	clusterctl, err := s.ensureClusterCtl(ctx, client)
	if err != nil {
		return nil, err
	}
	cmd := fmt.Sprintf("%s %s -n %s get kubeconfig %s", clusterctl, names.KconfArg, s.namespace, clusterName)
	out, outerr, err := pc.RunOutput(client, cmd)
	if err != nil {
		return nil, fmt.Errorf("CAPI get credentials failed, %s, %s, %s, %s", cmd, out, outerr, err)
	}
	return []byte(out), nil
}

func (s *ClusterAPI) ensureClusterKubeconfig(ctx context.Context, client ssh.Client, capiNames *k8smgmt.KconfNames, clusterInst *edgeproto.ClusterInst, clusterName string) (*k8smgmt.KconfNames, error) {
	kc, err := s.getCredentials(ctx, client, capiNames, clusterName)
	if err != nil {
		return nil, err
	}
	kconfName := k8smgmt.GetKconfName(clusterInst)
	err = k8smgmt.EnsureKubeconfig(ctx, client, kconfName, kc)
	if err != nil {
		return nil, err
	}
	return &k8smgmt.KconfNames{
		KconfName: kconfName,
		KconfArg:  "--kubeconfig=" + kconfName,
	}, nil
}

func (s *ClusterAPI) CreateClusterPrerequisites(ctx context.Context, clusterName string) error {
	return nil
}

func (s *ClusterAPI) generateClusterManifest(ctx context.Context, names *k8smgmt.KconfNames, clusterName string, clusterInst *edgeproto.ClusterInst, caCert string) (string, error) {
	version := clusterInst.KubernetesVersion
	if version == "" {
		return "", fmt.Errorf("cluster must specify the kubernetes version")
	}
	client := s.getClient()
	var controlNP *edgeproto.NodePool
	var workerNPs []*edgeproto.NodePool
	var infraFlavor string
	// currently we only support a single control pool and
	// single worker pool. To add additional worker pools,
	// we'd apparently need to manually copy and edit generated
	// MachineDeployments.
	for _, np := range clusterInst.NodePools {
		if np.ControlPlane {
			if controlNP != nil {
				return "", fmt.Errorf("cluster %s may only specify a single control node pool", clusterName)
			}
			controlNP = np
		} else {
			workerNPs = append(workerNPs, np)
			if np.NodeResources == nil {
				return "", fmt.Errorf("cluster %s node pool %s must specify node resources for the infra node flavor", clusterName, np.Name)
			}
			if np.NodeResources.InfraNodeFlavor == "" {
				return "", fmt.Errorf("cluster %s node pool %s must specify an infra node flavor", clusterName, np.Name)
			}
			infraFlavor = np.NodeResources.InfraNodeFlavor
		}
	}
	if controlNP != nil {
		if controlNP.NumNodes%2 == 0 {
			return "", fmt.Errorf("cluster %s specified %d control plane nodes, but must be odd for Etcd", clusterName, controlNP.NumNodes)
		}
	} else {
		// default to a single control plane node, which is
		// equivalent to ClusterInst.NumMasters
		controlNP = &edgeproto.NodePool{
			NumNodes:     1,
			ControlPlane: true,
		}
	}
	if len(workerNPs) == 0 {
		return "", fmt.Errorf("cluster %s must specify a worker node pool", clusterName)
	}
	if len(workerNPs) > 1 {
		return "", fmt.Errorf("cluster %s may only specify a single worker node pool", clusterName)
	}
	if clusterInst.Annotations == nil {
		return "", fmt.Errorf("no floating VIP allocated for cluster %s", clusterName)
	}
	vip, ok := clusterInst.Annotations[cloudcommon.AnnotationControlVIP]
	if !ok {
		return "", fmt.Errorf("no floating VIP allocated for cluster %s", clusterName)
	}
	if vip == "" {
		return "", fmt.Errorf("empty floating VIP for cluster %s", clusterName)
	}
	imageURL, _ := s.properties.GetValue(ImageURL)
	imageChecksum, _ := s.properties.GetValue(ImageChecksum)
	imageChecksumType, _ := s.properties.GetValue(ImageChecksumType)
	imageFormat, _ := s.properties.GetValue(ImageFormat)

	// Set the kube API port to 6443 instead of 6444 because it's
	// possible when the management cluster is running on k3s that
	// the load balancer created for the kamaji control plane may
	// be assigned the k3s node's IP, overlapping the cluster's
	// kube API port and bricking the cluster.
	apiPort := 6444
	// Create a config file for cluster vars, which is easier than trying
	// to set env vars for this remote clusterctl command.
	// Note that we fill in the extra configs later directly into
	// the yaml, because the format of the env vars is a text chunk
	// that requires leading whitespace to match the target yaml
	// manifest, but that can't be done in the yaml config file.
	// To see what variables can be specified, run:
	// clusterctl generate cluster foo --list-variables
	config := map[string]string{
		// This is a VIP for the cluster control plane
		"CLUSTER_APIENDPOINT_HOST":      vip,
		"CLUSTER_APIENDPOINT_PORT":      strconv.Itoa(apiPort),
		"IMAGE_CHECKSUM":                imageChecksum,
		"IMAGE_CHECKSUM_TYPE":           imageChecksumType,
		"IMAGE_FORMAT":                  imageFormat,
		"IMAGE_URL":                     imageURL,
		"KUBERNETES_VERSION":            version,
		"CTLPLANE_KUBEADM_EXTRA_CONFIG": "", // fill in later
		"WORKERS_KUBEADM_EXTRA_CONFIG":  "", // fill in later
	}
	configContents, err := yaml.Marshal(config)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "failed to marshal cluster config", "config", config, "err", err)
		return "", fmt.Errorf("failed to marshal cluster config, %s", err)
	}
	configFile := fmt.Sprintf("%s-capi-config.yaml", clusterName)
	err = pc.WriteFile(client, configFile, string(configContents), "cluster-capi-config", pc.NoSudo)
	if err != nil {
		return "", err
	}

	clusterctl, err := s.ensureClusterCtl(ctx, client)
	if err != nil {
		return "", err
	}
	cmd := fmt.Sprintf("%s %s generate cluster %s --kubernetes-version %s --target-namespace %s --control-plane-machine-count=%d --worker-machine-count=%d --infrastructure %s --config %s", clusterctl, names.KconfArg, clusterName, version, s.namespace, controlNP.NumNodes, workerNPs[0].NumNodes, s.infra, configFile)
	log.SpanLog(ctx, log.DebugLevelInfra, "CAPI generate cluster manifests", "cmd", cmd)

	out, outerr, err := pc.RunOutput(client, cmd)
	if err != nil {
		return "", fmt.Errorf("CAPI generate cluster manifests failed, %s, %s, %s, %s", cmd, out, outerr, err)
	}
	manifest := out

	objs, gvks, err := cloudcommon.DecodeK8SYaml(manifest)
	if err != nil {
		return "", fmt.Errorf("failed to decode cluster manifests, %s", err)
	}

	buf := bytes.Buffer{}
	kcpArgs := kamajiControlPlaneTemplateArgs{
		Name:                     clusterName,
		Namespace:                s.namespace,
		ControlPlaneEndpointHost: vip,
		ControlPlaneEndpointPort: apiPort,
		Version:                  version,
	}
	err = kamajiControlPlaneTemplate.Execute(&buf, &kcpArgs)
	if err != nil {
		return "", fmt.Errorf("failed to execute kamaji control plane  template, %s", err)
	}

	// We need to:
	// 1. Set up cloud-init for the control plane.
	// - we need to set up a static kubernetes manifest for kube-vip,
	// with the VIP in the config.
	// - we need to configure the default user and ssh key in case we
	// need to ssh in to debug.
	bootComands := []string{
		"cloud-init-per once ssh-users-ca echo \"TrustedUserCAKeys /etc/ssh/trusted-user-ca-keys.pem\" >> /etc/ssh/sshd_config",
	}
	appendValTrue := true
	trustUserCAKeysFile := bootstrapv1.File{
		Path:    "/etc/ssh/trusted-user-ca-keys.pem",
		Content: caCert,
		Append:  &appendValTrue,
	}
	dhcpAllInterfaces := `network:
  version: 2
  ethernets:
    all-en:
      match:
        name: "en*"
      dhcp4: true
      dhcp6: true
      optional: true
`
	appendValFalse := false
	netplan99 := bootstrapv1.File{
		Path:        "/etc/netplan/99-all-en-dhcp.yaml",
		Content:     dhcpAllInterfaces,
		Permissions: "0600",
		Append:      &appendValFalse,
	}
	user := bootstrapv1.User{
		Name:  "ubuntu",
		Shell: "/bin/bash",
		Sudo:  "ALL=(ALL) NOPASSWD:ALL",
	}
	// configure console password if specified by operator
	consolePassword := s.accessVars[ConsolePassword]
	if consolePassword != "" {
		passwdHash, err := bcrypt.GenerateFromPassword([]byte(consolePassword), bcrypt.DefaultCost)
		if err != nil {
			return "", fmt.Errorf("failed to generate password hash, %s", err)
		}
		lockPassword := false
		user.Passwd = string(passwdHash)
		user.LockPassword = &lockPassword
	}
	featureGatesVals, _ := s.properties.GetValue(KubeletFeatureGates)
	featureGates := map[string]bool{}
	kubeletExtraArgs := []bootstrapv1.Arg{}
	if featureGatesVals != "" {
		parts := strings.SplitSeq(featureGatesVals, ",")
		for part := range parts {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) == 2 {
				if kv[1] == "true" {
					featureGates[kv[0]] = true
				} else {
					featureGates[kv[0]] = false
				}
			}
		}
	}
	// it appears that the patch that clusterapi applies to the
	// kubelet config adds default values for feature options that
	// are not enabled by default. This causes kubelet.service to
	// fail with an invalid kubelet config. To avoid this, enable
	// the feature gates. This behavior was seen for clusterapi
	// 1.12.2 using KubeadmBootstrap provider 1.12.2, and
	// kubeadm/kubelet 1.34.1.
	if _, ok := featureGates["KubeletCrashLoopBackOffMax"]; !ok {
		featureGates["KubeletCrashLoopBackOffMax"] = true
	}
	if _, ok := featureGates["KubeletEnsureSecretPulledImages"]; !ok {
		featureGates["KubeletEnsureSecretPulledImages"] = true
	}
	fgs := []string{}
	for fg, val := range featureGates {
		fgs = append(fgs, fmt.Sprintf("%s=%t", fg, val))
	}
	if len(fgs) > 0 {
		featureGatesVals = strings.Join(fgs, ",")
		kubeletExtraArgs = append(kubeletExtraArgs,
			bootstrapv1.Arg{
				Name:  "feature-gates",
				Value: &featureGatesVals,
			},
		)
	}
	for i := range objs {
		if _, ok := objs[i].(*controlplanev1.KubeadmControlPlane); ok {
			// replace with KamajiControlPlane
			objs[i] = nil
		} else if obj, ok := objs[i].(*clusterv1.Cluster); ok {
			// switch from Kubeadm to Kamaji control plane
			obj.Spec.ControlPlaneRef.Kind = "KamajiControlPlane"
			// enforce different kube API port
			obj.Spec.ClusterNetwork.APIServerPort = int32(apiPort)
		} else if obj, ok := objs[i].(*bootstrapv1.KubeadmConfigTemplate); ok {
			obj.Spec.Template.Spec.BootCommands = bootComands
			obj.Spec.Template.Spec.PreKubeadmCommands = []string{
				"netplan apply",
			}
			obj.Spec.Template.Spec.Files = []bootstrapv1.File{
				trustUserCAKeysFile,
				netplan99,
			}
			obj.Spec.Template.Spec.Users = []bootstrapv1.User{
				user,
			}
			if len(featureGates) > 0 {
				obj.Spec.Template.Spec.ClusterConfiguration.FeatureGates = featureGates
			}
			if len(kubeletExtraArgs) > 0 {
				obj.Spec.Template.Spec.JoinConfiguration.NodeRegistration.KubeletExtraArgs = append(obj.Spec.Template.Spec.JoinConfiguration.NodeRegistration.KubeletExtraArgs, kubeletExtraArgs...)
			}
		} else if obj, ok := objs[i].(*metal3provv1.Metal3MachineTemplate); ok {
			if strings.Contains(obj.GetName(), "controlplane") {
				// kamaji control plane doesn't need physical nodes
				objs[i] = nil
				continue
			}
			// set hostSelector to choose nodes based on flavor label
			obj.Spec.Template.Spec.HostSelector.MatchLabels = map[string]string{
				metal3.FlavorLabel: infraFlavor,
			}
			//obj.Spec.Template.Spec.NetworkData = &v1.SecretReference{
			//	Name: "node1-networkdata2",
			//}
		} else if obj, ok := objs[i].(metav1.Object); ok {
			gvk := gvks[i]
			if gvk.Kind == "Metal3DataTemplate" && strings.Contains(obj.GetName(), "controlplane") {
				// kamaji control plane doesn't need physical nodes
				objs[i] = nil
			}
		}
	}
	manifest, err = cloudcommon.EncodeK8SYaml(objs)
	if err != nil {
		return "", fmt.Errorf("failed to encode cluster manifests, %s", err)
	}
	// add kamaji control plane template
	manifest += "---\n" + buf.String()

	return manifest, nil
}

// There were too many problems trying to import the kamaji CRD
// golang definitions, primarily because their api dir was not
// separated into its own go package, so adding the deps was importing
// a lot of kubernetes operator packages. Instead, we'll use a
// string template.
type kamajiControlPlaneTemplateArgs struct {
	Name                     string
	Namespace                string
	ControlPlaneEndpointHost string
	ControlPlaneEndpointPort int
	LBClass                  string
	Version                  string
}

var kamajiControlPlaneTemplateString = `apiVersion: controlplane.cluster.x-k8s.io/v1alpha1
kind: KamajiControlPlane
metadata:
  name: {{ .Name }}
  namespace: {{ .Namespace }}
spec:
  controlPlaneEndpoint:
    host: {{ .ControlPlaneEndpointHost }}
    port: {{ .ControlPlaneEndpointPort }}
  dataStoreName: default
  addons:
    coreDNS: {}
    kubeProxy: {}
    konnectivity: {}
  admissionControllers: [CertificateApproval, CertificateSigning, CertificateSubjectRestriction, DefaultIngressClass, DefaultStorageClass, DefaultTolerationSeconds, LimitRanger, MutatingAdmissionWebhook, NamespaceLifecycle, PersistentVolumeClaimResize, PodSecurity, Priority, ResourceQuota, RuntimeClass, ServiceAccount, StorageObjectInUseProtection, TaintNodesByCondition, ValidatingAdmissionWebhook]
  kubelet:
    cgroupfs: systemd
    preferredAddressTypes:
      - ExternalIP
      - InternalIP
      - Hostname
  network:
    certSANs:
    - {{ .ControlPlaneEndpointHost }}
    serviceType: LoadBalancer
    serviceAddress: {{ .ControlPlaneEndpointHost }}
  version: {{ .Version }}
`

func (s *ClusterAPI) RunClusterCreateCommand(ctx context.Context, clusterName string, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) (map[string]string, error) {
	client := s.getClient()
	names, err := s.ensureCAPIKubeconfig(ctx, client)
	if err != nil {
		return nil, err
	}
	publicSSHKey, err := s.accessApi.GetSSHPublicKey(ctx)
	if err != nil {
		return nil, err
	}
	manifest, err := s.generateClusterManifest(ctx, names, clusterName, clusterInst, publicSSHKey)
	if err != nil {
		return nil, err
	}
	clusterFile := clusterName + ".yaml"
	err = pc.WriteFile(client, clusterFile, manifest, "cluster-api-manifest", pc.NoSudo)
	if err != nil {
		return nil, err
	}
	cmd := fmt.Sprintf("kubectl %s apply -f %s", names.KconfArg, clusterFile)
	log.SpanLog(ctx, log.DebugLevelInfra, "creating capi cluster", "cmd", cmd)
	out, err := client.Output(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to apply capi cluster manifest %q: %s, %s", cmd, out, err)
	}
	err = s.waitForCluster(ctx, client, names, clusterName, clusterInst, cloudcommon.Create, nil, updateCallback)
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func (s *ClusterAPI) RunClusterUpdateCommand(ctx context.Context, clusterName string, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) (map[string]string, error) {
	// Support worker pool scaling and kubernetes version upgrade
	client := s.getClient()
	names, err := s.ensureCAPIKubeconfig(ctx, client)
	if err != nil {
		return nil, err
	}
	status, err := s.checkClusterStatus(ctx, client, names, clusterName, clusterInst, NewClusterStatus(), cloudcommon.Update)
	if err != nil {
		return nil, err
	}
	// check for worker pool scaling
	var workerPool *edgeproto.NodePool
	for _, np := range clusterInst.NodePools {
		if np.ControlPlane {
			continue
		}
		workerPool = np
		break
	}
	if workerPool == nil {
		return nil, fmt.Errorf("cluster %s does not have a worker node pool", clusterName)
	}
	if int(workerPool.NumNodes) != status.WorkerNodesDesired {
		updateCallback(edgeproto.UpdateTask, fmt.Sprintf("Scaling worker pool from %d to %d", status.WorkerNodesDesired, workerPool.NumNodes))
		cmd := fmt.Sprintf("kubectl %s scale machinedeployment -n %s %s --replicas=%d", names.KconfArg, s.namespace, clusterName, workerPool.NumNodes)
		log.SpanLog(ctx, log.DebugLevelInfra, "scaling worker pool", "cmd", cmd)
		out, err := client.Output(cmd)
		if err != nil {
			return nil, fmt.Errorf("failed to scale worker pool, %s, %s, %v", cmd, out, err)
		}
		err = s.waitForCluster(ctx, client, names, clusterName, clusterInst, cloudcommon.Update, status, updateCallback)
		if err != nil {
			return nil, err
		}
	}
	// TODO: support version upgrade, see:
	// https://cluster-api.sigs.k8s.io/tasks/upgrading-clusters
	return nil, nil
}

func (s *ClusterAPI) RunClusterDeleteCommand(ctx context.Context, clusterName string, clusterInst *edgeproto.ClusterInst, updateCallback edgeproto.CacheUpdateCallback) error {
	client := s.getClient()
	names, err := s.ensureCAPIKubeconfig(ctx, client)
	if err != nil {
		return err
	}
	// for delete, start wait with status before delete so that we don't
	// print messages about state before delete.
	initialStatus, err := s.checkClusterStatus(ctx, client, names, clusterName, clusterInst, NewClusterStatus(), cloudcommon.Delete)
	if err != nil {
		// fallback to empty initial status
		log.SpanLog(ctx, log.DebugLevelInfra, "failed to get initial status for cluster delete, ignoring initial status", "cluster", clusterName, "err", err)
		initialStatus = NewClusterStatus()
		err = nil
	}
	cmd := fmt.Sprintf("kubectl %s delete cluster %s -n %s --wait=false", names.KconfArg, clusterName, s.namespace)
	log.SpanLog(ctx, log.DebugLevelInfra, "deleting capi cluster", "cmd", cmd)
	out, err := client.Output(cmd)
	if err != nil {
		if strings.Contains(out, "NotFound") {
			log.SpanLog(ctx, log.DebugLevelInfra, "cluster already deleted", "cluster", clusterName, "out", out, "err", err)
			return nil
		}
		return fmt.Errorf("failed to delete capi cluster %q: %s, %s", cmd, out, err)
	}

	err = s.waitForCluster(ctx, client, names, clusterName, clusterInst, cloudcommon.Delete, initialStatus, updateCallback)
	if err != nil {
		return err
	}
	return err
}

func (s *ClusterAPI) GetClusterAddonInfo(ctx context.Context, clusterName string, clusterInst *edgeproto.ClusterInst) (*k8smgmt.ClusterAddonInfo, error) {
	info := k8smgmt.ClusterAddonInfo{
		IngressNginxOps: []k8smgmt.IngressNginxOp{
			k8smgmt.WithIngressNginxEnsureLB(s, clusterInst.Key),
			k8smgmt.WithIngressNginxWaitForExternalIP(),
		},
	}

	return &info, nil
}

func (s *ClusterAPI) GetCluster(ctx context.Context, clusterInst *edgeproto.ClusterInst, names *k8smgmt.KconfNames) (*v1beta2.Cluster, error) {
	clusterName := k8smgmt.GetNormalizedClusterName(clusterInst)
	cmd := fmt.Sprintf("kubectl %s get cluster %s -n %s -o json", names.KconfArg, clusterName, s.namespace)
	out, err := s.getClient().Output(cmd)
	log.SpanLog(ctx, log.DebugLevelInfra, "CAPI get cluster", "cmd", cmd, "out", out, "err", err)
	if err != nil {
		return nil, fmt.Errorf("CAPI get cluster failed, %s, %s, %s", cmd, out, err)
	}
	cluster := v1beta2.Cluster{}
	err = json.Unmarshal([]byte(out), &cluster)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal cluster data, %s", err)
	}
	return &cluster, nil
}

func (s *ClusterAPI) GetCloudletInfraResourcesInfo(ctx context.Context) ([]edgeproto.InfraResource, error) {
	client := s.getClient()
	names, err := s.ensureCAPIKubeconfig(ctx, client)
	if err != nil {
		return nil, err
	}
	namespace, _ := s.properties.GetValue(ManagementNamespace)

	flavorData, err := metal3.UpdateBareMetalHostFlavors(ctx, client, names, namespace)
	ir := []edgeproto.InfraResource{}
	for _, flavor := range flavorData.Flavors {
		count := flavorData.Counts[flavor.Name]
		ir = append(ir, edgeproto.InfraResource{
			Name:          flavor.Name,
			InfraMaxValue: uint64(count),
			Type:          cloudcommon.ResourceTypeFlavor,
		})
	}
	return ir, nil
}

func (s *ClusterAPI) GetClusterAdditionalResources(ctx context.Context, cloudlet *edgeproto.Cloudlet, vmResources []edgeproto.VMResource) map[string]edgeproto.InfraResource {
	return nil
}

func (s *ClusterAPI) GetClusterAdditionalResourceMetric(ctx context.Context, cloudlet *edgeproto.Cloudlet, resMetric *edgeproto.Metric, resources []edgeproto.VMResource) error {
	return nil
}

func (s *ClusterAPI) GetAllClusters(ctx context.Context) ([]*edgeproto.CloudletManagedCluster, error) {
	return nil, errors.New("not supported")
}

func (s *ClusterAPI) RegisterCluster(ctx context.Context, clusterName string, in *edgeproto.ClusterInst) (map[string]string, error) {
	return nil, errors.New("not supported")
}

func (s *ClusterAPI) GetLoadBalancerAPI() platform.LoadBalancerApi {
	return s
}

func (s *ClusterAPI) EnsureLoadBalancer(ctx context.Context, cloudletKey edgeproto.CloudletKey, clusterKey edgeproto.ClusterKey, lbKey edgeproto.LoadBalancerKey) (*edgeproto.LoadBalancer, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "ensure load balancer", "cloudletKey", cloudletKey, "clusterKey", clusterKey, "lbKey", lbKey)
	lb, err := s.accessApi.ReserveLoadBalancerIP(ctx, cloudletKey, clusterKey, lbKey)
	if err != nil {
		return nil, err
	}
	clusterInst := &edgeproto.ClusterInst{}
	if !s.caches.ClusterInstCache.Get(&clusterKey, clusterInst) {
		return nil, clusterKey.NotFoundError()
	}
	clusterName := s.NameSanitize(k8smgmt.GetCloudletClusterName(clusterInst))
	client := s.getClient()
	names, err := s.ensureCAPIKubeconfig(ctx, client)
	if err != nil {
		return nil, err
	}
	clusterNames, err := s.ensureClusterKubeconfig(ctx, client, names, clusterInst, clusterName)
	if err != nil {
		return nil, err
	}
	// clusterapi uses metalLB to advertise load balancer IPs.
	// We do not create external LBs.
	err = k8smgmt.AnnotateLoadBalancerIP(ctx, s.getClient(), clusterNames, lb, k8smgmt.MetalLBLoadbalancerIPsAnnotation)
	if err != nil {
		return nil, err
	}
	return lb, nil
}

func (s *ClusterAPI) DeleteLoadBalancer(ctx context.Context, cloudletKey edgeproto.CloudletKey, clusterKey edgeproto.ClusterKey, lbKey edgeproto.LoadBalancerKey) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "delete load balancer", "cloudletKey", cloudletKey, "clusterKey", clusterKey, "lbKey", lbKey)
	return s.accessApi.FreeLoadBalancerIP(ctx, cloudletKey, clusterKey, lbKey)
}
