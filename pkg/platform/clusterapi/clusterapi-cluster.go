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

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	ssh "github.com/edgexr/golang-ssh"
	infrav1 "github.com/metal3-io/cluster-api-provider-metal3/api/v1beta1"
	"github.com/mobiledgex/yaml/v2"
	"golang.org/x/crypto/bcrypt"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/cluster-api/api/core/v1beta2"
	clusterv1 "sigs.k8s.io/cluster-api/api/core/v1beta2"

	bootstrapv1 "sigs.k8s.io/cluster-api/api/bootstrap/kubeadm/v1beta2"
	controlplanev1 "sigs.k8s.io/cluster-api/api/controlplane/kubeadm/v1beta2"
)

var kubeVIPTemplate *template.Template

const DebugUserPassword = "DebugUserPassword"

func init() {
	// register supporting CRD schemes to global scheme
	_ = apiextensionsv1.AddToScheme(scheme.Scheme)
	_ = clusterv1.AddToScheme(scheme.Scheme)
	_ = infrav1.AddToScheme(scheme.Scheme)
	_ = controlplanev1.AddToScheme(scheme.Scheme)
	_ = bootstrapv1.AddToScheme(scheme.Scheme)
	kubeVIPTemplate = template.Must(template.New("kube-vip").Parse(kubeVIPTemplateString))
}

func (s *ClusterAPI) GetCredentials(ctx context.Context, clusterName string, clusterInst *edgeproto.ClusterInst) ([]byte, error) {
	names, err := s.ensureCAPIKubeconfig(ctx, s.getClient())
	if err != nil {
		return nil, err
	}
	return s.getCredentials(ctx, s.getClient(), names, clusterName)
}

func (s *ClusterAPI) getCredentials(ctx context.Context, client ssh.Client, names *k8smgmt.KconfNames, clusterName string) ([]byte, error) {
	cmd := fmt.Sprintf("clusterctl %s -n %s get kubeconfig %s", names.KconfArg, s.namespace, clusterName)
	out, outerr, err := pc.RunOutput(client, cmd)
	if err != nil {
		return nil, fmt.Errorf("CAPI get credentials failed, %s, %s, %s, %s", cmd, out, outerr, err)
	}
	return []byte(out), nil
}

func (s *ClusterAPI) CreateClusterPrerequisites(ctx context.Context, clusterName string) error {
	return nil
}

func (s *ClusterAPI) generateClusterManifest(ctx context.Context, names *k8smgmt.KconfNames, clusterName string, clusterInst *edgeproto.ClusterInst, caCert string) (string, error) {
	version := clusterInst.KubernetesVersion
	if version == "" {
		return "", fmt.Errorf("cluster must specify the kubernetes version")
	}
	var controlNP *edgeproto.NodePool
	var workerNPs []*edgeproto.NodePool
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
	vip, ok := clusterInst.Annotations[cloudcommon.AnnotationFloatingVIP]
	if !ok {
		return "", fmt.Errorf("no floating VIP allocated for cluster %s", clusterName)
	}
	imageURL, _ := s.properties.GetValue(ImageURL)
	imageChecksum, _ := s.properties.GetValue(ImageChecksum)
	imageChecksumType, _ := s.properties.GetValue(ImageChecksumType)
	imageFormat, _ := s.properties.GetValue(ImageFormat)
	vipSubnet, _ := s.properties.GetValue(FloatingVIPsSubnet)

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
		"CLUSTER_APIENDPOINT_PORT":      "6443",
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
	err = pc.WriteFile(s.getClient(), configFile, string(configContents), "cluster-capi-config", pc.NoSudo)
	if err != nil {
		return "", err
	}

	cmd := fmt.Sprintf("clusterctl %s generate cluster %s --kubernetes-version %s --target-namespace %s --control-plane-machine-count=%d --worker-machine-count=%d --infrastructure %s --config %s", names.KconfArg, clusterName, version, s.namespace, controlNP.NumNodes, workerNPs[0].NumNodes, s.infra, configFile)
	log.SpanLog(ctx, log.DebugLevelInfra, "CAPI generate cluster manifests", "cmd", cmd)

	out, outerr, err := pc.RunOutput(s.getClient(), cmd)
	if err != nil {
		return "", fmt.Errorf("CAPI generate cluster manifests failed, %s, %s, %s, %s", cmd, out, outerr, err)
	}
	manifest := out

	objs, kinds, err := cloudcommon.DecodeK8SYaml(manifest)
	if err != nil {
		return "", fmt.Errorf("failed to decode cluster manifests, %s", err)
	}
	for i := range objs {
		if obj, ok := objs[i].(metav1.Object); ok {
			fmt.Printf("obj %s kind %s\n", obj.GetName(), kinds[i].Kind)
		}
	}

	buf := bytes.Buffer{}
	kubeVIPArgs := kubeVipTemplateArgs{
		KubeVIPIP:      vip,
		KubeVIPSubnet:  vipSubnet,
		EnableServices: true,
	}
	err = kubeVIPTemplate.Execute(&buf, &kubeVIPArgs)
	if err != nil {
		return "", fmt.Errorf("failed to execute kube-vip template, %s", err)
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
	append := true
	trustUserCAKeysFile := bootstrapv1.File{
		Path:    "/etc/ssh/trusted-user-ca-keys.pem",
		Content: caCert,
		Append:  &append,
	}
	kubeVIPTemplateFile := bootstrapv1.File{
		Content: buf.String(),
		Owner:   "root",
		Path:    "/root/kube-vip.template",
	}
	user := bootstrapv1.User{
		Name:  "ubuntu",
		Shell: "/bin/bash",
		Sudo:  "ALL=(ALL) NOPASSWD:ALL",
	}
	// Setting a user password is for debug only
	passwd, set := s.properties.GetValue(DebugUserPassword)
	if set && passwd != "" {
		passwdHash, err := bcrypt.GenerateFromPassword([]byte(passwd), bcrypt.DefaultCost)
		if err != nil {
			return "", fmt.Errorf("failed to generate password hash, %s", err)
		}
		lockPassword := false
		user.Passwd = string(passwdHash)
		user.LockPassword = &lockPassword
	}

	for i := range objs {
		if obj, ok := objs[i].(*controlplanev1.KubeadmControlPlane); ok {
			obj.Spec.KubeadmConfigSpec.BootCommands = bootComands
			obj.Spec.KubeadmConfigSpec.Files = []bootstrapv1.File{
				trustUserCAKeysFile,
				kubeVIPTemplateFile,
			}
			obj.Spec.KubeadmConfigSpec.PreKubeadmCommands = []string{
				"mkdir -p /etc/kubernetes/manifests",
				"export KUBEVIP_INTF=$(ip route | awk '/default/ {print $5}' | head -n 1)",
				"echo generating kube-vip using interface $KUBEVIP_INTF",
				"envsubst < /root/kube-vip.template > /etc/kubernetes/manifests/kube-vip.yaml",
			}
			obj.Spec.KubeadmConfigSpec.Users = []bootstrapv1.User{
				user,
			}
		} else if obj, ok := objs[i].(*bootstrapv1.KubeadmConfigTemplate); ok {
			obj.Spec.Template.Spec.BootCommands = bootComands
			obj.Spec.Template.Spec.Files = []bootstrapv1.File{
				trustUserCAKeysFile,
			}
			obj.Spec.Template.Spec.Users = []bootstrapv1.User{
				user,
			}
		}
	}
	manifest, err = cloudcommon.EncodeK8SYaml(objs)
	if err != nil {
		return "", fmt.Errorf("failed to encode cluster manifests, %s", err)
	}
	return manifest, nil
}

type kubeVipTemplateArgs struct {
	KubeVIPIP      string
	KubeVIPSubnet  string
	EnableServices bool // use VIP for load balancers
}

var kubeVIPTemplateString = `apiVersion: v1
kind: Pod
metadata:
  name: kube-vip
  namespace: kube-system
spec:
  containers:
  - args:
    - manager
    env:
    - name: vip_arp
      value: "true"
    - name: port
      value: "6443"
    - name: vip_interface
      value: $KUBEVIP_INTF
    - name: vip_subnet
      value: "{{ .KubeVIPSubnet }}"
    - name: cp_enable
      value: "true"
    - name: cp_namespace
      value: kube-system
{{- if .EnableServices }}
    - name: svc_enable
      value: "true"
{{- end }}
    - name: vip_leaderelection
      value: "true"
    - name: address
      value: {{ .KubeVIPIP }}
    image: ghcr.io/kube-vip/kube-vip:v1.0.1
    imagePullPolicy: Always
    name: kube-vip
    securityContext:
      capabilities:
        add:
        - NET_ADMIN
        - NET_RAW
        drop:
        - ALL
    volumeMounts:
    - mountPath: /etc/kubernetes/admin.conf
      name: kubeconfig
  hostAliases:
  - hostnames:
    - kubernetes
    ip: 127.0.0.1
  hostNetwork: true
  volumes:
  - hostPath:
      path: /etc/kubernetes/super-admin.conf
    name: kubeconfig
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
	err = s.waitForCluster(ctx, client, names, clusterName, clusterInst, cloudcommon.Create, updateCallback)
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
	status, err := s.checkClusterStatus(ctx, client, names, clusterName, clusterInst, ClusterStatus{}, cloudcommon.Update)
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
		err = s.waitForCluster(ctx, client, names, clusterName, clusterInst, cloudcommon.Update, updateCallback)
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
	cmd := fmt.Sprintf("kubectl %s delete cluster %s -n %s --wait=false", names.KconfArg, clusterName, s.namespace)
	log.SpanLog(ctx, log.DebugLevelInfra, "deleting capi cluster", "cmd", cmd)
	out, err := client.Output(cmd)
	if err != nil {
		return fmt.Errorf("failed to delete capi cluster %q: %s, %s", cmd, out, err)
	}
	err = s.waitForCluster(ctx, client, names, clusterName, clusterInst, cloudcommon.Delete, updateCallback)
	if err != nil {
		return err
	}
	return err
}

func (s *ClusterAPI) GetClusterAddonInfo(ctx context.Context, clusterName string, clusterInst *edgeproto.ClusterInst) (*k8smgmt.ClusterAddonInfo, error) {
	info := k8smgmt.ClusterAddonInfo{}
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
	return []edgeproto.InfraResource{}, nil
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
