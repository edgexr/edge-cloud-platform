package k8sop

import (
	"context"
	"fmt"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/k8smgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/infracommon"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/managedk8s"
	k8scommon "github.com/edgexr/edge-cloud-platform/pkg/platform/k8s-common"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
	ssh "github.com/edgexr/golang-ssh"
)

// k8s operator runs the crm as a pod inside the cluster it managers
// with rbac perms to be able to run kubectl in the pod. So no
// kubeconfig is needed.
const NoKubeconfig = ""
const WorkingDir = "/root/config"

type K8sOperator struct {
	managedk8s.ManagedK8sPlatform
	properties *infracommon.InfraProperties
	caches     *platform.Caches
}

func (s *K8sOperator) GetFeatures() *platform.Features {
	return &platform.Features{
		SupportsMultiTenantCluster:    true,
		SupportsKubernetesOnly:        true,
		KubernetesRequiresWorkerNodes: true,
		IPAllocatedPerService:         true,
		IsSingleKubernetesCluster:     true,
		IsPrebuiltKubernetesCluster:   true,
	}
}

func platformName() string {
	return platform.GetType(edgeproto.PlatformType_PLATFORM_TYPE_K8S_OPERATOR.String())
}

func (s *K8sOperator) getClient() ssh.Client {
	// k8s operator runs all kubectl commands locally in the pod
	return &pc.LocalClient{
		WorkingDir: WorkingDir,
	}
}

func (s *K8sOperator) GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string) (ssh.Client, error) {
	return s.getClient(), nil
}

func (s *K8sOperator) GetNodePlatformClient(ctx context.Context, node *edgeproto.CloudletMgmtNode, ops ...pc.SSHClientOp) (ssh.Client, error) {
	return s.getClient(), nil
}

func (s *K8sOperator) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "GatherCloudletInfo")
	var err error
	info.Flavors, err = k8scommon.GetFlavorList(ctx, s.caches)
	if err != nil {
		return err
	}
	info.NodeInfos, err = k8smgmt.GetNodeInfos(ctx, s.getClient(), NoKubeconfig)
	return err
}

func (s *K8sOperator) GetProviderSpecificProps(ctx context.Context) (map[string]*edgeproto.PropertyInfo, error) {
	return make(map[string]*edgeproto.PropertyInfo), nil
}

func (s *K8sOperator) SetProperties(props *infracommon.InfraProperties, caches *platform.Caches) error {
	s.properties = props
	s.caches = caches
	return nil
}

func (s *K8sOperator) Login(ctx context.Context) error {
	return nil
}

func (s *K8sOperator) GetCredentials(ctx context.Context, clusterName string) error {
	return nil
}

func (s *K8sOperator) NameSanitize(name string) string {
	return name
}

func (s *K8sOperator) CreateClusterPrerequisites(ctx context.Context, clusterName string) error {
	return nil
}

func (s *K8sOperator) RunClusterCreateCommand(ctx context.Context, clusterName string, numNodes uint32, flavor string) error {
	return fmt.Errorf("Cluster create not supported")
}

func (s *K8sOperator) RunClusterDeleteCommand(ctx context.Context, clusterName string) error {
	return fmt.Errorf("Cluster delete not supported")
}

func (s *K8sOperator) InitApiAccessProperties(ctx context.Context, accessApi platform.AccessApi, vars map[string]string) error {
	return nil
}

func (k *K8sOperator) GetAccessData(ctx context.Context, cloudlet *edgeproto.Cloudlet, region string, vaultConfig *vault.Config, dataType string, arg []byte) (map[string]string, error) {
	return make(map[string]string), nil
}

// TODO
func (k *K8sOperator) GetCloudletInfraResourcesInfo(ctx context.Context) ([]edgeproto.InfraResource, error) {
	var resources []edgeproto.InfraResource
	return resources, nil
}

func (s *K8sOperator) GetCloudletResourceQuotaProps(ctx context.Context) (*edgeproto.CloudletResourceQuotaProps, error) {
	return &edgeproto.CloudletResourceQuotaProps{
		Properties: []edgeproto.InfraResource{},
	}, nil
}

// TODO
func (k *K8sOperator) GetClusterAdditionalResources(ctx context.Context, cloudlet *edgeproto.Cloudlet, vmResources []edgeproto.VMResource, infraResMap map[string]edgeproto.InfraResource) map[string]edgeproto.InfraResource {
	resInfo := make(map[string]edgeproto.InfraResource)
	return resInfo
}

// TODO
func (k *K8sOperator) GetClusterAdditionalResourceMetric(ctx context.Context, cloudlet *edgeproto.Cloudlet, resMetric *edgeproto.Metric, resources []edgeproto.VMResource) error {
	return nil
}
