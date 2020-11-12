package managedk8s

import (
	"context"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vault"
	ssh "github.com/mobiledgex/golang-ssh"
)

// ManagedK8sProvider is an interface that platforms implement to perform the details of interfacing with managed kubernetes services
type ManagedK8sProvider interface {
	GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error
	GetProviderSpecificProps(ctx context.Context) (map[string]*edgeproto.PropertyInfo, error)
	SetProperties(props *infracommon.InfraProperties)
	Login(ctx context.Context) error
	GetCredentials(ctx context.Context, clusterName string) error
	NameSanitize(name string) string
	CreateClusterPrerequisites(ctx context.Context, clusterName string) error
	RunClusterCreateCommand(ctx context.Context, clusterName string, numNodes uint32, flavor string) error
	RunClusterDeleteCommand(ctx context.Context, clusterName string) error
	InitApiAccessProperties(ctx context.Context, accessApi platform.AccessApi, vars map[string]string) error
	GetAccessData(ctx context.Context, cloudlet *edgeproto.Cloudlet, region string, vaultConfig *vault.Config, dataType string, arg []byte) (map[string]string, error)
}

const (
	ManagedK8sProviderAzure string = "azure"
	ManagedK8sProviderGCP   string = "gcp"
	ManagedK8sProviderAWS   string = "aws"
)

// ManagedK8sPlatform contains info needed by all Managed Kubernetes Providers
type ManagedK8sPlatform struct {
	Type     string
	CommonPf infracommon.CommonPlatform
	Provider ManagedK8sProvider
}

func (m *ManagedK8sPlatform) GetType() string {
	return m.Type
}

func (m *ManagedK8sPlatform) Init(ctx context.Context, platformConfig *platform.PlatformConfig, caches *platform.Caches, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "Init", "type", m.GetType())
	props, err := m.Provider.GetProviderSpecificProps(ctx)
	if err != nil {
		return err
	}

	log.SpanLog(ctx, log.DebugLevelInfra, "Init API access properties")
	err = m.Provider.InitApiAccessProperties(ctx, platformConfig.AccessApi, platformConfig.EnvVars)
	if err != nil {
		return err
	}

	if err := m.CommonPf.InitInfraCommon(ctx, platformConfig, props); err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "InitInfraCommon failed", "err", err)
		return err
	}
	m.Provider.SetProperties(&m.CommonPf.Properties)
	return m.Provider.Login(ctx)
}

func (m *ManagedK8sPlatform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	return m.Provider.GatherCloudletInfo(ctx, info)
}

func (m *ManagedK8sPlatform) GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string) (ssh.Client, error) {
	return &pc.LocalClient{}, nil
}

func (m *ManagedK8sPlatform) GetNodePlatformClient(ctx context.Context, node *edgeproto.CloudletMgmtNode, ops ...pc.SSHClientOp) (ssh.Client, error) {
	return &pc.LocalClient{}, nil
}

func (m *ManagedK8sPlatform) ListCloudletMgmtNodes(ctx context.Context, clusterInsts []edgeproto.ClusterInst) ([]edgeproto.CloudletMgmtNode, error) {
	return []edgeproto.CloudletMgmtNode{}, nil
}

func (m *ManagedK8sPlatform) GetCloudletProps(ctx context.Context) (*edgeproto.CloudletProps, error) {
	props := edgeproto.CloudletProps{}
	props.Properties = make(map[string]*edgeproto.PropertyInfo)
	providerProps, err := m.Provider.GetProviderSpecificProps(ctx)
	if err != nil {
		return nil, err
	}
	for k, v := range providerProps {
		props.Properties[k] = v
	}
	return &props, nil
}

func (m *ManagedK8sPlatform) GetAccessData(ctx context.Context, cloudlet *edgeproto.Cloudlet, region string, vaultConfig *vault.Config, dataType string, arg []byte) (map[string]string, error) {
	log.SpanLog(ctx, log.DebugLevelApi, "ManagedK8sPlatform GetAccessData", "dataType", dataType)
	return m.Provider.GetAccessData(ctx, cloudlet, region, vaultConfig, dataType, arg)
}
