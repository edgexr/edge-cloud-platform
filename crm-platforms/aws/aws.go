package aws

import (
	"context"
	"encoding/json"
	"fmt"

	sh "github.com/codeskyblue/go-sh"
	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vault"
	ssh "github.com/mobiledgex/golang-ssh"
)

type AWSPlatform struct {
	commonPf infracommon.CommonPlatform
}

type AWSQuotas struct {
	Limit  float64
	Metric string
}

type AWSInstanceType []interface{}

type AWSQuotasList struct {
	Quotas AWSQuotas
}

type AWSFlavor struct {
	Name     string
	Vcpus    uint
	MemoryMb uint
	DiskGb   uint
}

func (a *AWSPlatform) GetType() string {
	return "AWS"
}

//Init initializes the AWS Platform Config
func (a *AWSPlatform) Init(ctx context.Context, platformConfig *platform.PlatformConfig, caches *platform.Caches, updateCallback edgeproto.CacheUpdateCallback) error {
	var path string = "/secret/data/cloudlet/aws/credentials"
	vaultConfig, err := vault.BestConfig(platformConfig.VaultAddr)
	if err != nil {
		err = fmt.Errorf("cannot get best config from vault %s", err.Error())
		return err
	}

	err = infracommon.InternVaultEnv(ctx, vaultConfig, path)
	if err != nil {
		// Put Error Message
		err = fmt.Errorf("cannot intern vault data from vault %s", err.Error())
		return err
	}

	if err := a.commonPf.InitInfraCommon(ctx, platformConfig, AWSProps, vaultConfig); err != nil {
		err = fmt.Errorf("cannot get instance types from AWS %s", err.Error())
		return err
	}

	return nil
}

//GatherCloudletInfo does following query to populate flavor info:
// aws ec2 describe-instance-types --filters 'Name=instance-storage-supported,Values=true' \
// --query 'InstanceTypes[].[InstanceType,VCpuInfo.DefaultVCpus,MemoryInfo.SizeInMiB,InstanceStorageInfo.TotalSizeInGB]'
func (a *AWSPlatform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetLimits (AWS)")
	err := a.AWSLogin(ctx)
	if err != nil {
		return err
	}

	filter := "Name=instance-storage-supported,Values=true"
	query := "InstanceTypes[].[InstanceType,VCpuInfo.DefaultVCpus,MemoryInfo.SizeInMiB,InstanceStorageInfo.TotalSizeInGB]"

	out, err := sh.Command("aws", "ec2", "describe-instance-types",
		"--filter", filter,
		"--query", query,
		"--output", "json", sh.Dir("/tmp")).CombinedOutput()
	if err != nil {
		err = fmt.Errorf("cannot get instance types from AWS, %s, %s", out, err.Error())
		return err
	}
	jbytes := []byte(out)

	var instanceTypes []AWSInstanceType
	err = json.Unmarshal(jbytes, &instanceTypes)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal, %s, %v", out, err)
		return err
	}

	log.DebugLog(log.DebugLevelInfra, "AWS ", "instance types", instanceTypes)

	for _, m := range instanceTypes {
		name, ok := m[0].(string)
		if !ok {
			err := fmt.Errorf("wrong type for flavor name %T", m[0])
			return err
		}
		vcpus, ok := m[1].(float64)
		if !ok {
			err := fmt.Errorf("wrong type for vcpus %T", m[1])
			return err
		}
		ram, ok := m[2].(float64)
		if !ok {
			err := fmt.Errorf("wrong type for ram %T", m[2])
			return err
		}

		disk, ok := m[3].(float64)
		if !ok {
			err := fmt.Errorf("wrong type for disk %T", m[3])
			return err
		}

		info.Flavors = append(
			info.Flavors,
			&edgeproto.FlavorInfo{
				Name:  name,
				Vcpus: uint64(vcpus),
				Ram:   uint64(ram),
				Disk:  uint64(disk),
			},
		)
	}
	return nil
}

func (a *AWSPlatform) GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string) (ssh.Client, error) {
	return &pc.LocalClient{}, nil
}

func (a *AWSPlatform) GetNodePlatformClient(ctx context.Context, node *edgeproto.CloudletMgmtNode) (ssh.Client, error) {
	return &pc.LocalClient{}, nil
}

func (a *AWSPlatform) ListCloudletMgmtNodes(ctx context.Context, clusterInsts []edgeproto.ClusterInst) ([]edgeproto.CloudletMgmtNode, error) {
	return []edgeproto.CloudletMgmtNode{}, nil
}
