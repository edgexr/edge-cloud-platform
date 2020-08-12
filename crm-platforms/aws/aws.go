package aws

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	sh "github.com/codeskyblue/go-sh"
	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

type AWSPlatform struct {
	commonPf *infracommon.CommonPlatform
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

// GatherCloudletInfo gets flavor info from AWS
func (a *AWSPlatform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "GatherCloudletInfo (AWS)")
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

func (a *AWSPlatform) Login(ctx context.Context) error {
	return nil
}

func (a *AWSPlatform) NameSanitize(clusterName string) string {
	return strings.NewReplacer(".", "").Replace(clusterName)
}

func (a *AWSPlatform) SetCommonPlatform(cpf *infracommon.CommonPlatform) {
	a.commonPf = cpf
}
