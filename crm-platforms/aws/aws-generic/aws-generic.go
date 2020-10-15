package awsgeneric

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/codeskyblue/go-sh"
	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/log"

	"github.com/mobiledgex/edge-cloud/edgeproto"
)

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

type AwsGenericPlatform struct {
	Properties *infracommon.InfraProperties
}

func (a *AwsGenericPlatform) TimedAwsCommand(ctx context.Context, name string, p ...string) ([]byte, error) {
	parmstr := strings.Join(p, " ")
	start := time.Now()

	log.SpanLog(ctx, log.DebugLevelInfra, "AWS Command Start", "name", name, "parms", parmstr)
	newSh := sh.NewSession()
	//envvar stuff here

	out, err := newSh.Command(name, p).CombinedOutput()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "AWS command returned error", "parms", parmstr, "out", string(out), "err", err, "elapsed time", time.Since(start))
		return out, err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "AWS Command Done", "parmstr", parmstr, "elapsed time", time.Since(start))
	return out, nil
}

func (a *AwsGenericPlatform) GetFlavorList(ctx context.Context) ([]*edgeproto.FlavorInfo, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetFlavorList")
	var info edgeproto.CloudletInfo
	err := a.GatherCloudletInfo(ctx, &info)
	if err != nil {
		return nil, err
	}
	return info.Flavors, nil
}

// GatherCloudletInfo gets flavor info from AWS
func (a *AwsGenericPlatform) GatherCloudletInfo(ctx context.Context, info *edgeproto.CloudletInfo) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "GatherCloudletInfo (AWS)")
	filter := "Name=instance-storage-supported,Values=true"
	query := "InstanceTypes[].[InstanceType,VCpuInfo.DefaultVCpus,MemoryInfo.SizeInMiB,InstanceStorageInfo.TotalSizeInGB]"

	out, err := a.TimedAwsCommand(ctx, "aws", "ec2", "describe-instance-types",
		"--filter", filter,
		"--query", query,
		"--region", a.GetAwsRegion(),
		"--output", "json")
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
