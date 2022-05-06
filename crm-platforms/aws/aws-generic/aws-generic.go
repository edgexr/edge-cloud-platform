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

package awsgeneric

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/codeskyblue/go-sh"
	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud/log"

	"github.com/edgexr/edge-cloud/edgeproto"
)

type AwsCredentialsType string

const (
	AwsCredentialsAccount = "account"
	AwsCredentialsSession = "session"

	AWSServiceCodeEKS = "eks"
	AWSServiceCodeELB = "elasticloadbalancing"

	// Codes used to identify service quota for AWS resources
	AWSServiceQuotaClusters             = "L-1194D53C"
	AWSServiceQuotaNodeGroupsPerCluster = "L-6D54EA21"
	AWSServiceQuotaNodesPerNodeGroup    = "L-BD136A63"
	AWSServiceQuotaNetworkLBPerRegion   = "L-69A177A2"
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

type AWSClusterMetadata struct {
	Name   string
	Region string
}

type AWSCluster struct {
	Metadata AWSClusterMetadata
}

type AWSClusterNodeGroup struct {
	StackName       string
	Cluster         string
	Name            string
	Status          string
	MaxSize         int
	MinSize         int
	DesiredCapacity int
	InstanceType    string
}

type AWSServiceQuota struct {
	Adjustable bool
	Name       string
	Value      float64
	Code       string
}

type ELBListener struct {
	Protocol         string
	LoadBalancerPort int
	InstanceProtocol string
	InstancePort     int
}

type AWSELBDescription struct {
	LoadBalancerName     string
	DNSName              string
	Scheme               string
	ListenerDescriptions []ELBListener
}

type AWSELB struct {
	LoadBalancerDescriptions []AWSELBDescription
}

type AwsGenericPlatform struct {
	Properties *infracommon.InfraProperties
	// AccountAccessVars are fixed for the account credentials used to access the APIs
	AccountAccessVars map[string]string
	// SessionAccessVars must be renewed periodically via MFA
	SessionAccessVars map[string]string
}

func (a *AwsGenericPlatform) TimedAwsCommand(ctx context.Context, credType AwsCredentialsType, name string, p ...string) ([]byte, error) {
	parmstr := strings.Join(p, " ")
	start := time.Now()

	log.SpanLog(ctx, log.DebugLevelInfra, "AWS Command Start", "credType", credType, "name", name, "parms", parmstr)
	newSh := sh.NewSession()
	if credType == AwsCredentialsAccount {
		for key, val := range a.AccountAccessVars {
			newSh.SetEnv(key, val)
		}
	} else {
		for key, val := range a.SessionAccessVars {
			newSh.SetEnv(key, val)
		}
	}

	out, err := newSh.Command(name, p).CombinedOutput()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "AWS command returned error", "parms", parmstr, "out", string(out), "err", err, "elapsed time", time.Since(start))
		return out, err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "AWS Command Done", "parmstr", parmstr, "elapsed time", time.Since(start))
	return out, nil
}

func (a *AwsGenericPlatform) GetFlavorList(ctx context.Context, flavorMatchPattern string) ([]*edgeproto.FlavorInfo, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetFlavorList", "match pattern", flavorMatchPattern)
	var info edgeproto.CloudletInfo
	err := a.GatherCloudletInfo(ctx, flavorMatchPattern, &info)
	if err != nil {
		return nil, err
	}
	return info.Flavors, nil
}

// GatherCloudletInfo gets flavor info from AWS
func (a *AwsGenericPlatform) GatherCloudletInfo(ctx context.Context, flavorMatchPattern string, info *edgeproto.CloudletInfo) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "GatherCloudletInfo (AWS)")
	filter := "Name=instance-storage-supported,Values=true"
	query := "InstanceTypes[].[InstanceType,VCpuInfo.DefaultVCpus,MemoryInfo.SizeInMiB,InstanceStorageInfo.TotalSizeInGB]"

	r, err := regexp.Compile(flavorMatchPattern)
	if err != nil {
		return fmt.Errorf("Cannot compile flavor match pattern")
	}

	out, err := a.TimedAwsCommand(ctx, AwsCredentialsSession, "aws", "ec2", "describe-instance-types",
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

		if r.MatchString(name) {
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
	}
	return nil
}

func (a *AwsGenericPlatform) GetServiceQuotas(ctx context.Context, svcCode string) ([]AWSServiceQuota, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetServiceQuotas (AWS)", "svc code", svcCode)
	query := "Quotas[*].{Adjustable:Adjustable,Name:QuotaName,Value:Value,Code:QuotaCode}"
	out, err := a.TimedAwsCommand(ctx, AwsCredentialsAccount, "aws", "service-quotas", "list-aws-default-service-quotas",
		"--query", query,
		"--region", a.GetAwsRegion(),
		"--service-code", svcCode,
		"--output", "json")
	if err != nil {
		err = fmt.Errorf("Failed to get service quotas for %s from AWS, %s, %s", svcCode, out, err.Error())
		return nil, err
	}
	jbytes := []byte(out)

	var svcQuotas []AWSServiceQuota
	err = json.Unmarshal(jbytes, &svcQuotas)
	if err != nil {
		err = fmt.Errorf("Failed to unmarshal service quotas, %s, %v", out, err)
		return nil, err
	}
	return svcQuotas, nil
}

func (a *AwsGenericPlatform) GetAWSELBs(ctx context.Context) (*AWSELB, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetAWSELBs")
	out, err := a.TimedAwsCommand(ctx, AwsCredentialsAccount, "aws", "elb", "describe-load-balancers",
		"--region", a.GetAwsRegion(),
		"--output", "json")
	if err != nil {
		err = fmt.Errorf("Failed to get elb from AWS, %s, %s", out, err.Error())
		return nil, err
	}
	jbytes := []byte(out)

	var awsELB AWSELB
	err = json.Unmarshal(jbytes, &awsELB)
	if err != nil {
		err = fmt.Errorf("Failed to unmarshal elb from AWS, %s, %v", out, err)
		return nil, err
	}
	return &awsELB, nil
}
