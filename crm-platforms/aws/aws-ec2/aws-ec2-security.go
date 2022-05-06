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

package awsec2

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	awsgen "github.com/edgexr/edge-cloud-infra/crm-platforms/aws/aws-generic"
	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud-infra/vmlayer"
	dme "github.com/edgexr/edge-cloud/d-match-engine/dme-proto"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

type SecurityGroupAction string

const SecurityGroupRuleCreate SecurityGroupAction = "create"
const SecurityGroupRuleRevoke SecurityGroupAction = "revoke"

func (a *AwsEc2Platform) CreateSecurityGroupRule(ctx context.Context, groupId, protocol, portRange, allowedCIDR string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateSecurityGroupRule", "groupId", groupId, "portRange", portRange, "allowedCIDR", allowedCIDR)

	out, err := a.awsGenPf.TimedAwsCommand(ctx, awsgen.AwsCredentialsSession, "aws",
		"ec2",
		"authorize-security-group-ingress",
		"--group-id", groupId,
		"--cidr", allowedCIDR,
		"--protocol", protocol,
		"--port", portRange,
		"--region", a.awsGenPf.GetAwsRegion())
	if err != nil {
		if strings.Contains(string(out), RuleAlreadyExistsError) {
			log.SpanLog(ctx, log.DebugLevelInfra, "security rule already exists")
		} else {
			return fmt.Errorf("authorize-security-group-ingress failed: %s - %v", string(out), err)
		}
	}
	return nil
}

func (a *AwsEc2Platform) RevokeSecurityGroupRule(ctx context.Context, groupId, protocol, portRange, allowedCIDR string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "RevokeSecurityGroupRule", "groupId", groupId, "portRange", portRange, "allowedCIDR", allowedCIDR)

	out, err := a.awsGenPf.TimedAwsCommand(ctx, awsgen.AwsCredentialsSession, "aws",
		"ec2",
		"revoke-security-group-ingress",
		"--group-id", groupId,
		"--cidr", allowedCIDR,
		"--protocol", protocol,
		"--port", portRange,
		"--region", a.awsGenPf.GetAwsRegion())
	if err != nil {
		if strings.Contains(string(out), RuleDoesNotExistError) {
			log.SpanLog(ctx, log.DebugLevelInfra, "security rule does not exist")
		} else {
			return fmt.Errorf("revoke-security-group-ingress failed: %s - %v", string(out), err)
		}
	}
	return nil
}

// addOrDeleteSecurityRule is a utility function to share code within adding and removing a rule
func (a *AwsEc2Platform) addOrDeleteSecurityRule(ctx context.Context, grpName, allowedCidr string, ports []dme.AppPort, action SecurityGroupAction) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "addOrDeleteSecurityRule", "grpName", grpName, "allowedCidr", allowedCidr, "ports", ports, "action", action)
	vpc, err := a.GetVPC(ctx, a.GetVpcName())
	if err != nil {
		return err
	}

	secGrpMap, err := a.GetSecurityGroups(ctx, vpc.VpcId)
	if err != nil {
		return err
	}
	sg, ok := secGrpMap[grpName]
	if !ok {
		return fmt.Errorf("Security group %s not found", grpName)
	}

	for _, p := range ports {
		log.SpanLog(ctx, log.DebugLevelInfra, "WhiteListing port", "port", p)
		portRange := fmt.Sprintf("%d", p.PublicPort)
		if p.EndPort != 0 {
			portRange = fmt.Sprintf("%d-%d", p.PublicPort, p.EndPort)
		}
		proto, err := edgeproto.L4ProtoStr(p.Proto)
		if err != nil {
			return err
		}
		if action == SecurityGroupRuleCreate {
			err = a.CreateSecurityGroupRule(ctx, sg.GroupId, proto, portRange, allowedCidr)
		} else {
			err = a.RevokeSecurityGroupRule(ctx, sg.GroupId, proto, portRange, allowedCidr)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// GetSecurityGroup returns a single group with the name
func (a *AwsEc2Platform) GetSecurityGroup(ctx context.Context, name string, vpcId string) (*AwsEc2SecGrp, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetSecurityGroup", "name", name, "vpcId", vpcId)

	grpMap, err := a.GetSecurityGroups(ctx, vpcId)
	if err != nil {
		return nil, err
	}
	grp, ok := grpMap[name]
	if !ok {
		return nil, fmt.Errorf(SecGrpDoesNotExistError)
	}
	return grp, nil
}

// GetSecurityGroups returns a map of name to group for all groups in the VPC
func (a *AwsEc2Platform) GetSecurityGroups(ctx context.Context, vpcId string) (map[string]*AwsEc2SecGrp, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetSecurityGroups", "vpcId", vpcId)
	out, err := a.awsGenPf.TimedAwsCommand(ctx, awsgen.AwsCredentialsSession, "aws",
		"ec2",
		"describe-security-groups",
		"--region", a.awsGenPf.GetAwsRegion())
	if err != nil {
		return nil, fmt.Errorf("error in describe-security-groups: %s - %v", string(out), err)
	}
	var sgList AwsEc2SecGrpList
	err = json.Unmarshal(out, &sgList)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "aws describe-security-groups unmarshal fail", "vpcId", vpcId, "out", string(out), "err", err)
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return nil, err
	}
	var sgMap = make(map[string]*AwsEc2SecGrp)
	for i, sg := range sgList.SecurityGroups {
		if sg.VpcId == vpcId {
			sgMap[sg.GroupName] = &sgList.SecurityGroups[i]
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "found security groups", "sgMap", sgMap)
	return sgMap, nil
}

func (a *AwsEc2Platform) CreateSecurityGroup(ctx context.Context, secGrpname, vpcId, vmGroupName string) (*AwsEc2SecGrp, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateSecurityGroup", "secGrpname", secGrpname, "vmGroupName", vmGroupName, "vpcId", vpcId)
	tagspec := fmt.Sprintf("ResourceType=security-group,Tags=[{Key=%s,Value=%s},{Key=%s,Value=%s}]", NameTag, secGrpname, VMGroupNameTag, vmGroupName)

	out, err := a.awsGenPf.TimedAwsCommand(ctx, awsgen.AwsCredentialsSession, "aws",
		"ec2",
		"create-security-group",
		"--region", a.awsGenPf.GetAwsRegion(),
		"--group-name", secGrpname,
		"--vpc-id", vpcId,
		"--description", vmGroupName,
		"--tag-specifications", tagspec)

	if err != nil {
		return nil, fmt.Errorf("Error in create-security-group: %s - %v", string(out), err)
	}
	var sg AwsEc2SecGrp
	err = json.Unmarshal(out, &sg)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "aws create-security-group unmarshal fail", "vpcId", vpcId, "out", string(out), "err", err)
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return nil, err
	}
	sg.GroupName = secGrpname
	sg.VpcId = vpcId
	return &sg, nil
}

func (a *AwsEc2Platform) DeleteSecurityGroup(ctx context.Context, groupId, vpcId string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteSecurityGroup", "groupId", groupId, "vpcId", vpcId)
	out, err := a.awsGenPf.TimedAwsCommand(ctx, awsgen.AwsCredentialsSession, "aws",
		"ec2",
		"delete-security-group",
		"--region", a.awsGenPf.GetAwsRegion(),
		"--group-id", groupId)
	if err != nil && !strings.Contains(err.Error(), SecGrpDoesNotExistError) {
		return fmt.Errorf("Error in delete-security-group: %s - %v", string(out), err)
	}
	return nil
}

func (a *AwsEc2Platform) WhitelistSecurityRules(ctx context.Context, client ssh.Client, wlParams *infracommon.WhiteListParams) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "WhitelistSecurityRules", "wlParams", wlParams)
	return a.addOrDeleteSecurityRule(ctx, wlParams.SecGrpName, wlParams.AllowedCIDR, wlParams.Ports, SecurityGroupRuleCreate)
}

func (a *AwsEc2Platform) RemoveWhitelistSecurityRules(ctx context.Context, client ssh.Client, wlParams *infracommon.WhiteListParams) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "RemoveWhitelistSecurityRules", "client", client)
	return a.addOrDeleteSecurityRule(ctx, wlParams.SecGrpName, wlParams.AllowedCIDR, wlParams.Ports, SecurityGroupRuleRevoke)
}

// AllowIntraVpcTraffic creates a rule to allow traffic within the VPC
func (a *AwsEc2Platform) AllowIntraVpcTraffic(ctx context.Context, groupId string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "AllowIntraVpcTraffic", "groupId", groupId)
	err := a.CreateSecurityGroupRule(ctx, groupId, "tcp", "0-65535", a.VpcCidr)
	if err != nil {
		return err
	}
	err = a.CreateSecurityGroupRule(ctx, groupId, "udp", "0-65535", a.VpcCidr)
	if err != nil {
		return err
	}
	return nil
}

// GetIamAccountForImage gets the account Id, which is either the logged in account
// or the account specified as the GetAmiIamOwner
func (a *AwsEc2Platform) GetIamAccountForImage(ctx context.Context) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetIamAccountForImage")

	acct := a.awsGenPf.GetAwsAmiIamOwner()
	if acct != "" {
		log.SpanLog(ctx, log.DebugLevelInfra, "using account specified AWS_AMI_IAM_OWNER", "acct", acct)
		return acct, nil
	} else {
		if a.awsGenPf.IsAwsOutpost() {
			return "", fmt.Errorf("AWS_AMI_IAM_OWNER must be set for outpost")
		}
	}
	out, err := a.awsGenPf.TimedAwsCommand(ctx, awsgen.AwsCredentialsSession, "aws",
		"iam",
		"get-user")

	log.SpanLog(ctx, log.DebugLevelInfra, "get-user result", "out", string(out), "err", err)
	if err != nil {
		return "", fmt.Errorf("GetIamAccountForImage failed: %s - %v", string(out), err)
	}
	var iamResult AwsIamUserResult
	err = json.Unmarshal(out, &iamResult)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "aws get-user unmarshal fail", "out", string(out), "err", err)
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return "", err
	}
	return a.awsGenPf.GetUserAccountIdFromArn(ctx, iamResult.User.Arn)
}

func (a *AwsEc2Platform) ConfigureCloudletSecurityRules(ctx context.Context, egressRestricted bool, TrustPolicy *edgeproto.TrustPolicy, rootLbClients map[string]ssh.Client, action vmlayer.ActionType, updateCallback edgeproto.CacheUpdateCallback) error {
	return nil
}

func (a *AwsEc2Platform) ConfigureTrustPolicyExceptionSecurityRules(ctx context.Context, TrustPolicyException *edgeproto.TrustPolicyException, rootLbClients map[string]ssh.Client, action vmlayer.ActionType, updateCallback edgeproto.CacheUpdateCallback) error {
	return fmt.Errorf("Platform not supported for TrustPolicyException SecurityRules")
}
