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
	"time"

	awsgen "github.com/edgexr/edge-cloud-infra/crm-platforms/aws/aws-generic"
	"github.com/edgexr/edge-cloud-infra/vmlayer"
	"github.com/edgexr/edge-cloud/log"
)

const FreeInternalSubnetType string = "free-internal"
const FreeExternalSubnetType string = "free-external"

func (a *AwsEc2Platform) GetVpcName() string {
	outpostVpc := a.awsGenPf.GetAwsOutpostVPC()
	if outpostVpc != "" {
		return outpostVpc
	}
	return a.NameSanitize(a.VMProperties.CommonPf.PlatformConfig.CloudletKey.Name)
}

func (a *AwsEc2Platform) GetVPC(ctx context.Context, name string) (*AwsEc2Vpc, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetVPCs", "name", name)
	filter := fmt.Sprintf("Name=tag-value,Values=%s", name)
	out, err := a.awsGenPf.TimedAwsCommand(ctx, awsgen.AwsCredentialsSession, "aws",
		"ec2",
		"describe-vpcs",
		"--filters", "Name=tag-key,Values=Name", filter,
		"--region", a.awsGenPf.GetAwsRegion())

	if err != nil {
		return nil, fmt.Errorf("GetVPC failed: %s - %v", string(out), err)
	}
	var vpclist AwsEc2VpcList
	err = json.Unmarshal(out, &vpclist)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "aws describe-vpcs unmarshal fail", "name", name, "out", string(out), "err", err)
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return nil, err
	}
	if len(vpclist.Vpcs) == 0 {
		return nil, fmt.Errorf(VpcDoesNotExistError + ":" + name)
	}
	// there is nothing to prevent creating 2 VPCs with the same name tag, but it indicates
	// an error for us.
	if len(vpclist.Vpcs) > 2 {
		return nil, fmt.Errorf("more than one VPC matching name tag: %s - numvpcs: %d", name, len(vpclist.Vpcs))
	}
	return &vpclist.Vpcs[0], nil
}

// CreateVPC returns the vpcid after create
func (a *AwsEc2Platform) CreateVPC(ctx context.Context, name string, cidr string) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateVPC", "name", name, "cidr", cidr)
	vpc, err := a.GetVPC(ctx, name)
	if err == nil {
		// VPC already exists
		return vpc.VpcId, nil
	}
	if !strings.Contains(err.Error(), VpcDoesNotExistError) {
		// unexpected error
		return "", err
	}
	tagspec := fmt.Sprintf("ResourceType=vpc,Tags=[{Key=%s,Value=%s}]", NameTag, name)
	out, err := a.awsGenPf.TimedAwsCommand(ctx, awsgen.AwsCredentialsSession, "aws",
		"ec2",
		"create-vpc",
		"--cidr-block", cidr,
		"--region", a.awsGenPf.GetAwsRegion(),
		"--tag-specifications", tagspec)
	if err != nil {
		return "", fmt.Errorf("CreateVPC failed: %s - %v", string(out), err)
	}
	// the create-vpc command returns a json of the vpc
	var createdVpc AwsEc2VpcCreateResult
	err = json.Unmarshal(out, &createdVpc)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "aws create-vpc unmarshal fail", "name", name, "out", string(out), "err", err)
		return "", fmt.Errorf("cannot unmarshal, %v", err)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "created vpc", "vpc", createdVpc)
	if createdVpc.Vpc.VpcId == "" {
		return "", fmt.Errorf("no VPCID in VPC %s", name)
	}
	return createdVpc.Vpc.VpcId, err
}

func (a *AwsEc2Platform) GetInternetGateway(ctx context.Context, name string) (*AwsEc2Gateway, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetInternetGateway", "name", name)
	filter := fmt.Sprintf("Name=tag-value,Values=%s", name)
	out, err := a.awsGenPf.TimedAwsCommand(ctx, awsgen.AwsCredentialsSession, "aws",
		"ec2",
		"describe-internet-gateways",
		"--filters", "Name=tag-key,Values=Name", filter,
		"--region", a.awsGenPf.GetAwsRegion())
	log.SpanLog(ctx, log.DebugLevelInfra, "describe-internet-gateways result", "out", string(out), "err", err)
	if err != nil {
		return nil, fmt.Errorf("GetInternetGateway failed: %s - %v", string(out), err)
	}
	var gwList AwsEc2GatewayList
	err = json.Unmarshal(out, &gwList)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "aws describe-internet-gateways unmarshal fail", "name", name, "out", string(out), "err", err)
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return nil, err
	}
	if len(gwList.InternetGateways) == 0 {
		return nil, fmt.Errorf(GatewayDoesNotExistError + ":" + name)
	}
	// there is nothing to prevent creating 2 GWs with the same name tag, but it indicates
	// an error for us.
	if len(gwList.InternetGateways) > 2 {
		return nil, fmt.Errorf("more than one subnet matching name tag: %s - numsubnets: %d", name, len(gwList.InternetGateways))
	}
	return &gwList.InternetGateways[0], nil
}

func (a *AwsEc2Platform) CreateInternetGateway(ctx context.Context, vpcName string) (*AwsEc2Gateway, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateInternetGateway", "vpcName", vpcName)
	tagspec := fmt.Sprintf("ResourceType=internet-gateway,Tags=[{Key=%s,Value=%s}]", NameTag, vpcName)
	gw, err := a.GetInternetGateway(ctx, vpcName)
	if err == nil {
		// already exists
		log.SpanLog(ctx, log.DebugLevelInfra, "Internet GW already exists", "vpcName", vpcName)
		return gw, nil
	}
	if !strings.Contains(err.Error(), GatewayDoesNotExistError) {
		return nil, err
	}
	out, err := a.awsGenPf.TimedAwsCommand(ctx, awsgen.AwsCredentialsSession, "aws",
		"ec2",
		"create-internet-gateway",
		"--region", a.awsGenPf.GetAwsRegion(),
		"--tag-specifications", tagspec)

	if err != nil {
		return nil, fmt.Errorf("Error in creating gateway: %s - %v", string(out), err)
	}

	var createdGW AwsEc2GatewayCreateResult
	err = json.Unmarshal(out, &createdGW)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "aws create-internet-gateway unmarshal fail", "out", string(out), "err", err)
		return nil, fmt.Errorf("cannot unmarshal, %v", err)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "created Internet GW", "gw", createdGW)
	return &createdGW.InternetGateway, nil
}

func (a *AwsEc2Platform) CreateInternetGatewayDefaultRoute(ctx context.Context, vpcName, vpcId string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateInternetGatewayDefaultRoute", "vpcName", vpcName, "vpcId", vpcId)

	gw, err := a.GetInternetGateway(ctx, vpcName)
	if err != nil {
		return err
	}
	// attach the GW to the VPC
	out, err := a.awsGenPf.TimedAwsCommand(ctx, awsgen.AwsCredentialsSession, "aws",
		"ec2",
		"attach-internet-gateway",
		"--region", a.awsGenPf.GetAwsRegion(),
		"--internet-gateway-id", gw.InternetGatewayId,
		"--vpc-id", vpcId)

	log.SpanLog(ctx, log.DebugLevelInfra, "attach-internet-gateway", "out", string(out), "err", err)
	if err != nil {
		if strings.Contains(string(out), ResourceAlreadyAssociatedError) {
			log.SpanLog(ctx, log.DebugLevelInfra, "gateway already attached")
		} else {
			return fmt.Errorf("Error in attach-internet-gateway: %s - %v", string(out), err)
		}
	}

	rtid, err := a.GetRouteTableId(ctx, vpcId, SearchForMainRouteTable, "")
	if err != nil {
		return err
	}
	out, err = a.awsGenPf.TimedAwsCommand(ctx, awsgen.AwsCredentialsSession, "aws",
		"ec2",
		"create-route",
		"--region", a.awsGenPf.GetAwsRegion(),
		"--gateway-id", gw.InternetGatewayId,
		"--destination-cidr-block", "0.0.0.0/0",
		"--route-table-id", rtid)

	log.SpanLog(ctx, log.DebugLevelInfra, "create-route result", "out", string(out), "err", err)
	if err != nil {
		return fmt.Errorf("Error in create-route: %s - %v", out, err)
	}
	return nil
}

func (a *AwsEc2Platform) GetRouteTableId(ctx context.Context, vpcId string, searchType RouteTableSearchType, name string) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetRouteTableId", "vpcId", vpcId, "searchType", searchType, "name", name)
	filter := fmt.Sprintf("Name=vpc-id,Values=%s", vpcId)
	out, err := a.awsGenPf.TimedAwsCommand(ctx, awsgen.AwsCredentialsSession, "aws",
		"ec2",
		"describe-route-tables",
		"--filters", filter,
		"--region", a.awsGenPf.GetAwsRegion())
	log.SpanLog(ctx, log.DebugLevelInfra, "describe-route-tables result", "out", string(out), "err", err)

	if err != nil {
		return "", fmt.Errorf("GetRouteTableId failed: %s - %v", string(out), err)
	}

	var rtList AwsEc2RouteTableList
	err = json.Unmarshal(out, &rtList)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "aws describe-route-tables unmarshal fail", "vpcId", vpcId, "out", string(out), "err", err)
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return "", err
	}
	for i, rt := range rtList.RouteTables {
		if searchType == SearchForRouteTableByName {
			for _, tag := range rt.Tags {
				if tag.Key == NameTag && tag.Value == name {
					return rtList.RouteTables[i].RouteTableId, nil
				}
			}
		} else if searchType == SearchForMainRouteTable {
			for _, a := range rt.Associations {
				if a.Main {
					return rtList.RouteTables[i].RouteTableId, nil
				}
			}
		} else {
			return "", fmt.Errorf("Must search route table either by main or name")
		}
	}
	return "", fmt.Errorf(RouteTableDoesNotExistError)
}

// CreateInternalRouteTable returns routeTableId, error
func (a *AwsEc2Platform) CreateInternalRouteTable(ctx context.Context, vpcId, natGwId, name string) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateInternalRouteTable", "name", name)
	rt, err := a.GetRouteTableId(ctx, vpcId, SearchForRouteTableByName, name)
	if err == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "RouteTable already exists")
		return rt, nil
	}
	if err != nil {
		if !strings.Contains(err.Error(), RouteTableDoesNotExistError) {
			return "", err
		}
	}

	tagspec := fmt.Sprintf("ResourceType=route-table,Tags=[{Key=%s,Value=%s}]", NameTag, name)
	out, err := a.awsGenPf.TimedAwsCommand(ctx, awsgen.AwsCredentialsSession, "aws",
		"ec2",
		"create-route-table",
		"--vpc-id", vpcId,
		"--region", a.awsGenPf.GetAwsRegion(),
		"--tag-specifications", tagspec)

	if err != nil {
		return "", fmt.Errorf("Error in creating route table: %s - %v", string(out), err)
	}

	// the create-route-table command returns a json of the rt
	var createdRt AwsEc2RouteTableCreateResult
	err = json.Unmarshal(out, &createdRt)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "aws create-route-table unmarshal fail", "name", name, "out", string(out), "err", err)
		return "", fmt.Errorf("cannot unmarshal, %v", err)
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "created route table", "rt", createdRt)

	// now add the natgw as the default route
	out, err = a.awsGenPf.TimedAwsCommand(ctx, awsgen.AwsCredentialsSession, "aws",
		"ec2",
		"create-route",
		"--route-table-id", createdRt.RouteTable.RouteTableId,
		"--nat-gateway-id", natGwId,
		"--destination-cidr-block", "0.0.0.0/0",
		"--region", a.awsGenPf.GetAwsRegion())

	if err != nil {
		return "", fmt.Errorf("Error in creating route : %s - %v", string(out), err)
	}
	return createdRt.RouteTable.RouteTableId, nil
}

func (a *AwsEc2Platform) GetElasticIP(ctx context.Context, name, vpcId string) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetElasticIP", "name", name)

	iflist, err := a.GetNetworkInterfaces(ctx)
	if err != nil {
		return "", err
	}
	usedIps := make(map[string]string)
	for _, intf := range iflist.NetworkInterfaces {
		if intf.Association.AllocationId != "" {
			usedIps[intf.Association.AllocationId] = intf.Association.PublicIp
		}
	}

	out, err := a.awsGenPf.TimedAwsCommand(ctx, awsgen.AwsCredentialsSession, "aws",
		"ec2",
		"describe-addresses",
		"--region", a.awsGenPf.GetAwsRegion())

	log.SpanLog(ctx, log.DebugLevelInfra, "describe-addresses", "out", string(out), "err", err)

	var addresses AwsEc2AddressList
	err = json.Unmarshal(out, &addresses)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "aws describe-addresses unmarshal fail", "name", name, "out", string(out), "err", err)
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return "", err
	}
	if len(addresses.Addresses) == 0 {

	}
	for _, addr := range addresses.Addresses {
		log.SpanLog(ctx, log.DebugLevelInfra, "Found elastic IP", "addr", addr)

		pip, ok := usedIps[addr.AllocationId]
		if ok {
			log.SpanLog(ctx, log.DebugLevelInfra, "Elastic IP already associated", "addr", addr, "pip", pip)
			continue
		}
		return addr.AllocationId, nil
	}
	return "", fmt.Errorf(ElasticIpDoesNotExistError + ":" + name)
}

func (a *AwsEc2Platform) AllocateElasticIP(ctx context.Context) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "AllocateElasticIP")

	out, err := a.awsGenPf.TimedAwsCommand(ctx, awsgen.AwsCredentialsSession, "aws",
		"ec2",
		"allocate-address",
		"--domain", "vpc",
		"--region", a.awsGenPf.GetAwsRegion())

	log.SpanLog(ctx, log.DebugLevelInfra, "allocate-address", "out", string(out), "err", err)

	var address AwsEc2Address
	err = json.Unmarshal(out, &address)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "aws allocate-address unmarshal fail", "out", string(out), "err", err)
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return "", err
	}
	return address.AllocationId, nil
}

func (a *AwsEc2Platform) GetSubnets(ctx context.Context) (map[string]*AwsEc2Subnet, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetSubnets")
	snMap := make(map[string]*AwsEc2Subnet)
	out, err := a.awsGenPf.TimedAwsCommand(ctx, awsgen.AwsCredentialsSession, "aws",
		"ec2",
		"describe-subnets",
		"--region", a.awsGenPf.GetAwsRegion())
	log.SpanLog(ctx, log.DebugLevelInfra, "describe-subnets result", "out", string(out), "err", err)
	if err != nil {
		return nil, fmt.Errorf("GetSubnets failed: %s - %v", string(out), err)
	}
	var subnetList AwsEc2SubnetList
	err = json.Unmarshal(out, &subnetList)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "aws describe-subnets unmarshal fail", "out", string(out), "err", err)
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return nil, err
	}
	for i, s := range subnetList.Subnets {
		subnetName := ""
		for _, t := range s.Tags {
			if t.Key == NameTag {
				subnetName = t.Value
			}
		}
		if subnetName != "" {
			subnetList.Subnets[i].Name = subnetName
			snMap[subnetName] = &subnetList.Subnets[i]
		}
	}
	return snMap, nil
}

func (a *AwsEc2Platform) GetSubnet(ctx context.Context, name string) (*AwsEc2Subnet, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetSubnet", "name", name)
	filter := fmt.Sprintf("Name=tag-value,Values=%s", name)
	out, err := a.awsGenPf.TimedAwsCommand(ctx, awsgen.AwsCredentialsSession, "aws",
		"ec2",
		"describe-subnets",
		"--filters", "Name=tag-key,Values=Name", filter,
		"--region", a.awsGenPf.GetAwsRegion())
	log.SpanLog(ctx, log.DebugLevelInfra, "describe-subnets result", "out", string(out), "err", err)
	if err != nil {
		return nil, fmt.Errorf("GetSubnet failed: %s - %v", string(out), err)
	}
	var subnetList AwsEc2SubnetList
	err = json.Unmarshal(out, &subnetList)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "aws describe-subnets unmarshal fail", "name", name, "out", string(out), "err", err)
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return nil, err
	}
	if len(subnetList.Subnets) == 0 {
		return nil, fmt.Errorf(SubnetDoesNotExistError + ":" + name)
	}
	// there is nothing to prevent creating 2 VPCs with the same name tag, but it indicates
	// an error for us.
	if len(subnetList.Subnets) > 2 {
		return nil, fmt.Errorf("more than one subnet matching name tag: %s - numsubnets: %d", name, len(subnetList.Subnets))
	}
	subnetList.Subnets[0].Name = name
	return &subnetList.Subnets[0], nil
}

// CreateSubnet returns subnetId, error
func (a *AwsEc2Platform) CreateSubnet(ctx context.Context, vmGroupName, name string, cidr string, routeTableId string) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateSubnet", "vmGroupName", vmGroupName, "name", name, "routeTableId", routeTableId)
	tagspec := fmt.Sprintf("ResourceType=subnet,Tags=[{Key=%s,Value=%s},{Key=%s,Value=%s}]", NameTag, name, VMGroupNameTag, vmGroupName)
	sn, err := a.GetSubnet(ctx, name)
	if err == nil {
		// already exists
		return sn.SubnetId, fmt.Errorf(SubnetAlreadyExistsError + ": " + name)
	}
	if !strings.Contains(err.Error(), SubnetDoesNotExistError) {
		return "", err
	}
	vpc, err := a.GetVPC(ctx, a.GetVpcName())
	if err != nil {
		return "", err
	}
	out, err := a.awsGenPf.TimedAwsCommand(ctx, awsgen.AwsCredentialsSession, "aws",
		"ec2",
		"create-subnet",
		"--vpc-id", vpc.VpcId,
		"--region", a.awsGenPf.GetAwsRegion(),
		"--cidr-block", cidr,
		"--tag-specifications", tagspec)
	log.SpanLog(ctx, log.DebugLevelInfra, "create-subnet result", "out", string(out), "err", err)
	if err != nil {
		return "", fmt.Errorf("Error in creating subnet: %s - %v", string(out), err)
	}
	var createdSn AwsEc2SubnetCreateResult
	err = json.Unmarshal(out, &createdSn)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "aws create-subnet unmarshal fail", "out", string(out), "err", err)
		return "", fmt.Errorf("cannot unmarshal, %v", err)
	}
	if routeTableId != MainRouteTable {
		// associate the non default route table
		out, err := a.awsGenPf.TimedAwsCommand(ctx, awsgen.AwsCredentialsSession, "aws",
			"ec2",
			"associate-route-table",
			"--route-table-id", routeTableId,
			"--subnet-id", createdSn.Subnet.SubnetId)

		log.SpanLog(ctx, log.DebugLevelInfra, "associate-route-table result", "out", string(out), "err", err)
		if err != nil {
			return "", fmt.Errorf("Error in associating route table: %s - %v", string(out), err)
		}
	}
	return createdSn.Subnet.SubnetId, nil
}

func (a *AwsEc2Platform) DeleteSubnet(ctx context.Context, snId string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteSubnet", "snId", snId)
	out, err := a.awsGenPf.TimedAwsCommand(ctx, awsgen.AwsCredentialsSession, "aws",
		"ec2",
		"delete-subnet",
		"--subnet-id", snId,
		"--region", a.awsGenPf.GetAwsRegion())
	log.SpanLog(ctx, log.DebugLevelInfra, "delete-subnet result", "out", string(out), "err", err)
	if err != nil {
		return fmt.Errorf("DeleteSubnet failed: %s - %v", string(out), err)
	}
	return nil
}

func (a *AwsEc2Platform) GetNatGateway(ctx context.Context, name string) (*AwsEc2NatGateway, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetNatGateway", "name", name)
	out, err := a.awsGenPf.TimedAwsCommand(ctx, awsgen.AwsCredentialsSession, "aws",
		"ec2",
		"describe-nat-gateways",
		"--region", a.awsGenPf.GetAwsRegion())
	if err != nil {
		return nil, fmt.Errorf("GetNatGateway failed: %s - %v", string(out), err)
	}
	var ngwList AwsEc2NatGatewayList
	err = json.Unmarshal(out, &ngwList)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "aws describe-nat-gateways unmarshal fail", "name", name, "out", string(out), "err", err)
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return nil, err
	}
	numgw := 0
	for _, gw := range ngwList.NatGateways {
		log.SpanLog(ctx, log.DebugLevelInfra, "found nat gw", "gw", gw)
		if gw.State == "available" {
			numgw++
		}
	}
	if numgw == 0 {
		return nil, fmt.Errorf(GatewayDoesNotExistError + ":" + name)
	}
	// there is nothing to prevent creating 2 GWs with the same name tag, but it indicates
	// an error for us.
	if numgw > 2 {
		return nil, fmt.Errorf("more than one subnet matching name tag: %s - numsubnets: %d", name, len(ngwList.NatGateways))
	}
	return &ngwList.NatGateways[0], nil
}

// CreateNatGateway returns natGatewayId, error
func (a *AwsEc2Platform) CreateNatGateway(ctx context.Context, subnetId, elasticIpId, vpcName string) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateNatGateway", "subnetId", subnetId, "vpcName", vpcName)
	tagspec := fmt.Sprintf("ResourceType=natgateway,Tags=[{Key=%s,Value=%s}]", NameTag, vpcName)

	ng, err := a.GetNatGateway(ctx, vpcName)
	if err == nil {
		// already exists
		return ng.NatGatewayId, nil
	}
	if !strings.Contains(err.Error(), GatewayDoesNotExistError) {
		return "", err
	}
	out, err := a.awsGenPf.TimedAwsCommand(ctx, awsgen.AwsCredentialsSession, "aws",
		"ec2",
		"create-nat-gateway",
		"--subnet-id", subnetId,
		"--allocation-id", elasticIpId,
		"--region", a.awsGenPf.GetAwsRegion(),
		"--tag-specifications", tagspec)

	if err != nil {
		return "", fmt.Errorf("Error in creating gateway: %s - %v", string(out), err)
	}
	var createdNg AwsEc2NatGatewayCreateResult
	err = json.Unmarshal(out, &createdNg)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "aws create-nat-gateway unmarshal fail", "out", string(out), "err", err)
		return "", fmt.Errorf("cannot unmarshal, %v", err)
	}
	// wait for it to become active
	start := time.Now()
	for {
		_, err := a.GetNatGateway(ctx, vpcName)
		if err == nil {
			break
		}
		if !strings.Contains(err.Error(), GatewayDoesNotExistError) {
			return "", err
		}
		elapsed := time.Since(start)
		if elapsed > maxGwWait {
			return "", fmt.Errorf("timed out waiting for nat gw")
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "Sleep and check natgw again", "elaspsed", elapsed)
		time.Sleep(5 * time.Second)
	}
	return createdNg.NatGateway.NatGatewayId, nil
}

// AssignFreePrecreatedSubnet sets a new name and group tag to denote that the subnet is being used
func (a *AwsEc2Platform) AssignFreePrecreatedSubnet(ctx context.Context, subnetId, vmGroupName, newName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "AssignFreePrecreatedSubnet", "subnetId", subnetId, "newName", newName)

	tags := []string{
		fmt.Sprintf("Key=%s,Value=%s", NameTag, newName),
		fmt.Sprintf("Key=%s,Value=%s", VMGroupNameTag, vmGroupName),
	}
	for _, t := range tags {
		out, err := a.awsGenPf.TimedAwsCommand(ctx, awsgen.AwsCredentialsSession, "aws",
			"ec2",
			"create-tags",
			"--resources", subnetId,
			"--region", a.awsGenPf.GetAwsRegion(),
			"--tags", t)
		log.SpanLog(ctx, log.DebugLevelInfra, "create-tags result", "out", string(out), "err", err)
		if err != nil {
			return fmt.Errorf("Error in setting subnet tag %s: %s - %v", t, out, err)
		}
	}
	return nil
}

// ReleasePrecreatedSubnet removes the group tag and sets the name tag back to free-<type>
func (a *AwsEc2Platform) ReleasePrecreatedSubnet(ctx context.Context, subnetId, vmGroupName, subnetType string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "ReleasePrecreatedSubnet", "subnetId", subnetId, "subnetType", subnetType)

	nameTag := fmt.Sprintf("Key=%s,Value=%s", NameTag, subnetType+"-"+subnetId)
	groupTag := fmt.Sprintf("Key=%s,Value=%s", VMGroupNameTag, vmGroupName)

	out, err := a.awsGenPf.TimedAwsCommand(ctx, awsgen.AwsCredentialsSession, "aws",
		"ec2",
		"create-tags",
		"--resources", subnetId,
		"--region", a.awsGenPf.GetAwsRegion(),
		"--tags", nameTag)
	if err != nil {
		return fmt.Errorf("Error in setting subnet name tag %s: %s - %v", nameTag, out, err)
	}
	out, err = a.awsGenPf.TimedAwsCommand(ctx, awsgen.AwsCredentialsSession, "aws",
		"ec2",
		"delete-tags",
		"--resources", subnetId,
		"--region", a.awsGenPf.GetAwsRegion(),
		"--tags", groupTag)
	if err != nil {
		return fmt.Errorf("Error in deleting subnet group tag %s: %s - %v", groupTag, out, err)
	}

	return nil
}

// GetFreePrecreatedSubnet finds a free pre-created subnet of the given type and then assigns it
func (a *AwsEc2Platform) GetFreePrecreatedSubnet(ctx context.Context, subnetName, subnetType, vmGroupName string, subnets map[string]*AwsEc2Subnet) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetFreePrecreatedSubnet", "subnetName", subnetName)

	for sname := range subnets {
		// first look for the existing one
		if sname == subnetName {
			return nil
		}
	}
	for sname, subnet := range subnets {
		if strings.HasPrefix(sname, subnetType) {
			return a.AssignFreePrecreatedSubnet(ctx, subnet.SubnetId, vmGroupName, subnetName)
		}
	}
	return fmt.Errorf("No free subnet found for type %s", subnetType)
}

func (o *AwsEc2Platform) ValidateAdditionalNetworks(ctx context.Context, additionalNets map[string]vmlayer.NetworkType) error {
	return fmt.Errorf("Additional networks not supported in AWS EC2 cloudlets")
}
