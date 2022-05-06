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

package openstack

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/edgexr/edge-cloud-infra/infracommon"
	"github.com/edgexr/edge-cloud-infra/vmlayer"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

// CloudletSecurityGroupIDMap is a cache of cloudlet to security group id
var CloudletSecurityGroupIDMap = make(map[string]string)

var cloudetSecurityGroupIDLock sync.Mutex

const SecgrpDoesNotExist string = "Security group does not exist"
const SecgrpRuleAlreadyExists string = "Security group rule already exists"
const StackAlreadyExists string = "already exists"

func getCachedSecgrpID(ctx context.Context, name string) string {
	cloudetSecurityGroupIDLock.Lock()
	defer cloudetSecurityGroupIDLock.Unlock()
	groupID, ok := CloudletSecurityGroupIDMap[name]
	if !ok {
		return ""
	}
	return groupID
}

func setCachedCloudletSecgrpID(ctx context.Context, keyString, groupID string) {
	cloudetSecurityGroupIDLock.Lock()
	defer cloudetSecurityGroupIDLock.Unlock()
	CloudletSecurityGroupIDMap[keyString] = groupID
}

//ListSecurityGroups returns a list of security groups
func (s *OpenstackPlatform) ListSecurityGroups(ctx context.Context) ([]OSSecurityGroup, error) {
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "security", "group", "list", "-f", "json")
	if err != nil {
		err = fmt.Errorf("can't get a list of security groups, %s, %v", out, err)
		return nil, err
	}
	secgrps := []OSSecurityGroup{}
	err = json.Unmarshal(out, &secgrps)
	if err != nil {
		err = fmt.Errorf("can't unmarshal security groups, %v", err)
		return nil, err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "list security groups", "security groups", secgrps)
	return secgrps, nil
}

//ListSecurityGroups returns a list of security groups
func (s *OpenstackPlatform) ListSecurityGroupRules(ctx context.Context, secGrp string) ([]OSSecurityGroupRule, error) {
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "security", "group", "rule", "list", secGrp, "-f", "json")
	if err != nil {
		err = fmt.Errorf("can't get a list of security group rules, %s, %v", out, err)
		return nil, err
	}
	rules := []OSSecurityGroupRule{}
	err = json.Unmarshal(out, &rules)
	if err != nil {
		err = fmt.Errorf("can't unmarshal security group rules, %v", err)
		return nil, err
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "list security group rules", "security groups", rules)
	return rules, nil
}

func (s *OpenstackPlatform) CreateSecurityGroup(ctx context.Context, groupName string) error {
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "security", "group", "create", groupName)
	if err != nil {
		err = fmt.Errorf("can't create security group, %s, %v", out, err)
		return err
	}
	return nil
}

func (s *OpenstackPlatform) AttachSecurityGroupToPort(ctx context.Context, portID, groupName string) error {
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "port", "set", "--security-group", groupName, portID)
	if err != nil {
		err = fmt.Errorf("can't attach security group to port, %s, %v", out, err)
		return err
	}
	return nil
}

func (s *OpenstackPlatform) DetachSecurityGroupFromPort(ctx context.Context, portID, groupName string) error {
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "port", "unset", "--security-group", groupName, portID)
	if err != nil {
		err = fmt.Errorf("can't detach security group to port, %s, %v", out, err)
		return err
	}
	return nil
}

// GetSecurityGroupIDForName gets the group ID for the given security group name.  It handles
// duplicate names by finding the one for the project.
func (s *OpenstackPlatform) GetSecurityGroupIDForName(ctx context.Context, groupName string) (string, error) {

	log.SpanLog(ctx, log.DebugLevelInfra, "GetCloudletSecurityGroupID", "groupName", groupName)

	cloudletKey := s.VMProperties.CommonPf.PlatformConfig.CloudletKey.GetKeyString()
	groupKey := cloudletKey + groupName
	groupID := getCachedSecgrpID(ctx, groupKey)
	if groupID != "" {
		//cached
		log.SpanLog(ctx, log.DebugLevelInfra, "GetCloudletSecurityGroupID using existing value", "groupID", groupID)
		return groupID, nil
	}

	projectName := s.GetCloudletProjectName()
	if projectName == "" {
		return "", fmt.Errorf("No OpenStack project name, cannot get project security group")
	}
	projects, err := s.ListProjects(ctx)
	if err != nil {
		return "", err
	}
	for _, p := range projects {
		if p.Name == projectName {
			groupID, err = s.GetSecurityGroupIDForProject(ctx, groupName, p.ID)
			if err != nil {
				return "", err
			}
			setCachedCloudletSecgrpID(ctx, groupKey, groupID)
			log.SpanLog(ctx, log.DebugLevelInfra, "GetCloudletSecurityGroupID using new value", "groupID", groupID)
			return groupID, nil
		}
	}
	return "", fmt.Errorf("Unable to find cloudlet project: %s", projectName)
}

func (o *OpenstackPlatform) AddSecurityRulesForRemoteGroup(ctx context.Context, groupId, remoteGroupId, protocol, direction string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "AddSecurityRulesForRemoteGroup", "groupId", groupId, "remoteGroupId", remoteGroupId, "protocol", protocol, "direction", direction)
	out, err := o.TimedOpenStackCommand(ctx, "openstack", "security", "group", "rule", "create", "--"+direction, "--proto", protocol, "--remote-group", remoteGroupId, groupId)
	if err != nil {
		if strings.Contains(string(out), SecgrpRuleAlreadyExists) {
			log.SpanLog(ctx, log.DebugLevelInfra, "security group rule already exists, proceeding")
		} else {
			return fmt.Errorf("can't add rule for security group %s protocol %s direction %s to remote %s,%v", groupId, protocol, direction, remoteGroupId, err)
		}
	}
	return nil
}

func (s *OpenstackPlatform) AddSecurityRuleCIDR(ctx context.Context, cidr string, proto string, groupName string, port string) error {
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "security", "group", "rule", "create", "--remote-ip", cidr, "--proto", proto, "--dst-port", port, "--ingress", groupName)
	if err != nil {
		if strings.Contains(string(out), SecgrpRuleAlreadyExists) {
			log.SpanLog(ctx, log.DebugLevelInfra, "security group rule already exists, proceeding")
		} else {
			return fmt.Errorf("can't add security group rule for port %s to %s,%s,%v", port, groupName, string(out), err)
		}
	}
	return nil
}

func (s *OpenstackPlatform) DeleteSecurityGroupRule(ctx context.Context, ruleID string) error {
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "security", "group", "rule", "delete", ruleID)
	if err != nil {
		return fmt.Errorf("can't delete security group rule %s,%s,%v", ruleID, string(out), err)
	}
	return nil
}

func (o *OpenstackPlatform) RemoveWhitelistSecurityRules(ctx context.Context, client ssh.Client, wlParams *infracommon.WhiteListParams) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "RemoveWhitelistSecurityRules", "wlParams", wlParams)

	allowedClientCIDR := infracommon.GetAllowedClientCIDR()
	rules, err := o.ListSecurityGroupRules(ctx, wlParams.SecGrpName)
	if err != nil {
		return err
	}
	for _, port := range wlParams.Ports {
		portString := fmt.Sprintf("%d:%d", port.PublicPort, port.PublicPort)
		if port.EndPort != 0 {
			portString = fmt.Sprintf("%d:%d", port.PublicPort, port.EndPort)
		}
		proto, err := edgeproto.L4ProtoStr(port.Proto)
		if err != nil {
			return err
		}
		for _, r := range rules {
			if r.PortRange == portString && r.Protocol == proto && r.IPRange == allowedClientCIDR {
				if err := o.DeleteSecurityGroupRule(ctx, r.ID); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (o *OpenstackPlatform) WhitelistSecurityRules(ctx context.Context, client ssh.Client, wlParams *infracommon.WhiteListParams) error {
	// open the firewall for internal traffic
	log.SpanLog(ctx, log.DebugLevelInfra, "WhitelistSecurityRules", "wlParams", wlParams)

	for _, p := range wlParams.Ports {
		portStr := fmt.Sprintf("%d", p.PublicPort)
		if p.EndPort != 0 {
			portStr = fmt.Sprintf("%d:%d", p.PublicPort, p.EndPort)
		}
		proto, err := edgeproto.L4ProtoStr(p.Proto)
		if err != nil {
			return err
		}
		if err := o.AddSecurityRuleCIDR(ctx, wlParams.AllowedCIDR, proto, wlParams.SecGrpName, portStr); err != nil {
			return err
		}
	}
	return nil
}

func (s *OpenstackPlatform) GetSecurityGroupIDForProject(ctx context.Context, grpname string, projectID string) (string, error) {
	grps, err := s.ListSecurityGroups(ctx)
	if err != nil {
		return "", err
	}
	grpId := ""
	for _, g := range grps {
		if g.Name == grpname {
			if g.Project == projectID {
				log.SpanLog(ctx, log.DebugLevelInfra, "GetSecurityGroupIDForProject", "projectID", projectID, "group", grpname)
				return g.ID, nil
			}
			if g.Project == "" {
				// This is an openstack bug in some environments in which it may not show the project ids when listing the group
				// all we can do is hope for no conflicts in this case
				// Use this group ID, if no other ID found
				grpId = g.ID
			}
		}
	}
	if grpId != "" {
		log.SpanLog(ctx, log.DebugLevelInfra, "Warning: no project id returned for security group", "group", grpname)
		return grpId, nil
	}
	return "", fmt.Errorf("%s: %s project %s", SecgrpDoesNotExist, grpname, projectID)
}

// PrepareCloudletSecurityGroup creates the cloudlet group if it does not exist and ensures
// that the remote-group rules are present to allow platform components to communicate
func (o *OpenstackPlatform) ConfigureCloudletSecurityRules(ctx context.Context, egressRestricted bool, TrustPolicy *edgeproto.TrustPolicy, rootLbClients map[string]ssh.Client, action vmlayer.ActionType, updateCallback edgeproto.CacheUpdateCallback) error {
	grpName := o.VMProperties.CloudletSecgrpName
	log.SpanLog(ctx, log.DebugLevelInfra, "ConfigureCloudletSecurityRules", "CloudletSecgrpName", grpName, "action", action, "egressRestricted", egressRestricted)

	if action == vmlayer.ActionCreate || action == vmlayer.ActionUpdate {
		err := o.CreateOrUpdateCloudletSecgrpStack(ctx, egressRestricted, TrustPolicy, updateCallback)
		if err != nil {
			return err
		}
		cloudletGrpId, err := o.GetSecurityGroupIDForName(ctx, grpName)
		if err != nil {
			return err
		}
		log.SpanLog(ctx, log.DebugLevelInfra, "Creating remote-group rules from cloudlet grp to itself", "cloudletGrpId", cloudletGrpId)

		// Add cloudlet group rules to itself and to the platform secrgrp if one exists
		directions := []string{"ingress", "egress"}
		remoteGroups := []string{cloudletGrpId}

		platGrpId, err := o.GetSecurityGroupIDForName(ctx, o.VMProperties.PlatformSecgrpName)
		if err != nil {
			if strings.Contains(err.Error(), SecgrpDoesNotExist) {
				// this should only happen if CreateCloudlet was not used to onboard and the CRM was created manually
				log.SpanLog(ctx, log.DebugLevelInfra, "Platform group does not exist", "platform group", o.VMProperties.PlatformSecgrpName)
			} else {
				return err
			}
		} else {
			remoteGroups = append(remoteGroups, platGrpId)
		}
		for _, remote := range remoteGroups {
			for _, dir := range directions {
				err = o.AddSecurityRulesForRemoteGroup(ctx, cloudletGrpId, remote, "any", dir)
				if err != nil {
					return err
				}
			}
		}
	} else {
		return o.DeleteCloudletSecgrpStack(ctx, updateCallback)
	}
	return nil
}

func (o *OpenstackPlatform) CreateOrUpdateSecgrpStack(ctx context.Context, grpName string, egressRestricted bool, rules []edgeproto.SecurityRule, updateCallback edgeproto.CacheUpdateCallback) error {

	log.SpanLog(ctx, log.DebugLevelInfra, "CreateOrUpdateSecgrpStack", "grpName", grpName)

	grpExists := false
	stackExists := false
	_, err := o.GetSecurityGroupIDForName(ctx, grpName)
	if err != nil {
		if strings.Contains(err.Error(), SecgrpDoesNotExist) {
			// this is ok
			log.SpanLog(ctx, log.DebugLevelInfra, "Security group does not exist", "secGrpName", grpName)
		} else {
			return err
		}
	} else {
		grpExists = true
	}
	vmgp, err := vmlayer.GetVMGroupOrchestrationParamsFromTrustPolicy(ctx, grpName, rules, egressRestricted, vmlayer.SecGrpWithAccessPorts("tcp:22", infracommon.RemoteCidrAll))
	if err != nil {
		return err
	}
	_, err = o.getHeatStackDetail(ctx, grpName)
	if err != nil {
		if strings.Contains(err.Error(), StackNotFound) {
			// this is ok
			log.SpanLog(ctx, log.DebugLevelInfra, "heat stack does not exist", "secGrpName", grpName)
		} else {
			return err
		}
	} else {
		stackExists = true
	}
	if grpExists {
		if stackExists {
			// update the existing stack
			log.SpanLog(ctx, log.DebugLevelInfra, "Updating heat stack for existing cloudlet security group", "name", grpName)
			err = o.UpdateHeatStackFromTemplate(ctx, vmgp, grpName, VmGroupTemplate, updateCallback)
			if err != nil {
				return err
			}
		} else {
			// this can happen if a previously existing cloudlet with a security group already defined exists.  In this case
			// leave it alone as it may have any number of custom settings
			log.SpanLog(ctx, log.DebugLevelInfra, "Leaving existing cloudlet group with no stack unmodified", "name", grpName)
		}
	} else {
		if stackExists {
			// the stack exists but the group does not.  It could have been deleted separately, so attempt to modify the stack and re-create the group
			log.SpanLog(ctx, log.DebugLevelInfra, "Updating heat stack for missing cloudlet security group", "name", grpName)
			err = o.UpdateHeatStackFromTemplate(ctx, vmgp, grpName, VmGroupTemplate, updateCallback)
			if err != nil {
				return err
			}
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "Creating heat stack for new cloudlet security group", "name", grpName)
			err = o.CreateHeatStackFromTemplate(ctx, vmgp, grpName, VmGroupTemplate, updateCallback)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func (o *OpenstackPlatform) CreateOrUpdateCloudletSecgrpStack(ctx context.Context, egressRestricted bool, TrustPolicy *edgeproto.TrustPolicy, updateCallback edgeproto.CacheUpdateCallback) error {
	grpName := o.VMProperties.CloudletSecgrpName

	log.SpanLog(ctx, log.DebugLevelInfra, "CreateOrUpdateCloudletSecgrpStack", "grpName", grpName, "TrustPolicy", TrustPolicy)

	return o.CreateOrUpdateSecgrpStack(ctx, grpName, egressRestricted, TrustPolicy.OutboundSecurityRules, updateCallback)
}

func (o *OpenstackPlatform) DeleteCloudletSecgrpStack(ctx context.Context, updateCallback edgeproto.CacheUpdateCallback) error {
	grpName := o.VMProperties.CloudletSecgrpName
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteCloudletSecgrpStack", "grpName", grpName)
	return o.deleteHeatStack(ctx, grpName)
}

func (o *OpenstackPlatform) getTrustPolicyExceptionStackName(tpeKey *edgeproto.TrustPolicyExceptionKey) string {
	grpName := o.NameSanitize(tpeKey.Name + "-" + tpeKey.AppKey.Name + "-" + tpeKey.AppKey.Organization + "-" + tpeKey.AppKey.Version + "-" + tpeKey.CloudletPoolKey.Name + "-" + tpeKey.CloudletPoolKey.Organization)
	return grpName
}

// Attach or Detach a security group to/from a port of rootLbClients
func (o *OpenstackPlatform) programSecurityGroupToPort(ctx context.Context, grpName string, rootLbClients map[string]ssh.Client, action vmlayer.ActionType) error {
	var err error
	err = nil
	for keyServerName, _ := range rootLbClients {

		netTypes := []vmlayer.NetworkType{
			vmlayer.NetworkTypeExternalAdditionalRootLb,
			vmlayer.NetworkTypeExternalPrimary,
		}
		externalNetMap := o.VMProperties.GetNetworksByType(ctx, netTypes)

		var ports []OSPort
		for keyNetworkName, _ := range externalNetMap {
			portList, err := o.ListPortsServerNetwork(ctx, keyServerName, keyNetworkName)
			if err != nil {
				err = fmt.Errorf("cannot get port list, %s, %v", keyServerName, err)
				log.SpanLog(ctx, log.DebugLevelInfra, "ListPortsServer failed", "server:", keyServerName, "err:", err)
				continue
			}
			ports = append(ports, portList...)
		}

		for _, port := range ports {
			if action == vmlayer.ActionCreate || action == vmlayer.ActionUpdate {
				err = o.AttachSecurityGroupToPort(ctx, port.ID, grpName)
			} else {
				err = o.DetachSecurityGroupFromPort(ctx, port.ID, grpName)
			}
			if err != nil {
				err = fmt.Errorf("cannot program security group %s to server:%s port: %s err:%v", grpName, keyServerName, port.ID, err)
			}
		}
	}
	return err
}

func (o *OpenstackPlatform) ConfigureTrustPolicyExceptionSecurityRules(ctx context.Context, TrustPolicyException *edgeproto.TrustPolicyException, rootLbClients map[string]ssh.Client, action vmlayer.ActionType, updateCallback edgeproto.CacheUpdateCallback) error {
	grpName := o.getTrustPolicyExceptionStackName(&TrustPolicyException.Key)
	egressRestricted := false
	log.SpanLog(ctx, log.DebugLevelInfra, "ConfigureTrustPolicyExceptionSecurityRules", "TrustPolicyExceptionSecgrpName", grpName, "action", action, "egressRestricted", egressRestricted)

	if action == vmlayer.ActionCreate || action == vmlayer.ActionUpdate {
		err := o.CreateOrUpdateTrustPolicyExceptionSecgrpStack(ctx, egressRestricted, TrustPolicyException, updateCallback)
		if err != nil {
			return err
		}
	} else {
		err := o.DeleteTrustPolicyExceptionSecgrpStack(ctx, &TrustPolicyException.Key, updateCallback)
		if err != nil {
			return err
		}
	}
	return o.programSecurityGroupToPort(ctx, grpName, rootLbClients, action)

}

func (o *OpenstackPlatform) CreateOrUpdateTrustPolicyExceptionSecgrpStack(ctx context.Context, egressRestricted bool, TrustPolicyException *edgeproto.TrustPolicyException, updateCallback edgeproto.CacheUpdateCallback) error {
	grpName := o.getTrustPolicyExceptionStackName(&TrustPolicyException.Key)
	log.SpanLog(ctx, log.DebugLevelInfra, "CreateOrUpdateTrustPolicyExceptionSecgrpStack", "grpName", grpName, "TrustPolicyException", TrustPolicyException)
	return o.CreateOrUpdateSecgrpStack(ctx, grpName, egressRestricted, TrustPolicyException.OutboundSecurityRules, updateCallback)
}

func (o *OpenstackPlatform) DeleteTrustPolicyExceptionSecgrpStack(ctx context.Context, tpeKey *edgeproto.TrustPolicyExceptionKey, updateCallback edgeproto.CacheUpdateCallback) error {
	grpName := o.getTrustPolicyExceptionStackName(tpeKey)
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteTrustPolicyExceptionSecgrpStack", "grpName", grpName, "tpeKey", tpeKey)
	return o.deleteHeatStack(ctx, grpName)
}
