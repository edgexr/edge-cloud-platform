package openstack

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	dme "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

// CloudletSecurityGroupIDMap is a cache of cloudlet to security group id
var CloudletSecurityGroupIDMap = make(map[string]string)

var cloudetSecurityGroupIDLock sync.Mutex

const SecgrpDoesNotExist string = "Security group does not exist"
const SecgrpRuleAlreadyExists string = "Security group rule already exists"

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

func (s *OpenstackPlatform) AddSecurityGroupToPort(ctx context.Context, portID, groupName string) error {
	out, err := s.TimedOpenStackCommand(ctx, "openstack", "port", "set", "--security-group", groupName, portID)
	if err != nil {
		err = fmt.Errorf("can't add security group to port, %s, %v", out, err)
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

func (o *OpenstackPlatform) AddSecurityRules(ctx context.Context, groupName string, ports []dme.AppPort, serverName string) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "AddSecurityRules", "ports", ports)
	allowedClientCIDR := vmlayer.GetAllowedClientCIDR()
	for _, port := range ports {
		//todo: distinguish already-exists errors from others
		portString := fmt.Sprintf("%d", port.PublicPort)
		if port.EndPort != 0 {
			portString = fmt.Sprintf("%d:%d", port.PublicPort, port.EndPort)
		}
		proto, err := edgeproto.L4ProtoStr(port.Proto)
		if err != nil {
			return err
		}
		if err := o.AddSecurityRuleCIDR(ctx, allowedClientCIDR, proto, groupName, portString); err != nil {
			return err
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

func (o *OpenstackPlatform) RemoveWhitelistSecurityRules(ctx context.Context, client ssh.Client, secGrpName, label, allowedCIDR string, ports []dme.AppPort) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "RemoveWhitelistSecurityRules", "secGrpName", secGrpName, "ports", ports)

	allowedClientCIDR := vmlayer.GetAllowedClientCIDR()
	rules, err := o.ListSecurityGroupRules(ctx, secGrpName)
	if err != nil {
		return err
	}
	for _, port := range ports {
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

func (o *OpenstackPlatform) WhitelistSecurityRules(ctx context.Context, client ssh.Client, grpName, server, label, allowedCidr string, ports []dme.AppPort) error {
	// open the firewall for internal traffic
	log.SpanLog(ctx, log.DebugLevelInfra, "WhitelistSecurityRules", "grpName", grpName, "allowedCidr", allowedCidr, "ports", ports)

	for _, p := range ports {
		portStr := fmt.Sprintf("%d", p.PublicPort)
		proto, err := edgeproto.L4ProtoStr(p.Proto)
		if err != nil {
			return err
		}
		if err := o.AddSecurityRuleCIDR(ctx, allowedCidr, proto, grpName, portStr); err != nil {
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
func (o *OpenstackPlatform) PrepareCloudletSecurityGroup(ctx context.Context) error {
	grpName := o.VMProperties.GetCloudletSecurityGroupName()
	log.SpanLog(ctx, log.DebugLevelInfra, "PrepareCloudletSecurityGroup", "grpName", grpName)

	_, err := o.GetSecurityGroupIDForName(ctx, grpName)
	if err != nil {
		if !strings.Contains(err.Error(), SecgrpDoesNotExist) {
			return err
		}
		// create the group
		log.SpanLog(ctx, log.DebugLevelInfra, "Cloudlet group does not exist, creating", "grpName", grpName)
		err := o.CreateSecurityGroup(ctx, grpName)
		if err != nil {
			return err
		}
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
	return nil
}
