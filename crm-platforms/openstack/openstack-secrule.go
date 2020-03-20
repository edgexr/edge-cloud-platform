package openstack

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/mobiledgex/edge-cloud-infra/mexos"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/access"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/dockermgmt"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/proxy"
	dme "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vault"
	ssh "github.com/mobiledgex/golang-ssh"
)

// CloudletSecurityGroupIDMap is a cache of cloudlet to security group id
var CloudletSecurityGroupIDMap = make(map[string]string)

var cloudetSecurityGroupIDLock sync.Mutex

// GetSecurityGroupName gets the secgrp name based on the server name
func GetSecurityGroupName(ctx context.Context, serverName string) string {
	return serverName + "-sg"
}

func getCachedCloudletSecgrpID(ctx context.Context, keyString string) string {
	cloudetSecurityGroupIDLock.Lock()
	defer cloudetSecurityGroupIDLock.Unlock()
	groupID, ok := CloudletSecurityGroupIDMap[keyString]
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

// GetCloudletSecurityGroupID gets the group ID for the default cloudlet-wide group for our project.  It handles
// duplicate names.  This group should not be used for application traffic, it is for management/OAM/CRM access.
func (s *Platform) GetCloudletSecurityGroupID(ctx context.Context, cloudletKey *edgeproto.CloudletKey) (string, error) {
	groupName := s.GetCloudletSecurityGroupName()
	keyString := cloudletKey.GetKeyString()

	log.SpanLog(ctx, log.DebugLevelMexos, "GetCloudletSecurityGroupID", "groupName", groupName, "keyString", keyString)

	groupID := getCachedCloudletSecgrpID(ctx, keyString)
	if groupID != "" {
		//cached
		log.SpanLog(ctx, log.DebugLevelMexos, "GetCloudletSecurityGroupID using existing value", "groupID", groupID)
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
			setCachedCloudletSecgrpID(ctx, keyString, groupID)
			log.SpanLog(ctx, log.DebugLevelMexos, "GetCloudletSecurityGroupID using new value", "groupID", groupID)
			return groupID, nil
		}
	}
	return "", fmt.Errorf("Unable to find cloudlet security group for project: %s", projectName)
}

func (s *Platform) AddSecurityRules(ctx context.Context, groupName string, ports []dme.AppPort, serverName string) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "AddSecurityRules", "ports", ports)
	allowedClientCIDR := mexos.GetAllowedClientCIDR()
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
		if err := s.AddSecurityRuleCIDRWithRetry(ctx, allowedClientCIDR, proto, groupName, portString, serverName); err != nil {
			return err
		}
	}
	return nil
}

// AddSecurityRuleCIDRWithRetry calls AddSecurityRuleCIDR, and then will retry if that fails because the group does not exist.  This can happen during
// the transition between cloudlet-wide security groups and the newer per-LB groups.  Eventually this function can be removed once all LBs have been
// updated with the per-cluster group
func (s *Platform) AddSecurityRuleCIDRWithRetry(ctx context.Context, cidr string, proto string, group string, port string, serverName string) error {
	err := s.AddSecurityRuleCIDR(ctx, cidr, proto, group, port)
	if err != nil {
		if strings.Contains(err.Error(), "No SecurityGroup found") {
			// it is possible this RootLB was created before the change to per-LB security groups.  Create the group separately
			log.SpanLog(ctx, log.DebugLevelMexos, "security group does not exist, creating it", "groupName", group)

			// LB can have multiple ports attached.  We need to assign this SG to the external network port only
			ports, err := s.ListPortsServerNetwork(ctx, serverName, s.GetCloudletExternalNetwork())
			if err != nil {
				return err
			}
			if len(ports) != 1 {
				return fmt.Errorf("Could find external network ports to add security group")
			}
			err = s.CreateSecurityGroup(ctx, group)
			if err != nil {
				return err
			}
			err = s.AddSecurityGroupToPort(ctx, ports[0].ID, group)
			if err != nil {
				return err
			}
			// try again to add the rule
			return s.AddSecurityRuleCIDR(ctx, cidr, proto, group, port)
		}
	}
	return err
}

func (s *Platform) DeleteProxySecurityGroupRules(ctx context.Context, client ssh.Client, name string, groupName string, ports []dme.AppPort, app *edgeproto.App, serverName string) error {
	log.SpanLog(ctx, log.DebugLevelMexos, "DeleteProxySecurityGroupRules", "name", name, "ports", ports)
	if app.InternalPorts {
		log.SpanLog(ctx, log.DebugLevelMexos, "app is internal, nothing to delete")
		return nil
	}
	err := proxy.DeleteNginxProxy(ctx, client, name)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelMexos, "cannot delete proxy", "name", name, "error", err)
	}
	allowedClientCIDR := mexos.GetAllowedClientCIDR()
	rules, err := s.ListSecurityGroupRules(ctx, groupName)
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
				if err := s.DeleteSecurityGroupRule(ctx, r.ID); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

type ProxyDnsSecOpts struct {
	AddProxy              bool
	AddDnsAndPatchKubeSvc bool
	AddSecurityRules      bool
}

// AddProxySecurityRulesAndPatchDNS Adds security rules and dns records in parallel
func (s *Platform) AddProxySecurityRulesAndPatchDNS(ctx context.Context, client ssh.Client, kubeNames *k8smgmt.KubeNames, app *edgeproto.App, appInst *edgeproto.AppInst, getDnsSvcAction mexos.GetDnsSvcActionFunc, rootLBName, listenIP, backendIP string, ops ProxyDnsSecOpts, vaultConfig *vault.Config, proxyops ...proxy.Op) error {
	secchan := make(chan string)
	dnschan := make(chan string)
	proxychan := make(chan string)

	log.SpanLog(ctx, log.DebugLevelMexos, "AddProxySecurityRulesAndPatchDNS", "appname", kubeNames.AppName, "rootLBName", rootLBName, "listenIP", listenIP, "backendIP", backendIP, "ops", ops)
	if len(appInst.MappedPorts) == 0 {
		log.SpanLog(ctx, log.DebugLevelMexos, "no ports for application, no DNS, LB or Security rules needed", "appname", kubeNames.AppName)
		return nil
	}
	configs := append(app.Configs, appInst.Configs...)
	aac, err := access.GetAppAccessConfig(ctx, configs)
	if err != nil {
		return err
	}
	go func() {
		if ops.AddProxy {
			// TODO update certs once AppAccessConfig functionality is added back
			/*if aac.LbTlsCertCommonName != "" {
			        ... get cert here
			}*/
			proxyerr := proxy.CreateNginxProxy(ctx, client, dockermgmt.GetContainerName(&app.Key), listenIP, backendIP, appInst.MappedPorts, proxyops...)
			if proxyerr == nil {
				proxychan <- ""
			} else {
				proxychan <- proxyerr.Error()
			}
		} else {
			proxychan <- ""
		}
	}()
	go func() {
		if ops.AddSecurityRules {
			err := s.AddSecurityRules(ctx, GetSecurityGroupName(ctx, rootLBName), appInst.MappedPorts, rootLBName)
			if err == nil {
				secchan <- ""
			} else {
				secchan <- err.Error()
			}
		} else {
			secchan <- ""
		}
	}()
	go func() {
		if ops.AddDnsAndPatchKubeSvc {
			err := s.commonPf.CreateAppDNSAndPatchKubeSvc(ctx, client, kubeNames, aac.DnsOverride, getDnsSvcAction)
			if err == nil {
				dnschan <- ""
			} else {
				dnschan <- err.Error()
			}
		} else {
			dnschan <- ""
		}
	}()
	proxyerr := <-proxychan
	secerr := <-secchan
	dnserr := <-dnschan

	if proxyerr != "" || secerr != "" || dnserr != "" {
		return fmt.Errorf("AddProxySecurityRulesAndPatchDNS error -- proxyerr: %v secerr: %v dnserr: %v", proxyerr, secerr, dnserr)
	}
	return nil
}
