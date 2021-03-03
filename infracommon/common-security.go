package infracommon

import (
	"context"
	"fmt"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/access"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/dockermgmt"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/proxy"
	dme "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/edgeproto"

	"github.com/mobiledgex/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

type WhiteListFunc func(ctx context.Context, client ssh.Client, secGrpName string, serverName, label, allowedCIDR string, ports []dme.AppPort) error

type ProxyDnsSecOpts struct {
	AddProxy              bool
	AddDnsAndPatchKubeSvc bool
	AddSecurityRules      bool
	ProxyNamePrefix       string
}

const RemoteCidrAll = "0.0.0.0/0"
const RemoteCidrNone = "0.0.0.0/32"

func GetAllowedClientCIDR() string {
	return RemoteCidrAll
}

func GetAppWhitelistRulesLabel(app *edgeproto.App) string {
	return "appaccess-" + k8smgmt.NormalizeName(app.Key.Name)
}

// GetServerSecurityGroupName gets the secgrp name based on the server name
func GetServerSecurityGroupName(serverName string) string {
	return serverName + "-sg"
}

// AddProxySecurityRulesAndPatchDNS Adds security rules and dns records in parallel
func (c *CommonPlatform) AddProxySecurityRulesAndPatchDNS(ctx context.Context, client ssh.Client, kubeNames *k8smgmt.KubeNames, app *edgeproto.App, appInst *edgeproto.AppInst, getDnsSvcAction GetDnsSvcActionFunc, whiteListAdd WhiteListFunc, rootLBName, listenIP, backendIP string, ops ProxyDnsSecOpts, proxyops ...proxy.Op) error {
	secchan := make(chan string)
	dnschan := make(chan string)
	proxychan := make(chan string)

	log.SpanLog(ctx, log.DebugLevelInfra, "AddProxySecurityRulesAndPatchDNS", "appname", kubeNames.AppName, "rootLBName", rootLBName, "listenIP", listenIP, "backendIP", backendIP, "ops", ops)
	if len(appInst.MappedPorts) == 0 {
		log.SpanLog(ctx, log.DebugLevelInfra, "no ports for application, no DNS, LB or Security rules needed", "appname", kubeNames.AppName)
		return nil
	}
	configs := append(app.Configs, appInst.Configs...)
	aac, err := access.GetAppAccessConfig(ctx, configs, app.TemplateDelimiter)
	if err != nil {
		return err
	}
	go func() {
		if ops.AddProxy {
			// TODO update certs once AppAccessConfig functionality is added back
			/*if aac.LbTlsCertCommonName != "" {
			        ... get cert here
			}*/
			containerName := ops.ProxyNamePrefix + dockermgmt.GetContainerName(&app.Key)
			proxyerr := proxy.CreateNginxProxy(ctx, client, containerName, listenIP, backendIP, appInst.MappedPorts, app.SkipHcPorts, proxyops...)
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
			err := whiteListAdd(ctx, client, GetServerSecurityGroupName(rootLBName), rootLBName, GetAppWhitelistRulesLabel(app), GetAllowedClientCIDR(), appInst.MappedPorts)
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
			err := c.CreateAppDNSAndPatchKubeSvc(ctx, client, kubeNames, aac.DnsOverride, getDnsSvcAction)
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

func (c *CommonPlatform) DeleteProxySecurityGroupRules(ctx context.Context, client ssh.Client, proxyName string, secGrpName string, label string, ports []dme.AppPort, app *edgeproto.App, serverName string, whiteListDel WhiteListFunc) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "DeleteProxySecurityGroupRules", "proxyName", proxyName, "ports", ports)

	err := proxy.DeleteNginxProxy(ctx, client, proxyName)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "cannot delete proxy", "proxyName", proxyName, "error", err)
	}
	allowedClientCIDR := GetAllowedClientCIDR()
	return whiteListDel(ctx, client, secGrpName, serverName, label, allowedClientCIDR, ports)
}
