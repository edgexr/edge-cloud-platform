package vmlayer

import (
	"context"
	"fmt"

	"github.com/mobiledgex/edge-cloud-infra/infracommon"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/access"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/dockermgmt"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/proxy"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

// GetServerSecurityGroupName gets the secgrp name based on the server name
func GetServerSecurityGroupName(serverName string) string {
	return serverName + "-sg"
}

// AddProxySecurityRulesAndPatchDNS Adds security rules and dns records in parallel
func (v *VMPlatform) AddProxySecurityRulesAndPatchDNS(ctx context.Context, client ssh.Client, kubeNames *k8smgmt.KubeNames, app *edgeproto.App, appInst *edgeproto.AppInst, getDnsSvcAction infracommon.GetDnsSvcActionFunc, rootLBName, listenIP, backendIP string, ops ProxyDnsSecOpts, proxyops ...proxy.Op) error {
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
			proxyerr := proxy.CreateNginxProxy(ctx, client, dockermgmt.GetContainerName(&app.Key), listenIP, backendIP, appInst.MappedPorts, app.SkipHcPorts, proxyops...)
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
			err := v.VMProvider.WhitelistSecurityRules(ctx, client, GetServerSecurityGroupName(rootLBName), rootLBName, GetAppWhitelistRulesLabel(app), GetAllowedClientCIDR(), appInst.MappedPorts)
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
			err := v.VMProperties.CommonPf.CreateAppDNSAndPatchKubeSvc(ctx, client, kubeNames, aac.DnsOverride, getDnsSvcAction)
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
