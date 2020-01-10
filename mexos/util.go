package mexos

import (
	"context"
	"fmt"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/access"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/proxy"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vault"
)

// AddProxySecurityRulesAndPatchDNS Adds security rules and dns records in parallel
func AddProxySecurityRulesAndPatchDNS(ctx context.Context, client pc.PlatformClient, kubeNames *k8smgmt.KubeNames, app *edgeproto.App, appInst *edgeproto.AppInst, getDnsSvcAction GetDnsSvcActionFunc, rootLBName, masterIP string, addProxy bool, vaultConfig *vault.Config, ops ...proxy.Op) error {
	secchan := make(chan string)
	dnschan := make(chan string)
	proxychan := make(chan string)

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
		if addProxy {
			if aac.LbTlsCertCommonName != "" {
				var tlsCert access.TLSCert
				proxyerr := GetCertFromVault(ctx, vaultConfig, aac.LbTlsCertCommonName, &tlsCert)
				log.SpanLog(ctx, log.DebugLevelMexos, "got cert from vault", "tlsCert", tlsCert, "err", err)
				if proxyerr != nil {
					log.SpanLog(ctx, log.DebugLevelMexos, "Error getting cert from vault", "err", err)
					proxychan <- proxyerr.Error()
					return
				}
				ops = append(ops, proxy.WithTLSCert(&tlsCert))
			}
			proxyerr := proxy.CreateNginxProxy(ctx, client, kubeNames.AppName, masterIP, appInst.MappedPorts, ops...)
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
		err := AddSecurityRules(ctx, GetSecurityGroupName(ctx, rootLBName), appInst.MappedPorts, rootLBName)
		if err == nil {
			secchan <- ""
		} else {
			secchan <- err.Error()
		}
	}()
	go func() {
		err := CreateAppDNS(ctx, client, kubeNames, aac.DnsOverride, getDnsSvcAction)
		if err == nil {
			dnschan <- ""
		} else {
			dnschan <- err.Error()
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
