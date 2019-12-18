package mexos

import (
	"context"
	"fmt"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/proxy"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

// AddProxySecurityRulesAndPatchDNS Adds security rules and dns records in parallel
func AddProxySecurityRulesAndPatchDNS(ctx context.Context, client pc.PlatformClient, kubeNames *k8smgmt.KubeNames, appInst *edgeproto.AppInst, getDnsSvcAction GetDnsSvcActionFunc, rootLBName, masterIP string, addProxy bool, ops ...proxy.Op) error {
	secchan := make(chan string)
	dnschan := make(chan string)
	proxychan := make(chan string)

	if len(appInst.MappedPorts) == 0 {
		log.SpanLog(ctx, log.DebugLevelMexos, "no ports for application, no DNS, LB or Security rules needed", "appname", kubeNames.AppName)
		return nil
	}
	go func() {
		if addProxy {
			err := proxy.CreateNginxProxy(ctx, client, kubeNames.AppName, masterIP, appInst.MappedPorts, ops...)
			if err == nil {
				proxychan <- ""
			} else {
				proxychan <- err.Error()
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
		err := CreateAppDNS(ctx, client, kubeNames, getDnsSvcAction)
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
