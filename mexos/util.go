package mexos

import (
	"fmt"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/nginx"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

// AddProxySecurityRulesAndPatchDNS Adds security rules and dns records in parallel
func AddProxySecurityRulesAndPatchDNS(client pc.PlatformClient, kubeNames *k8smgmt.KubeNames, appInst *edgeproto.AppInst, getDnsSvcAction GetDnsSvcActionFunc, rootLBName, masterIP string, addProxy bool, ops ...nginx.Op) error {
	secchan := make(chan string)
	dnschan := make(chan string)
	proxychan := make(chan string)

	if len(appInst.MappedPorts) == 0 {
		log.DebugLog(log.DebugLevelMexos, "no ports for application, no DNS, LB or Security rules needed", "appname", kubeNames.AppName)
		return nil
	}
	go func() {
		if addProxy {
			err := nginx.CreateNginxProxy(client, kubeNames.AppName, masterIP, appInst.MappedPorts, ops...)
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
		err := AddSecurityRules(appInst.MappedPorts)
		if err == nil {
			secchan <- ""
		} else {
			secchan <- err.Error()
		}
	}()
	go func() {
		err := CreateAppDNS(client, kubeNames, getDnsSvcAction)
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
