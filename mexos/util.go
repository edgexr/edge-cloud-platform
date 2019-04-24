package mexos

import (
	"fmt"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

// AddProxySecurityRulesAndPatchDNS Adds security rules and dns records in parallel
func AddProxySecurityRulesAndPatchDNS(client pc.PlatformClient, kubeNames *k8smgmt.KubeNames, appInst *edgeproto.AppInst, getDnsSvcAction GetDnsSvcActionFunc, rootLBName, masterIP string, addProxy bool) error {
	secchan := make(chan string)
	dnschan := make(chan string)
	proxychan := make(chan string)

	ports, err := GetPortDetail(appInst)
	if err != nil {
		return err
	}
	if len(ports) == 0 {
		log.DebugLog(log.DebugLevelMexos, "no ports for application, no DNS, LB or Security rules needed", "appname", kubeNames.AppName)
		return nil
	}
	go func() {
		if addProxy {
			err = AddNginxProxy(rootLBName, kubeNames.AppName, masterIP, ports, "")
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
		err := AddSecurityRules(ports)
		if err == nil {
			secchan <- ""
		} else {
			secchan <- err.Error()
		}
	}()
	go func() {
		err := CreateAppDNS(client, kubeNames, getDnsSvcAction)
		//err := KubePatchSvcAddDNSRecords(rootLB, kp, kubeNames)
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
