package mexos

import (
	"fmt"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

// AddProxySecurityRulesAndPatchDNS Adds security rules and dns records in parallel
func AddProxySecurityRulesAndPatchDNS(client pc.PlatformClient, kubeNames *k8smgmt.KubeNames, appInst *edgeproto.AppInst, getDnsSvcAction GetDnsSvcActionFunc, rootLBName, masterIP string) error {
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
		err = AddNginxProxy(rootLBName, kubeNames.AppName, masterIP, ports, "")
		if err == nil {
			proxychan <- ""
		} else {
			proxychan <- err.Error()
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
		if proxyerr == "" {
			// delete the nginx proxy if it worked but something else failed because it can cause subequent attempts to fail
			// cleanup of security rules and DNS we should do but not as important
			err := DeleteNginxProxy(rootLBName, kubeNames.AppName)
			if err != nil {
				log.InfoLog("cleanup nginx proxy Failed", "err", err)
			}
		}
		return fmt.Errorf("AddProxySecurityRulesAndPatchDNS error -- proxyerr: %v secerr: %v dnserr: %v", proxyerr, secerr, dnserr)
	}
	return nil
}
