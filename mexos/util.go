package mexos

import (
	"fmt"

	"github.com/mobiledgex/edge-cloud/edgeproto"
)

// AddProxySecurityRulesAndPatchDNS Adds security rules and dns records in parallel
func AddProxySecurityRulesAndPatchDNS(rootLB *MEXRootLB, kp *kubeParam, kubeNames *KubeNames, appInst *edgeproto.AppInst) error {
	secchan := make(chan string)
	dnschan := make(chan string)

	go func() {
		err := AddProxySecurityRules(rootLB, kp.ipaddr, kubeNames.appName, appInst)
		if err == nil {
			secchan <- ""
		} else {
			secchan <- err.Error()
		}
	}()
	go func() {
		err := KubePatchSvcAddDNSRecords(rootLB, kp, kubeNames)
		if err == nil {
			dnschan <- ""
		} else {
			dnschan <- err.Error()
		}
	}()
	secerr := <-secchan
	dnserr := <-dnschan

	if secerr != "" || dnserr != "" {
		return fmt.Errorf("AddProxySecurityRulesAndPatchDNS error -- secerr: %v dnserr: %v", secerr, dnserr)
	}
	return nil
}
