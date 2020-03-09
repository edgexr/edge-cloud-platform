package mexos

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/access"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/dockermgmt"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/proxy"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vault"
	ssh "github.com/mobiledgex/golang-ssh"
)

type ProxyDnsSecOpts struct {
	AddProxy              bool
	AddDnsAndPatchKubeSvc bool
	AddSecurityRules      bool
}

// AddProxySecurityRulesAndPatchDNS Adds security rules and dns records in parallel
func AddProxySecurityRulesAndPatchDNS(ctx context.Context, client ssh.Client, kubeNames *k8smgmt.KubeNames, app *edgeproto.App, appInst *edgeproto.AppInst, getDnsSvcAction GetDnsSvcActionFunc, rootLBName, listenIP, backendIP string, ops ProxyDnsSecOpts, vaultConfig *vault.Config, proxyops ...proxy.Op) error {
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
			err := AddSecurityRules(ctx, GetSecurityGroupName(ctx, rootLBName), appInst.MappedPorts, rootLBName)
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
			err := CreateAppDNSAndPatchKubeSvc(ctx, client, kubeNames, aac.DnsOverride, getDnsSvcAction)
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

// TODO collapse common keys into a single entry with multi-part values ex: "hw"
// (We don't use this property values today, but perhaps in the future)
func ParseFlavorProperties(f OSFlavorDetail) map[string]string {

	var props map[string]string

	ms := strings.Split(f.Properties, ",")
	props = make(map[string]string)
	for _, m := range ms {
		// ex: pci_passthrough:alias='t4gpu:1’
		val := strings.Split(m, ":")
		if len(val) > 1 {
			val[0] = strings.TrimSpace(val[0])
			var s []string
			for i := 1; i < len(val); i++ {
				val[i] = strings.Replace(val[i], "'", "", -1)
				if _, err := strconv.Atoi(val[i]); err == nil {
					s = append(s, ":")
				}
				s = append(s, val[i])
			}
			props[val[0]] = strings.Join(s, "")
		}

	}
	return props
}

// 5GB = 10minutes
func GetTimeout(cLen int) time.Duration {
	fileSizeInGB := float64(cLen) / (1024.0 * 1024.0 * 1024.0)
	timeoutUnit := int(math.Ceil(fileSizeInGB / 5.0))
	if fileSizeInGB > 5 {
		return time.Duration(timeoutUnit) * 10 * time.Minute
	}
	return 10 * time.Minute
}
