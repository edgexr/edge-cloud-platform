package mexos

import (
	"fmt"
	"strings"
	"time"

	"github.com/mobiledgex/edge-cloud/log"
)

//StartKubectlProxy starts kubectl proxy on the rootLB to handle kubectl commands remotely.
//  To be called after copying over the kubeconfig file from cluster to rootLB.
func StartKubectlProxy(mf *Manifest, rootLB *MEXRootLB, kubeconfig string) (int, error) {
	log.DebugLog(log.DebugLevelMexos, "start kubectl proxy", "kubeconfig", kubeconfig)
	if rootLB == nil {
		return 0, fmt.Errorf("cannot kubectl proxy, rootLB is null")
	}
	if mf.Values.Network.External == "" {
		return 0, fmt.Errorf("start kubectl proxy, missing external network in platform config")
	}
	client, err := GetSSHClient(mf, rootLB.Name, mf.Values.Network.External, sshUser)
	if err != nil {
		return 0, err
	}
	maxPort := 8000
	cmd := "sudo ps wwh -C kubectl -o args"
	out, err := client.Output(cmd)
	if err == nil && out != "" {
		lines := strings.Split(out, "\n")
		for _, ln := range lines {
			portnum := parseKCPort(ln)
			if portnum > maxPort {
				maxPort = portnum
			}
		}
	}
	maxPort++
	log.DebugLog(log.DebugLevelMexos, "port for kubectl proxy", "maxport", maxPort)
	cmd = fmt.Sprintf("kubectl proxy  --port %d --accept-hosts='.*' --address='0.0.0.0' --kubeconfig=%s ", maxPort, kubeconfig)
	//Use .Start() because we don't want to hang
	cl1, cl2, err := client.Start(cmd)
	if err != nil {
		return 0, fmt.Errorf("error running kubectl proxy, %s,  %v", cmd, err)
	}
	cl1.Close() //nolint
	cl2.Close() //nolint
	err = AddSecurityRuleCIDR(mf, GetAllowedClientCIDR(), "tcp", GetMEXSecurityRule(mf), maxPort)
	log.DebugLog(log.DebugLevelMexos, "adding external ingress security rule for kubeproxy", "port", maxPort)
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "warning, error while adding external ingress security rule for kubeproxy", "error", err, "port", maxPort)
	}

	cmd = "sudo ps wwh -C kubectl -o args"
	for i := 0; i < 5; i++ {
		//verify
		out, outerr := client.Output(cmd)
		if outerr == nil {
			if out == "" {
				continue
			}
			lines := strings.Split(out, "\n")
			for _, ln := range lines {
				if parseKCPort(ln) == maxPort {
					log.DebugLog(log.DebugLevelMexos, "kubectl confirmed running with port", "port", maxPort)
				}
			}
			return maxPort, nil
		}
		log.DebugLog(log.DebugLevelMexos, "waiting for kubectl proxy...")
		time.Sleep(3 * time.Second)
	}
	return 0, fmt.Errorf("timeout error verifying kubectl proxy")
}
