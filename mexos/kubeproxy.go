package mexos

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/mobiledgex/edge-cloud/log"
)

var kcproxySuffix = "-kcproxy"

//StartKubectlProxy starts kubectl proxy on the rootLB to handle kubectl commands remotely.
//  To be called after copying over the kubeconfig file from cluster to rootLB.
func StartKubectlProxy(rootLB *MEXRootLB, name, kubeconfig string) (int, error) {
	log.DebugLog(log.DebugLevelMexos, "start kubectl proxy", "name", name, "kubeconfig", kubeconfig)
	if rootLB == nil {
		return 0, fmt.Errorf("cannot kubectl proxy, rootLB is null")
	}
	if GetCloudletExternalNetwork() == "" {
		return 0, fmt.Errorf("start kubectl proxy, missing external network in platform config")
	}
	client, err := GetSSHClient(rootLB.Name, GetCloudletExternalNetwork(), sshUser)
	if err != nil {
		return 0, err
	}
	//TODO check /home/ubuntu/.docker-pass file
	cmd := fmt.Sprintf("echo %s | docker login -u mobiledgex --password-stdin %s", GetCloudletDockerPass(), GetCloudletDockerRegistry())
	out, err := client.Output(cmd)
	if err != nil {
		return 0, fmt.Errorf("can't docker login, %s, %v", out, err)
	}
	cmd = fmt.Sprintf("docker pull registry.mobiledgex.net:5000/mobiledgex/mobiledgex")
	res, err := client.Output(cmd)
	if err != nil {
		return 0, fmt.Errorf("cannot pull mobiledgex image, %v, %s", err, res)
	}
	//TODO verify existence of kubeconfig file
	containerName := name + kcproxySuffix
	cmd = fmt.Sprintf("docker run --net host  -d --rm -it -v /home:/home --name %s registry.mobiledgex.net:5000/mobiledgex/mobiledgex kubectl proxy --port 0 --accept-hosts '^127.0.0.1$' --address 127.0.0.1 --kubeconfig /home/ubuntu/%s", containerName, kubeconfig)
	res, err = client.Output(cmd)
	if err != nil {
		return 0, fmt.Errorf("error running kubectl proxy, %s,  %v, %s", cmd, err, res)
	}
	res, err = client.Output(fmt.Sprintf("docker logs %s", containerName))
	if err != nil {
		return 0, fmt.Errorf("cannot get logs for container %s", containerName)
	}
	items := strings.Split(res, " ")
	if len(items) < 5 {
		return 0, fmt.Errorf("insufficient address info in log output, %s", res)
	}
	addr := items[4]
	addr = strings.TrimSpace(addr)
	items = strings.Split(addr, ":")
	if len(items) < 2 {
		return 0, fmt.Errorf("cannot get port from %s", addr)
	}
	port := items[1]
	portnum, aerr := strconv.Atoi(port)
	if aerr != nil {
		return 0, fmt.Errorf("cannot convert port %v, %s", aerr, port)
	}
	log.DebugLog(log.DebugLevelMexos, "adding external ingress security rule for kubeproxy", "port", port)
	err = AddSecurityRuleCIDR(GetAllowedClientCIDR(), "tcp", GetCloudletSecurityRule(), portnum+1) //XXX
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "warning, error while adding external ingress security rule for kubeproxy", "error", err, "port", port)
	}
	portnum++
	//TODO delete security rule when kubectl proxy container deleted
	if err := AddNginxKubectlProxy(rootLB.Name, name, portnum); err != nil {
		return 0, fmt.Errorf("cannot add nginx kubectl proxy, %v", err)
	}
	log.DebugLog(log.DebugLevelMexos, "nginx kubectl proxy", "port", portnum)
	return portnum, nil
}
