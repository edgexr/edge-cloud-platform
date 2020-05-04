package infracommon

import (
	"context"
	"fmt"

	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	ssh "github.com/mobiledgex/golang-ssh"
)

func GetLocalKconfName(clusterInst *edgeproto.ClusterInst) string {
	kconf := fmt.Sprintf("%s/%s", MEXDir(), k8smgmt.GetKconfName(clusterInst))
	return kconf
}

//CopyKubeConfig copies over kubeconfig from the cluster
func CopyKubeConfig(ctx context.Context, rootLBClient ssh.Client, clusterInst *edgeproto.ClusterInst, rootLBName, masterIP string) error {
	kconfname := k8smgmt.GetKconfName(clusterInst)
	log.SpanLog(ctx, log.DebugLevelInfra, "attempt to get kubeconfig from k8s master", "masterIP", masterIP, "dest", kconfname)
	cmd := fmt.Sprintf("scp -o %s -o %s -i %s %s@%s:.kube/config %s", SSHOpts[0], SSHOpts[1], SSHPrivateKeyName, SSHUser, masterIP, kconfname)
	out, err := rootLBClient.Output(cmd)
	if err != nil {
		return fmt.Errorf("can't copy kubeconfig via cmd %s, %s, %v", cmd, out, err)
	}
	cmd = fmt.Sprintf("cat %s", kconfname)
	out, err = rootLBClient.Output(cmd)
	if err != nil {
		return fmt.Errorf("can't cat %s, %s, %v", kconfname, out, err)
	}
	//TODO generate per proxy password and record in vault
	//port, serr := StartKubectlProxy(mf, rootLB, name, kconfname)
	//if serr != nil {
	//	return serr
	//}
	return nil
}
