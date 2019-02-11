package mexos

import (
	"fmt"
	"regexp"

	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

func DeleteHelmAppInst(rootLB *MEXRootLB, kubeNames *KubeNames, clusterInst *edgeproto.ClusterInst, kubeManifest string) error {
	log.DebugLog(log.DebugLevelMexos, "delete kubernetes helm app")

	var err error
	if rootLB == nil {
		return fmt.Errorf("cannot delete helm app, rootLB is null")
	}
	kp, err := ValidateKubernetesParameters(rootLB, kubeNames, clusterInst)
	if err != nil {
		return err
	}
	if CloudletIsLocalDIND() {
		// remove DNS entries
		if err = deleteAppDNS(kp, kubeNames.appURI, kubeNames.appName); err != nil {
			log.DebugLog(log.DebugLevelMexos, "warning, cannot delete DNS record", "error", err)
		}
	} else {
		// remove DNS entries
		if err = KubeDeleteDNSRecords(rootLB, kp, kubeNames.appURI, kubeNames.appName); err != nil {
			log.DebugLog(log.DebugLevelMexos, "warning, cannot delete DNS record", "error", err)
		}
		// remove Security rules
		if err = DeleteProxySecurityRules(rootLB, kp.ipaddr, kubeNames.appName); err != nil {
			log.DebugLog(log.DebugLevelMexos, "warning, cannot delete security rules", "error", err)
		}
	}

	cmd := fmt.Sprintf("%s helm delete --purge %s", kp.kubeconfig, kubeNames.appName)
	out, err := kp.client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error deleting helm chart, %s, %s, %v", cmd, out, err)
	}
	log.DebugLog(log.DebugLevelMexos, "removed helm chart")
	return nil
}

func CreateHelmAppInst(rootLB *MEXRootLB, kubeNames *KubeNames, appInst *edgeproto.AppInst, clusterInst *edgeproto.ClusterInst, kubeManifest string) error {
	log.DebugLog(log.DebugLevelMexos, "create kubernetes helm app", "clusterInst", clusterInst, "kubeNames", kubeNames)

	var err error

	if rootLB == nil {
		return fmt.Errorf("cannot create helm app, rootLB is null")
	}
	kp, err := ValidateKubernetesParameters(rootLB, kubeNames, clusterInst)
	if err != nil {
		return err
	}
	log.DebugLog(log.DebugLevelMexos, "will launch app into cluster", "kubeconfig", kp.kubeconfig, "ipaddr", kp.ipaddr)

	// install helm if it's not installed yet
	cmd := fmt.Sprintf("%s helm version", kp.kubeconfig)
	out, err := kp.client.Output(cmd)
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "installing helm into cluster", "kubeconfig", kp.kubeconfig, "ipaddr", kp.ipaddr)

		// Add service account for tiller
		cmd := fmt.Sprintf("%s kubectl create serviceaccount --namespace kube-system tiller", kp.kubeconfig)
		out, err := kp.client.Output(cmd)
		if err != nil {
			return fmt.Errorf("error creating tiller service account, %s, %s, %v", cmd, out, err)
		}
		log.DebugLog(log.DebugLevelMexos, "setting serice acct", "kubeconfig", kp.kubeconfig, "ipaddr", kp.ipaddr)

		cmd = fmt.Sprintf("%s kubectl create clusterrolebinding tiller-cluster-rule --clusterrole=cluster-admin --serviceaccount=kube-system:tiller", kp.kubeconfig)
		out, err = kp.client.Output(cmd)
		if err != nil {
			return fmt.Errorf("error creating role binding, %s, %s, %v", cmd, out, err)
		}

		cmd = fmt.Sprintf("%s helm init --wait --service-account tiller", kp.kubeconfig)
		out, err = kp.client.Output(cmd)
		if err != nil {
			return fmt.Errorf("error initializing tiller for app, %s, %s, %v", cmd, out, err)
		}
		log.DebugLog(log.DebugLevelMexos, "helm tiller initialized")
	}

	helmOpts := ""
	// XXX This gets helm's prometheus able to query kubelet metrics.
	// This can be removed once Lev passes in an option in the yaml to
	// set the helm command line options.
	prom, err := regexp.MatchString("prometheus", kubeNames.appName)
	if err == nil && prom {
		log.DebugLog(log.DebugLevelMexos, "setting helm prometheus option")
		helmOpts = "--set kubelet.serviceMonitor.https=true"
	}
	cmd = fmt.Sprintf("%s helm install %s --name %s %s", kp.kubeconfig, kubeNames.appImage, kubeNames.appName, helmOpts)
	out, err = kp.client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error deploying helm chart, %s, %s, %v", cmd, out, err)
	}
	log.DebugLog(log.DebugLevelMexos, "applied helm chart")
	if CloudletIsLocalDIND() {
		// Add DNS Zone
		if err = createAppDNS(kp, kubeNames.appURI, kubeNames.appName); err != nil {
			log.DebugLog(log.DebugLevelMexos, "cannot add DNS entries", "error", err)
			return err
		}
	} else {
		// Add security rules
		if err = AddProxySecurityRules(rootLB, kp.ipaddr, kubeNames.appName, appInst); err != nil {
			log.DebugLog(log.DebugLevelMexos, "cannot create security rules", "error", err)
			return err
		}
		log.DebugLog(log.DebugLevelMexos, "done AddProxySecurityRules", "kubeNames.appName", kubeNames.appName)
		// Add DNS Zone
		if err = KubeAddDNSRecords(rootLB, kp, appInst.Uri, kubeNames.appName); err != nil {
			log.DebugLog(log.DebugLevelMexos, "cannot add DNS entries", "error", err)
			return err
		}
	}
	return nil
}
