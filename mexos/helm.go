package mexos

import (
	"fmt"

	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

func DeleteHelmAppInst(rootLB *MEXRootLB, clusterInst *edgeproto.ClusterInst, kubeManifest string, app *edgeproto.App, appInst *edgeproto.AppInst) error {
	log.DebugLog(log.DebugLevelMexos, "delete kubernetes helm app")

	clusterName := clusterInst.Key.ClusterKey.Name
	appName := NormalizeName(app.Key.Name)

	kp, err := ValidateKubernetesParameters(clusterInst, rootLB, clusterName)
	if err != nil {
		return err
	}
	// remove DNS entries
	if err = KubeDeleteDNSRecords(rootLB, kp, appInst.Uri, appName); err != nil {
		log.DebugLog(log.DebugLevelMexos, "warning, cannot delete DNS record", "error", err)
	}
	// remove Security rules
	if err = DeleteProxySecurityRules(rootLB, kp.ipaddr, appInst); err != nil {
		log.DebugLog(log.DebugLevelMexos, "warning, cannot delete security rules", "error", err)
	}
	cmd := fmt.Sprintf("%s helm delete --purge %s", kp.kubeconfig, appName)
	out, err := kp.client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error deleting helm chart, %s, %s, %v", cmd, out, err)
	}
	log.DebugLog(log.DebugLevelMexos, "removed helm chart")
	return nil
}

func CreateHelmAppInst(rootLB *MEXRootLB, clusterInst *edgeproto.ClusterInst, kubeManifest string, app *edgeproto.App, appInst *edgeproto.AppInst) error {
	log.DebugLog(log.DebugLevelMexos, "create kubernetes helm app", "clusterInst", clusterInst, "appInst", appInst)

	clusterName := clusterInst.Key.ClusterKey.Name
	appName := NormalizeName(app.Key.Name)
	appImage := app.ImagePath

	kp, err := ValidateKubernetesParameters(clusterInst, rootLB, clusterName)
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

	cmd = fmt.Sprintf("%s helm install %s --name %s", kp.kubeconfig, appImage, appName)
	out, err = kp.client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error deploying helm chart, %s, %s, %v", cmd, out, err)
	}
	log.DebugLog(log.DebugLevelMexos, "applied helm chart")
	// Add security rules
	if err = AddProxySecurityRules(rootLB, kp.ipaddr, appInst); err != nil {
		log.DebugLog(log.DebugLevelMexos, "cannot create security rules", "error", err)
		return err
	}

	if err = KubeAddDNSRecords(rootLB, kp, appInst.Uri, appName); err != nil {
		log.DebugLog(log.DebugLevelMexos, "cannot add DNS entries", "error", err)
		return err
	}
	return nil
}
