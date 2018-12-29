package mexos

import (
	"fmt"

	"github.com/mobiledgex/edge-cloud/log"
)

func DeleteHelmAppManifest(mf *Manifest) error {
	log.DebugLog(log.DebugLevelMexos, "delete kubernetes helm app")
	rootLB, err := getRootLB(mf.Spec.RootLB)
	if err != nil {
		return err
	}
	if rootLB == nil {
		return fmt.Errorf("cannot delete helm app, rootLB is null")
	}
	if err = ValidateCommon(mf); err != nil {
		return err
	}
	kp, err := ValidateKubernetesParameters(mf, rootLB, mf.Spec.Key)
	if err != nil {
		return err
	}
	// remove DNS entries
	if err = KubeDeleteDNSRecords(rootLB, mf, kp); err != nil {
		log.DebugLog(log.DebugLevelMexos, "warning, cannot delete DNS record", "error", err)
	}
	// remove Security rules
	if err = DeleteProxySecurityRules(rootLB, mf, kp.ipaddr); err != nil {
		log.DebugLog(log.DebugLevelMexos, "warning, cannot delete security rules", "error", err)
	}
	cmd := fmt.Sprintf("%s helm delete %s", kp.kubeconfig, mf.Metadata.Name)
	out, err := kp.client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error deleting helm chart, %s, %s, %v", cmd, out, err)
	}
	log.DebugLog(log.DebugLevelMexos, "removed helm chart")
	return nil
}

func CreateHelmAppManifest(mf *Manifest) error {
	log.DebugLog(log.DebugLevelMexos, "create kubernetes helm app")
	rootLB, err := getRootLB(mf.Spec.RootLB)
	if err != nil {
		return err
	}
	if rootLB == nil {
		return fmt.Errorf("cannot create helm app, rootLB is null")
	}
	if err = ValidateCommon(mf); err != nil {
		return err
	}
	kp, err := ValidateKubernetesParameters(mf, rootLB, mf.Spec.Key)
	if err != nil {
		return err
	}
	log.DebugLog(log.DebugLevelMexos, "will launch app into cluster", "kubeconfig", kp.kubeconfig, "ipaddr", kp.ipaddr)

	cmd := fmt.Sprintf("%s helm init --wait", kp.kubeconfig)
	out, err := kp.client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error initializing tiller for app, %s, %s, %v", cmd, out, err)
	}
	log.DebugLog(log.DebugLevelMexos, "helm tiller initialized")

	cmd = fmt.Sprintf("%s helm install %s --name %s", kp.kubeconfig, mf.Spec.Image, mf.Metadata.Name)
	out, err = kp.client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error deploying helm chart, %s, %s, %v", cmd, out, err)
	}
	log.DebugLog(log.DebugLevelMexos, "applied helm chart")
	// Add security rules
	if err = AddProxySecurityRules(rootLB, mf, kp.ipaddr); err != nil {
		log.DebugLog(log.DebugLevelMexos, "cannot create security rules", "error", err)
		return err
	}
	log.DebugLog(log.DebugLevelMexos, "add spec ports", "ports", mf.Spec.Ports)
	// Add DNS Zone
	if err = KubeAddDNSRecords(rootLB, mf, kp); err != nil {
		log.DebugLog(log.DebugLevelMexos, "cannot add DNS entries", "error", err)
		return err
	}
	return nil
}
