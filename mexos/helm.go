package mexos

import (
	"fmt"
	"strings"

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
		if err = deleteAppDNS(kp, kubeNames); err != nil {
			log.DebugLog(log.DebugLevelMexos, "warning, cannot delete DNS record", "error", err)
		}
	} else {
		// remove DNS entries
		if err = KubeDeleteDNSRecords(rootLB, kp, kubeNames); err != nil {
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

// concatenate files with a ',' and prepend '-f'
// Example: ["foo.yaml", "bar.yaml", "foobar.yaml"] ---> "-f foo.yaml,bar.yaml,foobar.yaml"
func getHelmYamlOpt(ymls []string) string {
	// empty string
	if len(ymls) == 0 {
		return ""
	}
	return "-f " + strings.Join(ymls, ",")
}

func CreateHelmAppInst(rootLB *MEXRootLB, kubeNames *KubeNames, appInst *edgeproto.AppInst, clusterInst *edgeproto.ClusterInst, kubeManifest string, configs []*edgeproto.ConfigFile) error {
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
		log.DebugLog(log.DebugLevelMexos, "setting service acct", "kubeconfig", kp.kubeconfig, "ipaddr", kp.ipaddr)

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

	// Walk the Configs in the App and generate the yaml files from the helm customization ones
	var ymls []string
	for _, v := range configs {
		if v.Kind == AppConfigHemYaml {
			file, err := WriteConfigFile(kp, kubeNames.appName, v.Config, v.Kind)
			if err != nil {
				return err
			}
			ymls = append(ymls, file)
		}
	}
	helmOpts := getHelmYamlOpt(ymls)
	log.DebugLog(log.DebugLevelMexos, "Helm options", "helmOpts", helmOpts)
	cmd = fmt.Sprintf("%s helm install %s --name %s %s", kp.kubeconfig, kubeNames.appImage, kubeNames.appName, helmOpts)
	out, err = kp.client.Output(cmd)
	if err != nil {
		return fmt.Errorf("error deploying helm chart, %s, %s, %v", cmd, out, err)
	}
	log.DebugLog(log.DebugLevelMexos, "applied helm chart")
	if CloudletIsLocalDIND() {
		// Add DNS Zone
		if err = createAppDNS(kp, kubeNames); err != nil {
			log.DebugLog(log.DebugLevelMexos, "cannot add DNS entries", "error", err)
			return err
		}
	} else {
		err := AddProxySecurityRulesAndPatchDNS(rootLB, kp, kubeNames, appInst)
		if err != nil {
			return fmt.Errorf("CreateHelmAppInst error: %v", err)
		}
	}

	return nil
}
