package mexos

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"

	"github.com/ghodss/yaml"
	"github.com/mobiledgex/edge-cloud-infra/k8s-prov/azure"
	"github.com/mobiledgex/edge-cloud-infra/k8s-prov/dind"
	"github.com/mobiledgex/edge-cloud-infra/k8s-prov/gcloud"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/log"
)

// IsLocalDIND returns true if the cloudlet is a local DIND deploy
func IsLocalDIND(mf *Manifest) bool {
	return mf.Values.Operator.Kind == "localdind"
}

//MEXClusterCreateManifest creates a cluster
func MEXClusterCreateManifest(mf *Manifest) error {
	log.DebugLog(log.DebugLevelMexos, "creating cluster via manifest")
	if IsLocalDIND(mf) {
		return localCreateDIND(mf)
	}
	switch mf.Metadata.Operator {
	case "gcp":
		return gcloudCreateGKE(mf)
	case "azure":
		return azureCreateAKS(mf)
	default:
		//guid, err := mexCreateClusterKubernetes(mf)
		err := mexCreateClusterKubernetes(mf)
		if err != nil {
			return fmt.Errorf("can't create cluster, %v", err)
		}
		//log.DebugLog(log.DebugLevelMexos, "new guid", "guid", *guid)
		log.DebugLog(log.DebugLevelMexos, "created kubernetes cluster")
		return nil
	}
}

//MEXAddFlavor adds flavor using manifest
func MEXAddFlavor(mf *Manifest) error {
	log.DebugLog(log.DebugLevelMexos, "add mex flavor")
	//TODO use full manifest and validate against platform data
	return AddFlavorManifest(mf)
}

// TODO DeleteFlavor -- but almost never done

// TODO lookup guid using name

//MEXClusterRemoveManifest removes a cluster
func MEXClusterRemoveManifest(mf *Manifest) error {
	log.DebugLog(log.DebugLevelMexos, "removing cluster")
	if IsLocalDIND(mf) {
		return dind.DeleteDINDCluster(mf.Metadata.Name)
	}
	switch mf.Metadata.Operator {
	case "gcp":
		return gcloud.DeleteGKECluster(mf.Metadata.Name)
	case "azure":
		return azure.DeleteAKSCluster(mf.Metadata.ResourceGroup)
	default:
		if err := mexDeleteClusterKubernetes(mf); err != nil {
			return fmt.Errorf("can't remove cluster, %v", err)
		}
		return nil
	}
}

//MEXPlatformInitCloudletKey calls MEXPlatformInit with templated manifest
func MEXPlatformInitCloudletKey(rootLB *MEXRootLB, cloudletKeyStr string) error {
	ckmf, err := fillPlatformTemplateCloudletKey(rootLB, cloudletKeyStr)
	if err != nil {
		return err
	}
	ckmf.Values = rootLB.PlatConf.Values
	return MEXPlatformInitManifest(ckmf)
}

//MEXPlatformCleanCloudletKey calls MEXPlatformClean with templated manifest
func MEXPlatformCleanCloudletKey(rootLB *MEXRootLB, cloudletKeyStr string) error {
	mf, err := fillPlatformTemplateCloudletKey(rootLB, cloudletKeyStr)
	if err != nil {
		return err
	}
	return MEXPlatformCleanManifest(mf)
}

//MEXPlatformInitManifest initializes platform
func MEXPlatformInitManifest(mf *Manifest) error {
	log.DebugLog(log.DebugLevelMexos, "init platform")
	err := MEXCheckEnvVars(mf)
	if err != nil {
		return err
	}
	switch mf.Metadata.Operator {
	case "gcp":
		return nil //nothing to do
	case "azure":
		return nil //nothing to do
	default:
		if err = MEXCheckEnvVars(mf); err != nil {
			return err
		}
		//TODO validate all mf content against platform data
		if err = RunMEXAgentManifest(mf); err != nil {
			return err
		}
	}
	return nil
}

//MEXPlatformCleanManifest cleans up the platform
func MEXPlatformCleanManifest(mf *Manifest) error {
	log.DebugLog(log.DebugLevelMexos, "clean platform")
	err := MEXCheckEnvVars(mf)
	if err != nil {
		return err
	}
	switch mf.Metadata.Operator {
	case "gcp":
		return nil //nothing to do
	case "azure":
		return nil
	default:
		if err = MEXCheckEnvVars(mf); err != nil {
			return err
		}
		if err = RemoveMEXAgentManifest(mf); err != nil {
			return err
		}
	}
	return nil
}

//MEXAppCreateAppManifest creates app instances on the cluster platform
func MEXAppCreateAppManifest(mf *Manifest) error {
	log.DebugLog(log.DebugLevelMexos, "create app from manifest")
	appDeploymentType := mf.Config.ConfigDetail.Deployment
	log.DebugLog(log.DebugLevelMexos, "app deployment", "imageType", mf.Spec.ImageType, "deploymentType", appDeploymentType, "config", mf.Config)
	var kubeManifest string
	var err error
	if appDeploymentType == cloudcommon.AppDeploymentTypeKubernetes {
		kubeManifest, err = GetKubeManifest(mf)
		if err != nil {
			return err
		}
		if !strings.HasPrefix(kubeManifest, "apiVersion: v1") {
			log.DebugLog(log.DebugLevelMexos, "bad apiVersion at beginning kubemanifest")
			return fmt.Errorf("bad apiversion at beginning of kube manifest")
		}
	}
	//TODO values.application.template

	if IsLocalDIND(mf) {
		masteraddr := dind.GetMasterAddr()
		log.DebugLog(log.DebugLevelMexos, "call AddNginxProxy for dind")

		if err = AddNginxProxy(mf, "localhost", mf.Metadata.Name, masteraddr, mf.Spec.Ports, dind.GetDockerNetworkName(mf.Values.Cluster.Name)); err != nil {
			log.DebugLog(log.DebugLevelMexos, "cannot add nginx proxy", "name", mf.Metadata.Name, "ports", mf.Spec.Ports)
			return err
		}
		log.DebugLog(log.DebugLevelMexos, "call runKubectlCreateApp for dind")
		err := runKubectlCreateApp(mf, kubeManifest)
		if err != nil {
			log.DebugLog(log.DebugLevelMexos, "error creating dind app", "mf", mf)
			return err
		}
		return nil
	}

	switch mf.Metadata.Operator {
	case "gcp":
		fallthrough
	case "azure":
		if appDeploymentType == cloudcommon.AppDeploymentTypeKubernetes {
			return runKubectlCreateApp(mf, kubeManifest)
		} else if appDeploymentType == cloudcommon.AppDeploymentTypeKVM {
			return fmt.Errorf("not yet supported")
		} else if appDeploymentType == cloudcommon.AppDeploymentTypeHelm {
			return fmt.Errorf("not yet supported")
		} else if appDeploymentType == cloudcommon.AppDeploymentTypeDockerSwarm {
			return fmt.Errorf("not yet supported")
		}
		return fmt.Errorf("unknown deployment type %s", appDeploymentType)
	default:
		if appDeploymentType == cloudcommon.AppDeploymentTypeKubernetes {
			return CreateKubernetesAppManifest(mf, kubeManifest)
		} else if appDeploymentType == cloudcommon.AppDeploymentTypeKVM {
			return CreateQCOW2AppManifest(mf)
		} else if appDeploymentType == cloudcommon.AppDeploymentTypeHelm {
			return CreateHelmAppManifest(mf)
		} else if appDeploymentType == cloudcommon.AppDeploymentTypeDockerSwarm {
			return CreateDockerSwarmAppManifest(mf)
		}
		return fmt.Errorf("unknown deployment type %s", appDeploymentType)
	}
}

//MEXAppDeleteManifest kills app
func MEXAppDeleteAppManifest(mf *Manifest) error {
	log.DebugLog(log.DebugLevelMexos, "delete app with manifest")
	appDeploymentType := mf.Config.ConfigDetail.Deployment
	log.DebugLog(log.DebugLevelMexos, "app delete", "imageType", mf.Spec.ImageType, "deploymentType", appDeploymentType, "config", mf.Config)
	kubeManifest, err := GetKubeManifest(mf)
	if err != nil {
		return err
	}
	if IsLocalDIND(mf) {
		log.DebugLog(log.DebugLevelMexos, "run kubectl delete app for dind")
		err := runKubectlDeleteApp(mf, kubeManifest)
		if err != nil {
			return err
		}

		log.DebugLog(log.DebugLevelMexos, "call DeleteNginxProxy for dind")

		if err = DeleteNginxProxy(mf, "localhost", mf.Metadata.Name); err != nil {
			log.DebugLog(log.DebugLevelMexos, "cannot delete nginx proxy", "name", mf.Metadata.Name)
			return err
		}

		return nil

	}
	switch mf.Metadata.Operator {
	case "gcp":
		fallthrough
	case "azure":
		if appDeploymentType == cloudcommon.AppDeploymentTypeKubernetes {
			return runKubectlDeleteApp(mf, kubeManifest)
		} else if appDeploymentType == cloudcommon.AppDeploymentTypeKVM {
			return fmt.Errorf("not yet supported")
		} else if appDeploymentType == cloudcommon.AppDeploymentTypeHelm {
			return fmt.Errorf("not yet supported")
		} else if appDeploymentType == cloudcommon.AppDeploymentTypeDockerSwarm {
			return fmt.Errorf("not yet supported")
		}
		return fmt.Errorf("unknown image type %s", appDeploymentType)
	default:
		if appDeploymentType == cloudcommon.AppDeploymentTypeKubernetes {
			return DeleteKubernetesAppManifest(mf, kubeManifest)
		} else if appDeploymentType == cloudcommon.AppDeploymentTypeKVM {
			return DeleteQCOW2AppManifest(mf)
		} else if appDeploymentType == cloudcommon.AppDeploymentTypeHelm {
			return DeleteHelmAppManifest(mf)
		} else if appDeploymentType == cloudcommon.AppDeploymentTypeDockerSwarm {
			return DeleteDockerSwarmAppManifest(mf)
		}
		return fmt.Errorf("unknown image type %s", mf.Spec.ImageType)
	}
}

func GetDefaultRegistryBase(mf *Manifest, base string) string {
	mf.Base = base
	if mf.Base == "" {
		mf.Base = fmt.Sprintf("scp://%s/files-repo/mobiledgex", mf.Values.Registry.Name)
	}
	log.DebugLog(log.DebugLevelMexos, "default registry base", "base", mf.Base)
	return mf.Base
}

func FillManifestValues(mf *Manifest, kind, base string) error {
	if mf.Values.Name == "" {
		return fmt.Errorf("no name for mf values")
	}
	base = GetDefaultRegistryBase(mf, base)
	var uri string
	switch kind {
	case "openstack":
		kind = "platform"
		fallthrough
	case "platform":
		fallthrough
	case "cluster":
		uri = fmt.Sprintf("%s/%s/%s/%s.yaml", mf.Base, kind, mf.Values.Operator.Name, mf.Values.Base)
	case "application":
		uri = fmt.Sprintf("%s/%s/%s/%s.yaml", mf.Base, kind, mf.Values.Application.Base, mf.Values.Base)
	default:
		return fmt.Errorf("invalid manifest kind %s", kind)
	}
	dat, err := GetURIFile(mf, uri)
	if err != nil {
		return err
	}
	//log.DebugLog(log.DebugLevelMexos, "got file", "uri", uri, "data", string(dat))
	tmpl, err := template.New(mf.Values.Name).Parse(string(dat))
	if err != nil {
		return err
	}
	var outbuffer bytes.Buffer
	//log.DebugLog(log.DebugLevelMexos, "mf values", "values", mf.Values)
	err = tmpl.Execute(&outbuffer, &mf.Values)
	if err != nil {
		return err
	}
	err = yaml.Unmarshal(outbuffer.Bytes(), mf)
	if err != nil {
		return err
	}
	return nil
}

func GetDefaultSecurityRule(mf *Manifest) string {
	return mf.Values.Network.SecurityRule
}

func GetMEXSecurityRule(mf *Manifest) string {
	return mf.Values.Network.SecurityRule
}

//GetMEXExternalRouter returns default MEX external router name
func GetMEXExternalRouter(mf *Manifest) string {
	//TODO validate existence and status
	return mf.Values.Network.Router
}

//GetMEXExternalNetwork returns default MEX external network name
func GetMEXExternalNetwork(mf *Manifest) string {
	//TODO validate existence and status
	return mf.Values.Network.External
}

//GetMEXNetwork returns default MEX network, internal and prepped
func GetMEXNetwork(mf *Manifest) string {
	//TODO validate existence and status
	return mf.Values.Network.Name
}

func GetMEXImageName(mf *Manifest) string {
	return mf.Values.Cluster.OSImage
}

func GetMEXUserData(mf *Manifest) string {
	return MEXDir() + "/userdata.txt"
}

func GetKubeManifest(mf *Manifest) (string, error) {
	var kubeManifest string
	rootLB, err := getRootLB(mf.Spec.RootLB)
	if err != nil {
		return "", fmt.Errorf("cannot get rootlb, while getting kubemanifest, %v", err)
	}
	base := rootLB.PlatConf.Base
	if base == "" {
		log.DebugLog(log.DebugLevelMexos, "base is empty, using default")
		base = GetDefaultRegistryBase(mf, base)
	}
	mani := mf.Config.ConfigDetail.Manifest
	deployment := mf.Config.ConfigDetail.Deployment
	//XXX controlling pass full yaml text in parameter of another yaml
	log.DebugLog(log.DebugLevelMexos, "getting kubernetes manifest", "base", base, "manifest", mani)
	if deployment != cloudcommon.AppDeploymentTypeHelm && !strings.HasPrefix(mani, "apiVersion: v1") {
		fn := fmt.Sprintf("%s/%s", base, mani)
		log.DebugLog(log.DebugLevelMexos, "getting manifest file", "uri", fn)
		res, err := GetURIFile(mf, fn)
		if err != nil {
			return "", err
		}
		kubeManifest = string(res)
	} else {
		//XXX controller is passing full yaml as a string.
		log.DebugLog(log.DebugLevelMexos, "getting deployment from cloudcommon", "base", mf.Base, "manifest", mani)
		//XXX again it seems to download yaml but already yaml full string is passed from controller
		kubeManifest, err = cloudcommon.GetDeploymentManifest(mf.Config.ConfigDetail.Manifest)
		if err != nil {
			return "", err
		}
	}
	return kubeManifest, nil
}
