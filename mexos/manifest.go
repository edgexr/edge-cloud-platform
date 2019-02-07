package mexos

/*
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
	switch mf.Metadata.Operator {
	case cloudcommon.OperatorGCP:
		return nil //nothing to do
	case cloudcommon.OperatorAzure:
		return nil //nothing to do
	default:
		//TODO validate all mf content against platform data
		if err := RunMEXAgentManifest(mf); err != nil {
			return err
		}
	}
	return nil
}

//MEXPlatformCleanManifest cleans up the platform
func MEXPlatformCleanManifest(mf *Manifest) error {
	log.DebugLog(log.DebugLevelMexos, "clean platform")
	switch mf.Metadata.Operator {
	case "gcp":
		return nil //nothing to do
	case "azure":
		return nil
	default:
		if err := RemoveMEXAgentManifest(mf); err != nil {
			return err
		}
	}
	return nil
}

//MEXAppCreateAppManifest creates app instances on the cluster platform
func GetDefaultRegistryBase(mf *Manifest, base string) string {
	mf.Base = base
	if mf.Base == "" {
		mf.Base = fmt.Sprintf("scp://%s/files-repo/mobiledgex", GetCloudletRegistryFileServer())
	}
	log.DebugLog(log.DebugLevelMexos, "default registry base", "base", mf.Base)
	return mf.Base
}


func GetKubeManifest(rootLB *MEXRootLB, clusterInst *edgeproto.ClusterInst) (string, error) {
	var kubeManifest string

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
*/
