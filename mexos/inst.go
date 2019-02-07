package mexos

import (
	"fmt"

	"github.com/mobiledgex/edge-cloud-infra/k8s-prov/dind"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

/*
//MEXClusterRemoveClustInst calls MEXClusterRemove with a manifest created from the template
func MEXClusterRemoveClustInst(rootLB *MEXRootLB, clusterInst *edgeproto.ClusterInst) error {
	mf, err := FillClusterTemplateClustInst(rootLB, clusterInst)
	if err != nil {
		return err
	}
	fixValuesInst(mf, rootLB)
	return MEXClusterRemoveManifest(mf)
}
*/
/*
func FillClusterTemplateClustInst(rootLB *MEXRootLB, clusterInst *edgeproto.ClusterInst) (*Manifest, error) {
	log.DebugLog(log.DebugLevelMexos, "fill cluster template manifest cluster inst", "clustinst", clusterInst)
	if clusterInst.Key.ClusterKey.Name == "" {
		log.DebugLog(log.DebugLevelMexos, "cannot create empty cluster manifest", "clustinst", clusterInst)
		return nil, fmt.Errorf("invalid cluster inst %v", clusterInst)
	}
	if verr := ValidateClusterKind(clusterInst.Key.CloudletKey.OperatorKey.Name); verr != nil {
		return nil, verr
	}
	vp := &rootLB.PlatConf.Values
	data := templateFill{
		ResourceKind:  "cluster",
		Resource:      clusterInst.Flavor.Name,
		Name:          clusterInst.Key.ClusterKey.Name,
		Tags:          clusterInst.Key.ClusterKey.Name + "-tag",
		Tenant:        clusterInst.Key.ClusterKey.Name + "-tenant",
		Operator:      NormalizeName(clusterInst.Key.CloudletKey.OperatorKey.Name),
		Key:           clusterInst.Key.ClusterKey.Name,
		Kind:          vp.Cluster.Kind, //"kubernetes",
		ResourceGroup: clusterInst.Key.CloudletKey.Name + "_" + clusterInst.Key.ClusterKey.Name,
		Flavor:        clusterInst.Flavor.Name,
		DNSZone:       GetCloudletDNSZone(),
		RootLB:        rootLB.Name,
		NetworkScheme: GetCloudletNetworkScheme(),
		Swarm:         vp.Cluster.Swarm,
	}

	mf, err := templateUnmarshal(&data, yamlMEXCluster)
	if err != nil {
		return nil, err
	}
	fixValuesInst(mf, rootLB)
	return mf, nil
} */

/* this function never actually did anything
func MEXAddFlavorClusterInst(rootLB *MEXRootLB, flavor *edgeproto.ClusterFlavor) error {
	log.DebugLog(log.DebugLevelMexos, "adding cluster inst flavor", "flavor", flavor)

	if flavor.Key.Name == "" {
		log.DebugLog(log.DebugLevelMexos, "cannot add empty cluster inst flavor", "flavor", flavor)
		return fmt.Errorf("will not add empty cluster inst %v", flavor)
	}
	vp := &rootLB.PlatConf.Values
	data := templateFill{
		ResourceKind:  "flavor",
		Resource:      flavor.Key.Name,
		Name:          flavor.Key.Name,
		Tags:          flavor.Key.Name + "-tag",
		Kind:          vp.Cluster.Kind,
		Flags:         flavor.Key.Name + "-flags",
		NumNodes:      int(flavor.NumNodes),
		NumMasters:    int(flavor.NumMasters),
		NetworkScheme: GetCloudletNetworkScheme(),
		NodeFlavor:    flavor.NodeFlavor.Name,
		StorageSpec:   "default", //XXX
	}
	mf, err := templateUnmarshal(&data, yamlMEXFlavor)
	if err != nil {
		return err
	}
	fixValuesInst(mf, rootLB)
	return MEXAddFlavor(mf)
}
*/

//MEXAppDeleteAppInst deletes app with templated manifest
func MEXAppCreateAppInst(rootLB *MEXRootLB, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst) error {
	log.DebugLog(log.DebugLevelMexos, "mex create app inst", "rootlb", rootLB.Name, "clusterinst", clusterInst, "appinst", appInst)

	appDeploymentType := app.Deployment
	clusterName := clusterInst.Key.ClusterKey.Name
	appName := NormalizeName(app.Key.Name)
	operatorName := NormalizeName(appInst.Key.CloudletKey.OperatorKey.Name)

	//TODO values.application.template

	if IsLocalDIND() {
		masteraddr := dind.GetMasterAddr()
		log.DebugLog(log.DebugLevelMexos, "call AddNginxProxy for dind")

		portDetail, err := GetPortDetail(appInst)
		if err != nil {
			log.DebugLog(log.DebugLevelMexos, "GetPortDetail failed", "appInst", appInst, "err", err)
			return err
		}
		if err := AddNginxProxy("localhost", appName, masteraddr, portDetail, dind.GetDockerNetworkName(clusterName)); err != nil {
			log.DebugLog(log.DebugLevelMexos, "cannot add nginx proxy", "name", appName, "ports", appInst.MappedPorts)
			return err
		}
		log.DebugLog(log.DebugLevelMexos, "call runKubectlCreateApp for dind")
		err = runKubectlCreateApp(clusterInst, appInst, app.DeploymentManifest)
		if err != nil {
			log.DebugLog(log.DebugLevelMexos, "error creating dind app")
			return err
		}
		return nil
	}

	switch operatorName {
	case cloudcommon.OperatorGCP:
		fallthrough
	case cloudcommon.OperatorAzure:
		if appDeploymentType == cloudcommon.AppDeploymentTypeKubernetes {
			return runKubectlCreateApp(clusterInst, appInst, app.DeploymentManifest)
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
			return CreateKubernetesAppInst(rootLB, clusterInst, app.DeploymentManifest, app, appInst)

		} else if appDeploymentType == cloudcommon.AppDeploymentTypeHelm {
			return CreateHelmAppInst(rootLB, clusterInst, app.DeploymentManifest, app, appInst)
		}
		//TODO -- support these later
		//} else if appDeploymentType == cloudcommon.AppDeploymentTypeKVM {
		//	return CreateQCOW2AppManifest(mf)  TODO: support this later
		//else if appDeploymentType == cloudcommon.AppDeploymentTypeDockerSwarm {
		//	return CreateDockerSwarmAppManifest(mf)
		//}
		return fmt.Errorf("unknown deployment type %s", appDeploymentType)
	}
}

func MEXAppDeleteAppInst(rootLB *MEXRootLB, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst) error {
	log.DebugLog(log.DebugLevelMexos, "mex delete app inst", "rootlb", rootLB.Name, "clusterinst", clusterInst, "appinst", appInst)
	appDeploymentType := app.Deployment
	operatorName := NormalizeName(appInst.Key.CloudletKey.OperatorKey.Name)
	appName := NormalizeName(app.Key.Name)

	if IsLocalDIND() {
		log.DebugLog(log.DebugLevelMexos, "run kubectl delete app for dind")
		err := runKubectlDeleteApp(clusterInst, appInst, app.DeploymentManifest)
		if err != nil {
			return err
		}

		log.DebugLog(log.DebugLevelMexos, "call DeleteNginxProxy for dind")

		if err = DeleteNginxProxy("localhost", appName); err != nil {
			log.DebugLog(log.DebugLevelMexos, "cannot delete nginx proxy", "name", appName)
			return err
		}

		return nil

	}
	switch operatorName {
	case cloudcommon.OperatorGCP:
		fallthrough
	case cloudcommon.OperatorAzure:
		if appDeploymentType == cloudcommon.AppDeploymentTypeKubernetes {
			return runKubectlDeleteApp(clusterInst, appInst, app.DeploymentManifest)
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
			return DeleteKubernetesAppInst(rootLB, clusterInst, app.DeploymentManifest, app, appInst)
		} else if appDeploymentType == cloudcommon.AppDeploymentTypeHelm {
			return DeleteHelmAppInst(rootLB, clusterInst, app.DeploymentManifest, app, appInst)
		}
		//TODO
		//} else if appDeploymentType == cloudcommon.AppDeploymentTypeKVM {
		//	return DeleteQCOW2AppManifest(mf)
		//} else if appDeploymentType == cloudcommon.AppDeploymentTypeDockerSwarm {
		//	return DeleteDockerSwarmAppManifest(mf)
		return fmt.Errorf("unknown deployment type %s", appDeploymentType)
	}
}
