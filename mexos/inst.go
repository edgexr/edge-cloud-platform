package mexos

import (
	"fmt"

	"github.com/mobiledgex/edge-cloud-infra/k8s-prov/dind"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

//MEXAppDeleteAppInst deletes app instance
func MEXAppCreateAppInst(rootLB *MEXRootLB, clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst) error {
	log.DebugLog(log.DebugLevelMexos, "mex create app inst", "rootlb", rootLB.Name, "clusterinst", clusterInst, "appinst", appInst)

	appDeploymentType := app.Deployment
	clusterName := clusterInst.Key.ClusterKey.Name
	appName := NormalizeName(app.Key.Name)
	operatorName := NormalizeName(appInst.Key.CloudletKey.OperatorKey.Name)

	//TODO values.application.template

	if CloudletIsLocalDIND() {
		masteraddr := dind.GetMasterAddr()
		log.DebugLog(log.DebugLevelMexos, "call AddNginxProxy for dind")

		portDetail, err := GetPortDetail(appInst)
		if err != nil {
			log.DebugLog(log.DebugLevelMexos, "GetPortDetail failed", "appInst", appInst, "err", err)
			return err
		}

		if len(portDetail) > 0 {
			log.DebugLog(log.DebugLevelMexos, "call AddNginxProxy for dind", "ports", portDetail)
			if err := AddNginxProxy("localhost", appName, masteraddr, portDetail, dind.GetDockerNetworkName(clusterName)); err != nil {
				log.DebugLog(log.DebugLevelMexos, "cannot add nginx proxy", "name", appName, "ports", portDetail)
				return err
			}
		}

		log.DebugLog(log.DebugLevelMexos, "call runKubectlCreateApp for dind")
		if appDeploymentType == cloudcommon.AppDeploymentTypeKubernetes {
			err = runKubectlCreateApp(clusterInst, appInst, rootLB, app.DeploymentManifest)
		} else if appDeploymentType == cloudcommon.AppDeploymentTypeHelm {
			err = CreateHelmAppInst(rootLB, clusterInst, app.DeploymentManifest, app, appInst)
		} else {
			err = fmt.Errorf("invalid deployment type %s for dind", appDeploymentType)
		}
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
			return runKubectlCreateApp(clusterInst, appInst, rootLB, app.DeploymentManifest)
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

	if CloudletIsLocalDIND() {
		log.DebugLog(log.DebugLevelMexos, "run kubectl delete app for dind")

		var err error
		if appDeploymentType == cloudcommon.AppDeploymentTypeKubernetes {
			err = runKubectlDeleteApp(clusterInst, appInst, rootLB, app.DeploymentManifest)
		} else if appDeploymentType == cloudcommon.AppDeploymentTypeHelm {
			err = DeleteHelmAppInst(rootLB, clusterInst, app.DeploymentManifest, app, appInst)
		} else {
			err = fmt.Errorf("invalid deployment type %s for dind", appDeploymentType)
		}
		if err != nil {
			return err
		}

		log.DebugLog(log.DebugLevelMexos, "call DeleteNginxProxy for dind")
		portDetail, err := GetPortDetail(appInst)
		if err != nil {
			log.DebugLog(log.DebugLevelMexos, "GetPortDetail failed", "appInst", appInst, "err", err)
			return err
		}
		if len(portDetail) > 0 {
			if err = DeleteNginxProxy("localhost", appName); err != nil {
				log.DebugLog(log.DebugLevelMexos, "cannot delete nginx proxy", "name", appName)
				return err
			}
		}
		return nil
	}

	switch operatorName {
	case cloudcommon.OperatorGCP:
		fallthrough
	case cloudcommon.OperatorAzure:
		if appDeploymentType == cloudcommon.AppDeploymentTypeKubernetes {
			return runKubectlDeleteApp(clusterInst, appInst, rootLB, app.DeploymentManifest)
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
