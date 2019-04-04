package openstack

import (
	"fmt"

	"github.com/mobiledgex/edge-cloud-infra/mexos"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"k8s.io/api/core/v1"
)

func (s *Platform) CreateAppInst(clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, names *k8smgmt.KubeNames) error {
	// TODO: rootLB may be specific to clusterInst for dedicated IP configs
	rootLBName := s.rootLBName
	client, err := s.GetPlatformClient(rootLBName)
	if err != nil {
		return err
	}

	switch deployment := app.Deployment; deployment {
	case cloudcommon.AppDeploymentTypeKubernetes:
		err = k8smgmt.CreateAppInst(client, names, app, appInst)
	case cloudcommon.AppDeploymentTypeHelm:
		err = k8smgmt.CreateHelmAppInst(client, names, clusterInst, app, appInst)
	case cloudcommon.AppDeploymentTypeKVM:
		fallthrough
	case cloudcommon.AppDeploymentTypeDockerSwarm:
		fallthrough
	default:
		err = fmt.Errorf("unsupported deployment type %s", deployment)
	}
	if err != nil {
		return err
	}

	// set up DNS
	masterIP, err := mexos.GetMasterIP(clusterInst, mexos.GetCloudletExternalNetwork())
	if err != nil {
		return err
	}
	rootLBIPaddr, err := mexos.GetServerIPAddr(mexos.GetCloudletExternalNetwork(), rootLBName)
	if err != nil {
		return err
	}
	getDnsAction := func(svc v1.Service) (*mexos.DnsSvcAction, error) {
		action := mexos.DnsSvcAction{}
		action.PatchKube = true
		action.PatchIP = masterIP
		action.ExternalIP = rootLBIPaddr
		return &action, nil
	}
	err = mexos.AddProxySecurityRulesAndPatchDNS(client, names, appInst, getDnsAction, rootLBName, masterIP)
	if err != nil {
		return fmt.Errorf("CreateKubernetesAppInst error: %v", err)
	}
	return nil
}

func (s *Platform) DeleteAppInst(clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, names *k8smgmt.KubeNames) error {
	// TODO: rootLB may be specific to clusterInst for dedicated IP configs
	rootLBName := s.rootLBName
	client, err := s.GetPlatformClient(rootLBName)
	if err != nil {
		return err
	}

	masterIP, err := mexos.GetMasterIP(clusterInst, mexos.GetCloudletExternalNetwork())
	if err != nil {
		return err
	} // Clean up security rules and nginx proxy
	if err := mexos.DeleteProxySecurityRules(s.rootLB, masterIP, names.AppName); err != nil {
		log.DebugLog(log.DebugLevelMexos, "cannot clean up security rules", "name", names.AppName, "rootlb", rootLBName, "error", err)
	}
	// Clean up DNS entries
	if err := mexos.DeleteAppDNS(client, names); err != nil {
		log.DebugLog(log.DebugLevelMexos, "cannot clean up DNS entries", "name", names.AppName, "rootlb", rootLBName, "error", err)
		return err
	}

	switch deployment := app.Deployment; deployment {
	case cloudcommon.AppDeploymentTypeKubernetes:
		return k8smgmt.DeleteAppInst(client, names, app, appInst)
	case cloudcommon.AppDeploymentTypeHelm:
		return k8smgmt.DeleteHelmAppInst(client, names, clusterInst)
	case cloudcommon.AppDeploymentTypeKVM:
		fallthrough
	case cloudcommon.AppDeploymentTypeDockerSwarm:
		fallthrough
	default:
		return fmt.Errorf("unsupported deployment type %s", deployment)
	}
}
