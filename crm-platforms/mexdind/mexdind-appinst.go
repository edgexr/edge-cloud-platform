package mexdind

import (
	"net"

	"github.com/mobiledgex/edge-cloud-infra/mexos"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/dind"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	v1 "k8s.io/api/core/v1"
)

func (s *Platform) CreateAppInst(clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, flavor *edgeproto.Flavor, updateCallback edgeproto.CacheUpdateCallback) error {
	client, err := s.generic.GetPlatformClient(clusterInst)
	if err != nil {
		return err
	}

	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return err
	}
	err = mexos.CreateDockerRegistrySecret(client, clusterInst, app, s.config.VaultAddr)
	if err != nil {
		return err
	}

	// Use generic DIND to create the AppInst
	err = s.generic.CreateAppInst(clusterInst, app, appInst, flavor, updateCallback)
	if err != nil {
		return err
	}

	// set up DNS
	cluster, err := dind.FindCluster(names.ClusterName)
	if err != nil {
		return err
	}
	masterIP := cluster.MasterAddr
	externalIP, err := s.GetDINDServiceIP()
	getDnsAction := func(svc v1.Service) (*mexos.DnsSvcAction, error) {
		action := mexos.DnsSvcAction{}

		if len(svc.Spec.ExternalIPs) > 0 && svc.Spec.ExternalIPs[0] == masterIP {
			log.DebugLog(log.DebugLevelMexos, "external IP already present in DIND, no patch required", "addr", masterIP)
		} else {
			action.PatchKube = true
			action.PatchIP = masterIP
		}
		if err != nil {
			return nil, err
		}
		action.ExternalIP = externalIP
		// Should only add DNS for external ports
		action.AddDNS = !app.InternalPorts
		return &action, nil
	}
	if err = mexos.CreateAppDNS(client, names, getDnsAction); err != nil {
		log.DebugLog(log.DebugLevelMexos, "cannot add DNS entries", "error", err)
		return err
	}
	return nil
}

func (s *Platform) DeleteAppInst(clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst) error {
	var err error
	client, err := s.generic.GetPlatformClient(clusterInst)
	if err != nil {
		return err
	}

	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return err
	}

	// remove DNS entries if it was added
	if !app.InternalPorts {
		if err = mexos.DeleteAppDNS(client, names); err != nil {
			log.DebugLog(log.DebugLevelMexos, "warning, cannot delete DNS record", "error", err)
		}
	}
	if err = s.generic.DeleteAppInst(clusterInst, app, appInst); err != nil {
		log.DebugLog(log.DebugLevelMexos, "warning, cannot delete AppInst", "error", err)
		return err
	}
	return nil
}

func (s *Platform) GetAppInstRuntime(clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst) (*edgeproto.AppInstRuntime, error) {
	return s.generic.GetAppInstRuntime(clusterInst, app, appInst)
}

func (s *Platform) GetContainerCommand(clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, req *edgeproto.ExecRequest) (string, error) {
	return s.generic.GetContainerCommand(clusterInst, app, appInst, req)
}

// GetDINDServiceIP depending on the type of DIND cluster will return either the interface or external address
func (s *Platform) GetDINDServiceIP() (string, error) {
	if s.NetworkScheme == cloudcommon.NetworkSchemePrivateIP {
		return GetLocalAddr()
	}
	return mexos.GetExternalPublicAddr()
}

// GetLocalAddr gets the IP address the machine uses for outbound comms
func GetLocalAddr() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String(), nil
}
