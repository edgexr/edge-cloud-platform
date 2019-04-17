package mexdind

import (
	"net"
	"strings"

	sh "github.com/codeskyblue/go-sh"
	"github.com/mobiledgex/edge-cloud-infra/mexos"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/dind"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"k8s.io/api/core/v1"
)

func (s *Platform) CreateAppInst(clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst) error {
	var err error
	client, err := s.generic.GetPlatformClient()
	if err != nil {
		return err
	}

	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return err
	}

	masterIP := s.GetMasterAddr(names.ClusterName)
	log.DebugLog(log.DebugLevelMexos, "call AddNginxProxy for dind")

	portDetail, err := mexos.GetPortDetail(appInst)
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "GetPortDetail failed", "appInst", appInst, "err", err)
		return err
	}

	if len(portDetail) > 0 {
		log.DebugLog(log.DebugLevelMexos, "call AddNginxProxy for dind", "ports", portDetail)
		if err := mexos.AddNginxProxy("localhost", names.AppName, masterIP, portDetail, s.GetDockerNetworkName(names.ClusterName)); err != nil {
			log.DebugLog(log.DebugLevelMexos, "cannot add nginx proxy", "appName", names.AppName, "ports", portDetail)
			return err
		}
	}

	// Use generic DIND to create the AppInst
	err = s.generic.CreateAppInst(clusterInst, app, appInst)
	if err != nil {
		return err
	}

	// set up DNS
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
	client, err := s.generic.GetPlatformClient()
	if err != nil {
		return err
	}

	names, err := k8smgmt.GetKubeNames(clusterInst, app, appInst)
	if err != nil {
		return err
	}

	// remove DNS entries
	if err = mexos.DeleteAppDNS(client, names); err != nil {
		log.DebugLog(log.DebugLevelMexos, "warning, cannot delete DNS record", "error", err)
	}
	if err = s.generic.DeleteAppInst(clusterInst, app, appInst); err != nil {
		log.DebugLog(log.DebugLevelMexos, "warning, cannot delete AppInst", "error", err)
		return err
	}

	log.DebugLog(log.DebugLevelMexos, "call DeleteNginxProxy for dind")
	portDetail, err := mexos.GetPortDetail(appInst)
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "GetPortDetail failed", "appInst", appInst, "err", err)
		return err
	}
	if len(portDetail) > 0 {
		if err = mexos.DeleteNginxProxy("localhost", names.AppName); err != nil {
			log.DebugLog(log.DebugLevelMexos, "cannot delete nginx proxy", "name", names.AppName)
			return err
		}
	}
	return nil
}

func (s *Platform) GetAppInstRuntime(clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst) (*edgeproto.AppInstRuntime, error) {
	return s.generic.GetAppInstRuntime(clusterInst, app, appInst)
}

func (s *Platform) GetContainerCommand(clusterInst *edgeproto.ClusterInst, app *edgeproto.App, appInst *edgeproto.AppInst, req *edgeproto.ExecRequest) (string, error) {
	return s.generic.GetContainerCommand(clusterInst, app, appInst, req)
}

// Get gets the ip address of the k8s master that nginx proxy will route to
func (s *Platform) GetMasterAddr(clusterName string) string {
	c, found := s.generic.Clusters[clusterName]
	if !found {
		return ""
	}
	return c.MasterAddr
}

// GetDINDServiceIP depending on the type of DIND cluster will return either the interface or external address
func (s *Platform) GetDINDServiceIP() (string, error) {
	if s.NetworkScheme == cloudcommon.NetworkSchemePrivateIP {
		return GetLocalAddr()
	}
	return GetExternalPublicAddr()
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

// Get the externally visible public IP address
func GetExternalPublicAddr() (string, error) {
	out, err := sh.Command("dig", "@resolver1.opendns.com", "ANY", "myip.opendns.com", "+short").Output()
	log.DebugLog(log.DebugLevelMexos, "dig to resolver1.opendns.com called", "out", string(out), "err", err)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), err
}

func (s *Platform) GetDockerNetworkName(clusterName string) string {
	cluster, found := s.generic.Clusters[clusterName]
	if !found {
		log.DebugLog(log.DebugLevelMexos, "ERROR - Cluster %s doesn't exists", clusterName)
		return ""
	}
	return "kubeadm-dind-net-" + cluster.ClusterName + "-" + dind.GetClusterID(cluster.ClusterID)
}
