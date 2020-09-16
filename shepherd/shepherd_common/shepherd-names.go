package shepherd_common

import (
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/proxy"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

func GetProxyKey(appInstKey *edgeproto.AppInstKey) string {
	return appInstKey.AppKey.Name + "-" + appInstKey.ClusterInstKey.ClusterKey.Name + "-" +
		appInstKey.AppKey.Organization + "-" + appInstKey.AppKey.Version
}

func ShouldRunEnvoy(app *edgeproto.App, appInst *edgeproto.AppInst) bool {
	log.DebugLog(log.DebugLevelInfo, "ShouldRunEnvoy", "app", app.Key)
	needEnvoy, _ := proxy.CheckProtocols("", appInst.MappedPorts)
	if !needEnvoy {
		log.DebugLog(log.DebugLevelInfo, "ShouldRunEnvoy", "app", app.Key, "needEnvoy", needEnvoy)
		return false
	}
	if app.InternalPorts || app.AccessType != edgeproto.AccessType_ACCESS_TYPE_LOAD_BALANCER {
		log.DebugLog(log.DebugLevelInfo, "ShouldRunEnvoy", "app", app, "appCheck", false)
		return false
	}
	log.DebugLog(log.DebugLevelInfo, "ShouldRunEnvoy", "app", app.Key, "ok", true)
	return true
}
