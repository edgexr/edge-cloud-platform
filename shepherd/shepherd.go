package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	platform "github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_platform"
	"github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_platform/shepherd_edgebox"
	"github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_platform/shepherd_fake"
	"github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_platform/shepherd_openstack"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/cloudcommon/node"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/notify"
	"github.com/mobiledgex/edge-cloud/tls"
	opentracing "github.com/opentracing/opentracing-go"
)

var debugLevels = flag.String("d", "", fmt.Sprintf("comma separated list of %v", log.DebugLevelStrings))
var notifyAddrs = flag.String("notifyAddrs", "127.0.0.1:51001", "CRM notify listener addresses")
var metricsAddr = flag.String("metricsAddr", "0.0.0.0:9091", "Metrics Proxy Address")
var platformName = flag.String("platform", "", "Platform type of Cloudlet")
var physicalName = flag.String("physicalName", "", "Physical infrastructure cloudlet name, defaults to cloudlet name in cloudletKey")
var cloudletKeyStr = flag.String("cloudletKey", "", "Json or Yaml formatted cloudletKey for the cloudlet in which this CRM is instantiated; e.g. '{\"operator_key\":{\"name\":\"DMUUS\"},\"name\":\"tmocloud1\"}'")
var name = flag.String("name", "shepherd", "Unique name to identify a process")
var parentSpan = flag.String("span", "", "Use parent span for logging")
var region = flag.String("region", "local", "Region name")
var promTargetsFile = flag.String("targetsFile", "/tmp/prom_targets.json", "Prometheus targets file")
var appDNSRoot = flag.String("appDNSRoot", "mobiledgex.net", "App domain name root")

var defaultPrometheusPort = cloudcommon.PrometheusPort

//map keeping track of all the currently running prometheuses
var workerMap map[string]*ClusterWorker
var vmAppWorkerMap map[string]*AppInstWorker
var MEXPrometheusAppName = cloudcommon.MEXPrometheusAppName
var AppInstCache edgeproto.AppInstCache
var ClusterInstCache edgeproto.ClusterInstCache
var AppCache edgeproto.AppCache
var CloudletCache edgeproto.CloudletCache
var CloudletInfoCache edgeproto.CloudletInfoCache
var MetricSender *notify.MetricSend
var AlertCache edgeproto.AlertCache
var AutoProvPoliciesCache edgeproto.AutoProvPolicyCache
var settings edgeproto.Settings

var cloudletKey edgeproto.CloudletKey
var myPlatform platform.Platform
var nodeMgr node.NodeMgr

var sigChan chan os.Signal

func appInstCb(ctx context.Context, old *edgeproto.AppInst, new *edgeproto.AppInst) {
	// LB metrics are not supported in fake mode
	if myPlatform.GetType() != "fake" {
		if target := CollectProxyStats(ctx, new); target != "" {
			go writePrometheusTargetsFile()
			go writePrometheusAlertRuleForAppInst(ctx, new)
		}
	}
	var port int32
	var exists bool
	var mapKey string

	collectInterval := settings.ShepherdMetricsCollectionInterval.TimeDuration()
	// check cluster name if this is a VM App
	app := edgeproto.App{}
	found := AppCache.Get(&new.Key.AppKey, &app)
	if !found {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Unable to find app", "app", new.Key.AppKey.Name)
		return
	}
	if app.Deployment == cloudcommon.DeploymentTypeVM {
		mapKey = new.Key.GetKeyString()
		stats, exists := vmAppWorkerMap[mapKey]
		if new.State == edgeproto.TrackedState_READY && !exists {
			// Add/Create
			stats, err := NewAppInstWorker(ctx, collectInterval, MetricSender.Update, new, myPlatform)
			if err == nil {
				vmAppWorkerMap[mapKey] = stats
				stats.Start(ctx)
			}
		} else if new.State != edgeproto.TrackedState_READY && exists {
			delete(vmAppWorkerMap, mapKey)
			stats.Stop(ctx)
		}
		// Done for VM Apps
		return
	} else if new.Key.AppKey.Name == MEXPrometheusAppName {
		// check for prometheus
		mapKey = k8smgmt.GetK8sNodeNameSuffix(&new.Key.ClusterInstKey)
	} else {
		return
	}
	stats, exists := workerMap[mapKey]
	if new.State == edgeproto.TrackedState_READY {
		log.SpanLog(ctx, log.DebugLevelMetrics, "New Prometheus instance detected", "clustername", mapKey, "appInst", new)
		// get address of prometheus.
		clusterInst := edgeproto.ClusterInst{}
		found := ClusterInstCache.Get(&new.Key.ClusterInstKey, &clusterInst)
		if !found {
			log.SpanLog(ctx, log.DebugLevelMetrics, "Unable to find clusterInst for prometheus")
			return
		}
		clustIP, err := myPlatform.GetClusterIP(ctx, &clusterInst)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelMetrics, "error getting clusterIP", "err", err.Error())
			return
		}
		// We don't actually expose prometheus ports - we should default to 9090
		if len(new.MappedPorts) > 0 {
			port = new.MappedPorts[0].PublicPort
		} else {
			port = defaultPrometheusPort
		}
		promAddress := fmt.Sprintf("%s:%d", clustIP, port)
		log.SpanLog(ctx, log.DebugLevelMetrics, "prometheus found", "promAddress", promAddress)
		if !exists {
			stats, err = NewClusterWorker(ctx, promAddress, collectInterval, MetricSender.Update, &clusterInst, myPlatform)
			if err == nil {
				workerMap[mapKey] = stats
				stats.Start(ctx)
			}
		} else { //somehow this cluster's prometheus was already registered
			log.SpanLog(ctx, log.DebugLevelMetrics, "Error, Prometheus app already registered for this cluster")
		}
	} else { //if its anything other than ready just stop it
		//try to remove it from the workerMap
		if exists {
			delete(workerMap, mapKey)
			stats.Stop(ctx)
		}
	}
}

func clusterInstCb(ctx context.Context, old *edgeproto.ClusterInst, new *edgeproto.ClusterInst) {
	// This is for Docker deployments only
	if new.Deployment != cloudcommon.DeploymentTypeDocker {
		log.SpanLog(ctx, log.DebugLevelMetrics, "New cluster instace", "clusterInst", new)
		return
	}
	collectInterval := settings.ShepherdMetricsCollectionInterval.TimeDuration()
	var mapKey = k8smgmt.GetK8sNodeNameSuffix(&new.Key)
	stats, exists := workerMap[mapKey]
	if new.State == edgeproto.TrackedState_READY {
		log.SpanLog(ctx, log.DebugLevelMetrics, "New Docker cluster detected", "clustername", mapKey, "clusterInst", new)
		if !exists {
			stats, err := NewClusterWorker(ctx, "", collectInterval, MetricSender.Update, new, myPlatform)
			if err == nil {
				workerMap[mapKey] = stats
				stats.Start(ctx)
			}
		} else { //somehow this cluster's prometheus was already registered
			log.SpanLog(ctx, log.DebugLevelMetrics, "Error, This cluster is already registered")
		}
	} else { //if its anything other than ready just stop it
		//try to remove it from the workerMap
		if exists {
			delete(workerMap, mapKey)
			stats.Stop(ctx)
		}
	}
}

func getPlatform() (platform.Platform, error) {
	var plat platform.Platform
	var err error
	switch *platformName {
	case "PLATFORM_TYPE_EDGEBOX":
		plat = &shepherd_edgebox.Platform{}
	case "PLATFORM_TYPE_OPENSTACK":
		plat = &shepherd_openstack.ShepherdPlatform{}
	case "PLATFORM_TYPE_FAKEINFRA":
		plat = &shepherd_fake.Platform{}
	default:
		err = fmt.Errorf("Platform %s not supported", *platformName)
	}
	return plat, err
}

func main() {
	nodeMgr.InitFlags()
	flag.Parse()
	log.SetDebugLevelStrs(*debugLevels)
	log.InitTracer(nodeMgr.TlsCertFile)
	defer log.FinishTracer()

	var span opentracing.Span
	if *parentSpan != "" {
		span = log.NewSpanFromString(log.DebugLevelInfo, *parentSpan, "main")
	} else {
		span = log.StartSpan(log.DebugLevelInfo, "main")
	}
	ctx := log.ContextWithSpan(context.Background(), span)
	settings = *edgeproto.GetDefaultSettings()

	cloudcommon.ParseMyCloudletKey(false, cloudletKeyStr, &cloudletKey)

	err := nodeMgr.Init(ctx, "shepherd", node.WithCloudletKey(&cloudletKey), node.WithRegion(*region))
	if err != nil {
		span.Finish()
		log.FatalLog(err.Error())
	}
	clientTlsConfig, err := nodeMgr.InternalPki.GetClientTlsConfig(ctx,
		nodeMgr.CommonName(),
		node.CertIssuerRegionalCloudlet,
		[]node.MatchCA{node.SameRegionalCloudletMatchCA()})
	if err != nil {
		span.Finish()
		log.FatalLog("Failed to get internal pki tls config", "err", err)
	}

	myPlatform, err = getPlatform()
	if err != nil {
		span.Finish()
		log.FatalLog("Failed to get platform", "platformName", platformName, "err", err)
	}

	if err = startPrometheusMetricsProxy(ctx); err != nil {
		span.Finish()
		log.FatalLog("Failed to start prometheus metrics proxy", "err", err)
	}

	// register shepherd to receive appinst and clusterinst notifications from crm
	edgeproto.InitAppInstCache(&AppInstCache)
	AppInstCache.SetUpdatedCb(appInstCb)
	edgeproto.InitClusterInstCache(&ClusterInstCache)
	ClusterInstCache.SetUpdatedCb(clusterInstCb)
	edgeproto.InitAppCache(&AppCache)
	edgeproto.InitAutoProvPolicyCache(&AutoProvPoliciesCache)
	// also register to receive cloudlet details
	edgeproto.InitCloudletCache(&CloudletCache)

	addrs := strings.Split(*notifyAddrs, ",")
	notifyClient := notify.NewClient(addrs, tls.GetGrpcDialOption(clientTlsConfig))
	notifyClient.SetFilterByCloudletKey()
	notifyClient.RegisterRecvAppInstCache(&AppInstCache)
	notifyClient.RegisterRecvClusterInstCache(&ClusterInstCache)
	notifyClient.RegisterRecvAppCache(&AppCache)
	notifyClient.RegisterRecvCloudletCache(&CloudletCache)
	notifyClient.RegisterRecvAutoProvPolicyCache(&AutoProvPoliciesCache)
	// register to send metrics
	MetricSender = notify.NewMetricSend()
	notifyClient.RegisterSend(MetricSender)
	edgeproto.InitAlertCache(&AlertCache)
	notifyClient.RegisterSendAlertCache(&AlertCache)
	// register to send cloudletInfo, to receive appinst/clusterinst/cloudlet notifications from crm
	edgeproto.InitCloudletInfoCache(&CloudletInfoCache)
	notifyClient.RegisterSendCloudletInfoCache(&CloudletInfoCache)

	nodeMgr.RegisterClient(notifyClient)

	notifyClient.Start()
	defer notifyClient.Stop()

	cloudletInfo := edgeproto.CloudletInfo{
		Key: cloudletKey,
	}

	// Send state INIT to get cloudlet obj from crm
	cloudletInfo.State = edgeproto.CloudletState_CLOUDLET_STATE_INIT
	CloudletInfoCache.Update(ctx, &cloudletInfo, 0)

	var cloudlet edgeproto.Cloudlet

	// Fetch cloudlet cache from controller
	// This also ensures that cloudlet is up before we start collecting metrics
	found := false
	log.SpanLog(ctx, log.DebugLevelInfo, "wait for cloudlet cache", "key", cloudletKey)
	for i := 0; i < 50; i++ {
		if CloudletCache.Get(&cloudletKey, &cloudlet) {
			found = true
			break
		}
		time.Sleep(1 * time.Second)
	}
	if !found {
		span.Finish()
		log.FatalLog("failed to fetch cloudlet cache from controller")
	}
	log.SpanLog(ctx, log.DebugLevelInfo, "fetched cloudlet cache from controller", "cloudlet", cloudlet)

	err = myPlatform.Init(ctx, &cloudletKey, *region, *physicalName, nodeMgr.VaultAddr, *appDNSRoot, cloudlet.EnvVar)
	if err != nil {
		span.Finish()
		log.FatalLog("Failed to initialize platform", "platformName", platformName, "err", err)
	}
	workerMap = make(map[string]*ClusterWorker)
	vmAppWorkerMap = make(map[string]*AppInstWorker)
	// LB metrics are not supported in fake mode
	if myPlatform.GetType() != "fake" {
		InitProxyScraper()
		StartProxyScraper()
	}
	InitPlatformMetrics()

	// Send state READY to get AppInst/ClusterInst objs from crm
	cloudletInfo.State = edgeproto.CloudletState_CLOUDLET_STATE_READY
	CloudletInfoCache.Update(ctx, &cloudletInfo, 0)

	sigChan = make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)

	log.SpanLog(ctx, log.DebugLevelMetrics, "Ready")
	span.Finish()

	// wait until process in killed/interrupted
	sig := <-sigChan
	fmt.Println(sig)
}
