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
	"github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_platform/shepherd_dind"
	"github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_platform/shepherd_fake"
	"github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_platform/shepherd_openstack"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/notify"
)

var debugLevels = flag.String("d", "", fmt.Sprintf("comma separated list of %v", log.DebugLevelStrings))
var tlsCertFile = flag.String("tls", "", "server tls cert file.  Keyfile and CA file mex-ca.crt must be in same directory")
var notifyAddrs = flag.String("notifyAddrs", "127.0.0.1:51001", "CRM notify listener addresses")
var collectInterval = flag.Duration("interval", time.Second*5, "Metrics collection interval")
var platformName = flag.String("platform", "", "Platform type of Cloudlet")
var vaultAddr = flag.String("vaultAddr", "", "Address to vault")
var physicalName = flag.String("physicalName", "", "Physical infrastructure cloudlet name, defaults to cloudlet name in cloudletKey")
var cloudletKeyStr = flag.String("cloudletKey", "", "Json or Yaml formatted cloudletKey for the cloudlet in which this CRM is instantiated; e.g. '{\"operator_key\":{\"name\":\"DMUUS\"},\"name\":\"tmocloud1\"}'")
var region = flag.String("region", "local", "region name")
var name = flag.String("name", "shepherd", "Unique name to identify a process")

var defaultPrometheusPort = int32(9090)

//map keeping track of all the currently running prometheuses
var promMap map[string]*ClusterWorker
var MEXPrometheusAppName = cloudcommon.MEXPrometheusAppName
var AppInstCache edgeproto.AppInstCache
var ClusterInstCache edgeproto.ClusterInstCache
var AppCache edgeproto.AppCache
var MetricSender *notify.MetricSend

var cloudletKey edgeproto.CloudletKey
var pf platform.Platform

var sigChan chan os.Signal

func appInstCb(ctx context.Context, old *edgeproto.AppInst, new *edgeproto.AppInst) {
	CollectNginxStats(ctx, new)
	var port int32
	//check for prometheus
	if new.Key.AppKey.Name != MEXPrometheusAppName {
		return
	}
	var mapKey = k8smgmt.GetK8sNodeNameSuffix(&new.Key.ClusterInstKey)
	stats, exists := promMap[mapKey]
	if new.State == edgeproto.TrackedState_READY {
		log.SpanLog(ctx, log.DebugLevelMetrics, "New Prometheus instance detected", "clustername", mapKey, "appInst", new)
		//get address of prometheus.
		clusterInst := edgeproto.ClusterInst{}
		found := ClusterInstCache.Get(&new.Key.ClusterInstKey, &clusterInst)
		if !found {
			log.SpanLog(ctx, log.DebugLevelMetrics, "Unable to find clusterInst for prometheus")
			return
		}
		clustIP, err := pf.GetClusterIP(ctx, &clusterInst)
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
			stats, err = NewClusterWorker(ctx, promAddress, *collectInterval, MetricSender.Update, &clusterInst, pf)
			if err == nil {
				promMap[mapKey] = stats
				stats.Start(ctx)
			}
		} else { //somehow this cluster's prometheus was already registered
			log.SpanLog(ctx, log.DebugLevelMetrics, "Error, Prometheus app already registered for this cluster")
		}
	} else { //if its anything other than ready just stop it
		//try to remove it from the prommap
		if exists {
			delete(promMap, mapKey)
			stats.Stop(ctx)
		}
	}
}

func clusterInstCb(ctx context.Context, old *edgeproto.ClusterInst, new *edgeproto.ClusterInst) {
	// This is for Docker deployments only
	if new.Deployment != cloudcommon.AppDeploymentTypeDocker {
		return
	}
	var mapKey = k8smgmt.GetK8sNodeNameSuffix(&new.Key)
	stats, exists := promMap[mapKey]
	if new.State == edgeproto.TrackedState_READY {
		log.SpanLog(ctx, log.DebugLevelMetrics, "New Docker cluster detected", "clustername", mapKey, "clusterInst", new)
		if !exists {
			stats, err := NewClusterWorker(ctx, "", *collectInterval, MetricSender.Update, new, pf)
			if err == nil {
				promMap[mapKey] = stats
				stats.Start(ctx)
			}
		} else { //somehow this cluster's prometheus was already registered
			log.SpanLog(ctx, log.DebugLevelMetrics, "Error, This cluster is already registered")
		}
	} else { //if its anything other than ready just stop it
		//try to remove it from the prommap
		if exists {
			delete(promMap, mapKey)
			stats.Stop(ctx)
		}
	}
}

func getPlatform() (platform.Platform, error) {
	var plat platform.Platform
	var err error
	switch *platformName {
	case "PLATFORM_TYPE_MEXDIND":
		plat = &shepherd_dind.Platform{}
	case "PLATFORM_TYPE_OPENSTACK":
		plat = &shepherd_openstack.Platform{}
	case "PLATFORM_TYPE_FAKE":
		plat = &shepherd_fake.Platform{}
	default:
		err = fmt.Errorf("Platform %s not supported", *platformName)
	}
	return plat, err
}

func main() {
	flag.Parse()
	log.SetDebugLevelStrs(*debugLevels)
	log.InitTracer(*tlsCertFile)
	defer log.FinishTracer()
	span := log.StartSpan(log.DebugLevelInfo, "main")
	ctx := log.ContextWithSpan(context.Background(), span)

	cloudcommon.ParseMyCloudletKey(false, cloudletKeyStr, &cloudletKey)
	log.SpanLog(ctx, log.DebugLevelMetrics, "Metrics collection", "interval", collectInterval)
	var err error
	pf, err = getPlatform()
	if err != nil {
		log.FatalLog("Failed to get platform", "platformName", platformName, "err", err)
	}
	pf.Init(ctx, &cloudletKey, *physicalName, *vaultAddr)
	if err != nil {
		log.FatalLog("Failed to initialize platform", "platformName", platformName, "err", err)
	}
	promMap = make(map[string]*ClusterWorker)
	InitNginxScraper()

	//register shepherd to receive appinst and clusterinst notifications from crm
	edgeproto.InitAppInstCache(&AppInstCache)
	AppInstCache.SetUpdatedCb(appInstCb)
	ClusterInstCache.SetUpdatedCb(clusterInstCb)
	edgeproto.InitClusterInstCache(&ClusterInstCache)
	edgeproto.InitAppCache(&AppCache)
	addrs := strings.Split(*notifyAddrs, ",")
	notifyClient := notify.NewClient(addrs, *tlsCertFile)
	notifyClient.RegisterRecvAppInstCache(&AppInstCache)
	notifyClient.RegisterRecvClusterInstCache(&ClusterInstCache)
	notifyClient.RegisterRecvAppCache(&AppCache)
	//register to send metrics
	MetricSender = notify.NewMetricSend()
	notifyClient.RegisterSend(MetricSender)

	notifyClient.Start()
	defer notifyClient.Stop()

	sigChan = make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)

	log.SpanLog(ctx, log.DebugLevelMetrics, "Ready")
	span.Finish()

	// wait until process in killed/interrupted
	sig := <-sigChan
	fmt.Println(sig)
}
