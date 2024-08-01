// Copyright 2022 MobiledgeX, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package crm

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	accessapicloudlet "github.com/edgexr/edge-cloud-platform/pkg/accessapi-cloudlet"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/node"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/notify"
	pf "github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/cloudletssh"
	"github.com/edgexr/edge-cloud-platform/pkg/process"
	"github.com/edgexr/edge-cloud-platform/pkg/proxy/certs"
	"github.com/edgexr/edge-cloud-platform/pkg/redundancy"
	"github.com/edgexr/edge-cloud-platform/pkg/syncdata"
	"github.com/edgexr/edge-cloud-platform/pkg/tls"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
	opentracing "github.com/opentracing/opentracing-go"
)

var notifyAddrs = flag.String("notifyAddrs", "127.0.0.1:50001", "Comma separated list of controller notify listener addresses")
var notifySrvAddr = flag.String("notifySrvAddr", "127.0.0.1:51001", "Address for the CRM notify listener to run on")
var cloudletKeyStr = flag.String("cloudletKey", "", "Json or Yaml formatted cloudletKey for the cloudlet in which this CRM is instantiated; e.g. '{\"operator_key\":{\"name\":\"DMUUS\"},\"name\":\"tmocloud1\"}'")
var physicalName = flag.String("physicalName", "", "Physical infrastructure cloudlet name, defaults to cloudlet name in cloudletKey")
var debugLevels = flag.String("d", "", fmt.Sprintf("Comma separated list of %v", log.DebugLevelStrings))
var hostname = flag.String("hostname", "", "Unique hostname within Cloudlet")
var platformName = flag.String("platform", "", "Platform type of Cloudlet")
var solib = flag.String("plugin", "", "plugin file")
var region = flag.String("region", "local", "region name")
var testMode = flag.Bool("testMode", false, "Run CRM in test mode")
var parentSpan = flag.String("span", "", "Use parent span for logging")
var containerVersion = flag.String("containerVersion", "", "edge-cloud container version")
var vmImageVersion = flag.String("vmImageVersion", "", "CRM VM baseimage version")
var packageVersion = flag.String("packageVersion", "", "CRM VM baseimage debian package version")
var cloudletVMImagePath = flag.String("cloudletVMImagePath", "", "Image path where CRM VM baseimages are present")
var envoyWithCurlImage = flag.String("envoyWithCurlImage", "", "docker image for envoy with curl to use on LB as reverse proxy")
var nginxWithCurlImage = flag.String("nginxWithCurlImage", "", "docker image for nginx with curl to use on LB as reverse proxy")
var commercialCerts = flag.Bool("commercialCerts", false, "Get TLS certs from LetsEncrypt. If false CRM will generate its own self-signed certs")
var appDNSRoot = flag.String("appDNSRoot", "appdnsroot.net", "App domain name root")

var ansiblePublicAddr = flag.String("ansiblePublicAddr", "", "ansible webserver address")
var upgrade = flag.Bool("upgrade", false, "Flag to initiate upgrade run as part of crm bringup")
var cacheDir = flag.String("cacheDir", "/tmp/", "Cache used by CRM to store frequently accessed data")

// myCloudletInfo is the information for the cloudlet in which the CRM is instantiated.
// The key for myCloudletInfo is provided as a configuration - either command line or
// from a file. The rest of the data is extraced from Openstack.
var myCloudletInfo edgeproto.CloudletInfo //XXX this effectively makes one CRM per cloudlet
var nodeMgr node.NodeMgr
var highAvailabilityManager redundancy.HighAvailabilityManager

var crmdata *CRMData
var notifyClient *notify.Client
var notifyServer *notify.ServerMgr
var platform pf.Platform
var finishInfraResourceThread bool
var finishUpdateCloudletInfoHAThread bool
var proxyCerts *certs.ProxyCerts

const ControllerTimeout = 1 * time.Minute

const (
	envMexBuild       = "MEX_BUILD"
	envMexBuildTag    = "MEX_BUILD_TAG"
	envMexBuildFlavor = "MEX_BUILD_FLAVOR"
)

// do not change this string as the chef startup recipe looks for it during H/A upgrades
const waitingForPlatformActiveLog = "waiting for platform to become active"

func Run(builders map[string]pf.PlatformBuilder) {
	nodeMgr.InitFlags()
	nodeMgr.AccessKeyClient.InitFlags()
	highAvailabilityManager.InitFlags()
	flag.Parse()
	log.SetDebugLevelStrs(*debugLevels)

	err := Start(builders)
	if err != nil {
		Stop()
		log.FatalLog(err.Error())
	}
	defer Stop()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// wait until process is killed/interrupted
	sig := <-sigChan
	fmt.Println(sig)
}

func getPlatform(ctx context.Context, key *edgeproto.CloudletKey) (pf.Platform, error) {
	return platform, nil
}

func Start(builders map[string]pf.PlatformBuilder) error {
	standalone := false
	cloudcommon.ParseMyCloudletKey(standalone, cloudletKeyStr, &myCloudletInfo.Key)
	myCloudletInfo.CompatibilityVersion = cloudcommon.GetCRMCompatibilityVersion()
	nodeType := node.NodeTypeCRM
	nodeOps := []node.NodeOp{
		node.WithName(*hostname),
		node.WithCloudletKey(&myCloudletInfo.Key),
		node.WithNoUpdateMyNode(),
		node.WithRegion(*region),
		node.WithParentSpan(*parentSpan),
	}

	if highAvailabilityManager.HARole == string(process.HARoleSecondary) {
		nodeOps = append(nodeOps, node.WithHARole(process.HARoleSecondary))
	} else {
		nodeOps = append(nodeOps, node.WithHARole(process.HARolePrimary))
	}
	ctx, span, err := nodeMgr.Init(nodeType, node.CertIssuerRegionalCloudlet, nodeOps...)
	if err != nil {
		return err
	}
	defer span.Finish()

	log.SetTags(span, myCloudletInfo.Key.GetTags())
	InitDebug(&nodeMgr)

	if *platformName == "" {
		// see if env var was set
		*platformName = os.Getenv("PLATFORM")
	}
	if *platformName == "" {
		// if not specified, platform is derived from operator name
		*platformName = myCloudletInfo.Key.Organization
	}
	if *physicalName == "" {
		*physicalName = myCloudletInfo.Key.Name
	}
	// Convert old platform names for backwards compatibility
	*platformName = pf.GetTypeBC(*platformName)

	log.SpanLog(ctx, log.DebugLevelInfo, "Using cloudletKey", "key", myCloudletInfo.Key, "platform", *platformName, "physicalName", physicalName)

	// Load platform implementation.
	builder, ok := builders[*platformName]
	if !ok {
		return fmt.Errorf("Unknown CRM platform %s", *platformName)
	}
	platform = builder()
	features := platform.GetFeatures()

	if !nodeMgr.AccessKeyClient.IsEnabled() {
		return fmt.Errorf("access key client is not enabled")
	}
	crmdata = NewCRMData(platform, &myCloudletInfo.Key, &nodeMgr, &highAvailabilityManager)

	updateCloudletStatus := func(updateType edgeproto.CacheUpdateType, value string) {
		switch updateType {
		case edgeproto.UpdateTask:
			myCloudletInfo.Status.SetTask(value)
		case edgeproto.UpdateStep:
			myCloudletInfo.Status.SetStep(value)
		}
		crmdata.CloudletInfoCache.Update(ctx, &myCloudletInfo, 0)
	}

	//ctl notify
	addrs := strings.Split(*notifyAddrs, ",")
	notifyClientTls, err := nodeMgr.InternalPki.GetClientTlsConfig(ctx,
		nodeMgr.CommonNamePrefix(),
		node.CertIssuerRegionalCloudlet,
		[]node.MatchCA{node.SameRegionalMatchCA()})
	if err != nil {
		return err
	}
	notifyServerTls, err := nodeMgr.InternalPki.GetServerTlsConfig(ctx,
		nodeMgr.CommonNamePrefix(),
		node.CertIssuerRegionalCloudlet,
		[]node.MatchCA{node.SameRegionalCloudletMatchCA()})
	if err != nil {
		return err
	}
	dialOption := tls.GetGrpcDialOption(notifyClientTls)
	notifyClient = notify.NewClient(nodeMgr.Name(), addrs, dialOption,
		notify.ClientUnaryInterceptors(nodeMgr.AccessKeyClient.UnaryAddAccessKey),
		notify.ClientStreamInterceptors(nodeMgr.AccessKeyClient.StreamAddAccessKey),
	)
	notifyClient.SetFilterByCloudletKey()
	InitClientNotify(notifyClient, &nodeMgr, crmdata, crmdata.CRMHandler)
	notifyClient.Start()

	haKey := fmt.Sprintf("nodeType: %s cloudlet: %s", "CRM", nodeMgr.MyNode.Key.CloudletKey.String())
	haEnabled, err := crmdata.InitHAManager(ctx, &highAvailabilityManager, haKey, &myCloudletInfo.Key)
	if err != nil {
		return err
	}
	if haEnabled {
		log.SpanLog(ctx, log.DebugLevelInfra, "HA enabled", "role", highAvailabilityManager.HARole)
		if highAvailabilityManager.PlatformInstanceActive {
			log.SpanLog(ctx, log.DebugLevelInfra, "HA instance is active", "role", highAvailabilityManager.HARole)
			myCloudletInfo.ActiveCrmInstance = highAvailabilityManager.HARole
		} else {
			log.SpanLog(ctx, log.DebugLevelInfra, "HA instance is not active", "role", highAvailabilityManager.HARole)
		}
		crmdata.StartHAManagerActiveCheck(ctx, &highAvailabilityManager)
	}
	go func() {
		cspan := log.StartSpan(log.DebugLevelInfo, "cloudlet init thread", opentracing.ChildOf(log.SpanFromContext(ctx).Context()))
		log.SpanLog(ctx, log.DebugLevelInfo, "starting to init platform")
		cloudletContainerVersion := ""
		if *containerVersion == "" {
			cloudletContainerVersion, err = cloudcommon.GetDockerBaseImageVersion()
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfo, "unable to fetch docker image version", "err", err)
			}
		} else {
			cloudletContainerVersion = *containerVersion
		}
		nodeMgr.MyNode.ContainerVersion = cloudletContainerVersion
		getMexReleaseInfo(ctx)
		nodeMgr.UpdateMyNode(ctx)

		myCloudletInfo.State = dme.CloudletState_CLOUDLET_STATE_INIT
		myCloudletInfo.ContainerVersion = cloudletContainerVersion
		myCloudletInfo.Status.SetTask("Initializing controller connection")
		crmdata.waitForCRMINITOK = true
		crmdata.CloudletInfoCache.Update(ctx, &myCloudletInfo, 0)

		var cloudlet edgeproto.Cloudlet
		log.SpanLog(ctx, log.DebugLevelInfo, "wait for cloudlet cache", "key", myCloudletInfo.Key)
		// Wait for cloudlet cache from controller
		// This ensures that crm is able to communicate to controller via Notify Channel
		select {
		case <-crmdata.ControllerWait:
			if !crmdata.CloudletCache.Get(&myCloudletInfo.Key, &cloudlet) {
				log.FatalLog("failed to fetch cloudlet cache from controller")
			}
		case <-time.After(ControllerTimeout):
			log.FatalLog("Timed out waiting for cloudlet cache from controller")
		}
		log.SpanLog(ctx, log.DebugLevelInfo, "fetched cloudlet cache from controller", "cloudlet", cloudlet)

		caches := crmdata.GetCaches()

		if features.IsVmPool {
			if cloudlet.VmPool == "" {
				log.FatalLog("Cloudlet is missing VM pool name")
			}
			vmPoolKey := edgeproto.VMPoolKey{
				Name:         cloudlet.VmPool,
				Organization: myCloudletInfo.Key.Organization,
			}
			var vmPool edgeproto.VMPool
			if !crmdata.VMPoolCache.Get(&vmPoolKey, &vmPool) {
				log.FatalLog("failed to fetch vm pool cache from controller")
			}
			crmdata.VMPool = vmPool
			caches.VMPool = &crmdata.VMPool
			caches.VMPoolMux = &crmdata.VMPoolMux
			// Update VMPool Info, this is to notify shepherd about VMPool
			crmdata.UpdateVMPoolInfo(ctx, edgeproto.TrackedState_READY, "")
		}

		updateCloudletStatus(edgeproto.UpdateTask, "Initializing platform")

		accessApi := accessapicloudlet.NewControllerClient(nodeMgr.AccessApiClient)
		cloudletSSHKey := cloudletssh.NewSSHKey(accessApi)
		pc := pf.PlatformConfig{
			CloudletKey:         &myCloudletInfo.Key,
			CloudletObjID:       cloudlet.ObjId,
			PhysicalName:        *physicalName,
			Region:              *region,
			TestMode:            *testMode,
			CloudletVMImagePath: *cloudletVMImagePath,
			EnvoyWithCurlImage:  *envoyWithCurlImage,
			NginxWithCurlImage:  *nginxWithCurlImage,
			EnvVars:             cloudlet.EnvVar,
			NodeMgr:             &nodeMgr,
			AppDNSRoot:          *appDNSRoot,
			RootLBFQDN:          cloudlet.RootLbFqdn,
			DeploymentTag:       nodeMgr.DeploymentTag,
			TrustPolicy:         cloudlet.TrustPolicy,
			CacheDir:            *cacheDir,
			AnsiblePublicAddr:   *ansiblePublicAddr,
			CommercialCerts:     *commercialCerts,
			PlatformInitConfig: pf.PlatformInitConfig{
				AccessApi:      accessApi,
				CloudletSSHKey: cloudletSSHKey,
				SyncFactory:    syncdata.NewMutexSyncFactory(),
			},
		}

		conditionalInitRequired := true
		currentInitVersion := platform.GetInitHAConditionalCompatibilityVersion(ctx)

		// Perform init steps that are common in all cases
		if err = initPlatformCommon(ctx, &cloudlet, &myCloudletInfo, *physicalName, &pc, caches, nodeMgr.AccessApiClient, &highAvailabilityManager, updateCloudletStatus); err == nil {
			log.SpanLog(ctx, log.DebugLevelInfo, "common init functions done", "PlatformInstanceActive", highAvailabilityManager.PlatformInstanceActive)
			crmdata.PlatformCommonInitDone = true
			// get caches from controller
			waitControllerSync(ctx, &cloudlet, &myCloudletInfo, caches, updateCloudletStatus)

			log.SpanLog(ctx, log.DebugLevelInfo, waitingForPlatformActiveLog, "PlatformInstanceActive", highAvailabilityManager.PlatformInstanceActive)
			// wait for activity to be gained, This can happen on startup or on switchover
			<-crmdata.WaitPlatformActive

			if highAvailabilityManager.HAEnabled {
				// see if we can avoid full initialzation after switchover
				prevInitVersion, err := highAvailabilityManager.GetValue(ctx, InitCompatibilityVersionKey)
				if err != nil {
					// redis may be down, a full init is needed
					log.SpanLog(ctx, log.DebugLevelInfo, "error getting InitCompatibilityVersionKey from haMgr", "err", err)
					conditionalInitRequired = true
				}
				versionMatch := prevInitVersion == currentInitVersion
				log.SpanLog(ctx, log.DebugLevelInfo, "comparing previous and new init versions", "prevInitVersion", prevInitVersion, "currentInitVersion", currentInitVersion, "versionMatch", versionMatch)
				if versionMatch {
					// version matches now see if the cloudletInfo can be found
					err = crmdata.GetCloudletInfoFromHACache(ctx, &myCloudletInfo)
					if err != nil {
						// if we got this far then redis must be OK because the version matches. So this is unexpected.
						cspan.Finish()
						log.FatalLog("unexpected error getting cloudlet info from HA cache", "err", err)
					}
					// update the container version as this may not match what is in the cache
					myCloudletInfo.ContainerVersion = cloudletContainerVersion
					if myCloudletInfo.State == dme.CloudletState_CLOUDLET_STATE_READY {
						log.SpanLog(ctx, log.DebugLevelInfo, "conditional init not required as cloudlet was previously ready and versions match")
						conditionalInitRequired = false
					}
				} else {
					log.SpanLog(ctx, log.DebugLevelInfo, "version mismatch, full init required")
				}

			}
			log.SpanLog(ctx, log.DebugLevelInfo, "platform became active", "conditionalInitRequired", conditionalInitRequired, "state", myCloudletInfo.State.String())
		}
		if err == nil {

			err = platform.ActiveChanged(ctx, true)
			log.SpanLog(ctx, log.DebugLevelInfo, "ActiveChanged done", "err", err)
			if err == nil {
				if conditionalInitRequired {
					err = initPlatformHAConditional(ctx, &cloudlet, &myCloudletInfo, caches, updateCloudletStatus)
				}
			}
		}
		if err != nil {
			myCloudletInfo.Errors = append(myCloudletInfo.Errors, err.Error())
			myCloudletInfo.State = dme.CloudletState_CLOUDLET_STATE_ERRORS
		} else {
			// If cloudlet release version is known, update cloudletInfo with release version details
			myCloudletInfo.ReleaseVersion = os.Getenv("MEX_RELEASE_VERSION")

			// at this point we are ok to do periodic refresh of the platform init compatibility version in the HA Manager
			// because we have either matched the version from a switchover or have done a conditional init
			crmdata.UpdateHACompatibilityVersion = true
			myCloudletInfo.Errors = nil
			myCloudletInfo.State = dme.CloudletState_CLOUDLET_STATE_READY
			if cloudlet.TrustPolicy == "" {
				myCloudletInfo.TrustPolicyState = edgeproto.TrackedState_NOT_PRESENT
			} else {
				myCloudletInfo.TrustPolicyState = edgeproto.TrackedState_READY
			}
		}
		crmdata.CloudletInfoCache.Update(ctx, &myCloudletInfo, 0)
		log.SpanLog(ctx, log.DebugLevelInfo, "sent cloudletinfocache update")

		if features.RequiresCertRefresh {
			// start proxy certs
			proxyCerts = certs.NewProxyCerts(ctx, pc.CloudletKey, platform, pc.AccessApi, pc.NodeMgr, &highAvailabilityManager, features, pc.CommercialCerts, pc.EnvoyWithCurlImage)
			proxyCerts.Start(ctx)
		}

		cspan.Finish()

		if err != nil {
			// die so CRM can restart and try again
			log.FatalLog("Platform init fail", "err", err)
		}
	}()

	// setup crm notify listener (for shepherd)
	var notifyServ notify.ServerMgr
	InitSrvNotify(&notifyServ, &nodeMgr, crmdata.CRMHandler)
	notifyServ.Start(nodeMgr.Name(), *notifySrvAddr, notifyServerTls)
	notifyServer = &notifyServ

	log.SpanLog(ctx, log.DebugLevelInfra, "Starting Cloudlet resource refresh thread", "cloudlet", myCloudletInfo.Key)
	crmdata.StartInfraResourceRefreshThread()
	finishInfraResourceThread = true

	if haEnabled {
		crmdata.StartUpdateCloudletInfoHAThread(ctx)
		finishUpdateCloudletInfoHAThread = true
	}

	return nil
}

func Stop() {
	if proxyCerts != nil {
		proxyCerts.Stop()
		proxyCerts = nil
	}
	if finishInfraResourceThread {
		crmdata.FinishInfraResourceRefreshThread()
		finishInfraResourceThread = false
	}
	if finishUpdateCloudletInfoHAThread {
		crmdata.FinishUpdateCloudletInfoHAThread()
		finishUpdateCloudletInfoHAThread = false
	}
	if notifyServer != nil {
		notifyServer.Stop()
		notifyServer = nil
	}
	if notifyClient != nil {
		notifyClient.Stop()
		notifyClient = nil
	}
	nodeMgr.Finish()
	crmdata = nil
}

// initPlatformCommon does common init functions whether active or standby
func initPlatformCommon(ctx context.Context, cloudlet *edgeproto.Cloudlet, cloudletInfo *edgeproto.CloudletInfo, physicalName string, platformConfig *pf.PlatformConfig, caches *pf.Caches, accessClient edgeproto.CloudletAccessApiClient, haMgr *redundancy.HighAvailabilityManager, updateCallback edgeproto.CacheUpdateCallback) error {
	loc := util.DNSSanitize(cloudletInfo.Key.Name) //XXX  key.name => loc
	oper := util.DNSSanitize(cloudletInfo.Key.Organization)

	if cloudlet.GpuConfig.Driver.Name != "" {
		platformConfig.GPUConfig = &cloudlet.GpuConfig
	}

	log.SpanLog(ctx, log.DebugLevelInfra, "init platform", "location(cloudlet.key.name)", loc, "operator", oper, "Platform type", cloudlet.PlatformType)
	err := platform.InitCommon(ctx, platformConfig, caches, haMgr, updateCallback)
	return err
}

func waitControllerSync(ctx context.Context, cloudlet *edgeproto.Cloudlet, cloudletInfo *edgeproto.CloudletInfo, caches *pf.Caches, updateCallback edgeproto.CacheUpdateCallback) {
	log.SpanLog(ctx, log.DebugLevelInfo, "waitControllerSync")

	myCloudletInfo.State = dme.CloudletState_CLOUDLET_STATE_NEED_SYNC
	log.SpanLog(ctx, log.DebugLevelInfra, "cloudlet needs sync data", "state", myCloudletInfo.State, "myCloudletInfo", myCloudletInfo)
	crmdata.ControllerSyncInProgress = true
	crmdata.CloudletInfoCache.Update(ctx, &myCloudletInfo, 0)

	// Wait for CRM to receive cluster and appinst data from notify
	select {
	case <-crmdata.ControllerSyncDone:
		if !crmdata.CloudletCache.Get(&myCloudletInfo.Key, cloudlet) {
			log.FatalLog("failed to get sync data from controller")
		}
	case <-time.After(ControllerTimeout):
		log.FatalLog("Timed out waiting for sync data from controller")
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "controller sync data received")
	myCloudletInfo.ControllerCacheReceived = true
	crmdata.CloudletInfoCache.Update(ctx, &myCloudletInfo, 0)
}

// initPlatformHAConditionalCommon does init functions for first startup, or a switchover which requires full initialization
func initPlatformHAConditional(ctx context.Context, cloudlet *edgeproto.Cloudlet, cloudletInfo *edgeproto.CloudletInfo, caches *pf.Caches, updateCallback edgeproto.CacheUpdateCallback) error {
	log.SpanLog(ctx, log.DebugLevelInfo, "initPlatformHAConditional")

	err := platform.InitHAConditional(ctx, updateCallback)
	if err != nil {
		log.FatalLog("Platform InitHAConditional fail", "err", err)
	}
	err = crmdata.GatherInitialCloudletInfo(ctx, cloudlet, platform, cloudletInfo, updateCallback)
	// just log error
	log.SpanLog(ctx, log.DebugLevelInfra, "GatherInitialCloudletInfo done", "state", myCloudletInfo.State, "err", err)

	// Update AppInst runtime info in case it has changed
	crmdata.RefreshAppInstRuntime(ctx)

	if err == nil {
		err = platform.PerformUpgrades(ctx, caches, myCloudletInfo.State)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfra, "Platform upgrades failed", "err", err)
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "initPlatformHAConditional done", "cloudlet state", myCloudletInfo.State, "myCloudletInfo", myCloudletInfo, "err", err)
	return err
}

// Read file "/etc/mex-release" from original base vm image and parse certain env variables.
func readMexReleaseFileVars(ctx context.Context) (map[string]string, error) {
	filePath := "/etc/mex-release"
	m := make(map[string]string)

	file, err := os.Open(filePath)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Opening file /etc/mex-release failed", "err", err)
		return m, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		env := scanner.Text()
		envPair := strings.SplitN(env, "=", 2)
		if len(envPair) != 2 {
			continue
		}
		key := envPair[0]
		value := envPair[1]
		if key == envMexBuild || key == envMexBuildTag || key == envMexBuildFlavor {
			m[key] = value
		}
	}

	if err := scanner.Err(); err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Scanner failed on file /etc/mex-release", "err", err)
	}
	return m, nil
}

func getMexReleaseInfo(ctx context.Context) {
	m, err := readMexReleaseFileVars(ctx)
	if err != nil {
		return
	}
	if nodeMgr.MyNode.Properties == nil {
		nodeMgr.MyNode.Properties = make(map[string]string)
	}
	k := envMexBuild
	v, ok := m[k]
	if ok {
		nodeMgr.MyNode.Properties[k] = v
	}
	k = envMexBuildTag
	v, ok = m[k]
	if ok {
		nodeMgr.MyNode.Properties[k] = v
	}
	k = envMexBuildFlavor
	v, ok = m[k]
	if ok {
		nodeMgr.MyNode.Properties[k] = v
	}
}
