package main

import (
	"context"
	"testing"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/test/testutil"
)

func TestCloudletNodeApi(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelEtcd | log.DebugLevelApi | log.DebugLevelNotify)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())
	testSvcs := testinit(ctx, t)
	defer testfinish(testSvcs)

	dummy := dummyEtcd{}
	dummy.Start()
	defer dummy.Stop()

	sync := InitSync(&dummy)
	apis := NewAllApis(sync)
	sync.Start()
	defer sync.Done()

	responder := DefaultDummyInfoResponder(apis)
	responder.InitDummyInfoResponder()

	reduceInfoTimeouts(t, ctx, apis)

	// create support data
	addTestPlatformFeatures(t, ctx, apis, testutil.PlatformFeaturesData())
	cloudletData := testutil.CloudletData()
	testutil.InternalFlavorCreate(t, apis.flavorApi, testutil.FlavorData())
	testutil.InternalGPUDriverCreate(t, apis.gpuDriverApi, testutil.GPUDriverData())
	testutil.InternalResTagTableCreate(t, apis.resTagTableApi, testutil.ResTagTableData())
	testutil.InternalCloudletCreate(t, apis.cloudletApi, cloudletData)

	testutil.InternalCloudletNodeTest(t, "cud", apis.cloudletNodeApi, testutil.CloudletNodeData())
	testutil.InternalCloudletNodeTest(t, "show", apis.cloudletNodeApi, testutil.CloudletNodeData())
}
