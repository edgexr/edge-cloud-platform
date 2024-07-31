// Copyright 2024 EdgeXR, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controller

import (
	"context"
	"testing"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/regiondata"
	"github.com/edgexr/edge-cloud-platform/test/testutil"
)

func TestCloudletNodeApi(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelEtcd | log.DebugLevelApi | log.DebugLevelNotify)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())
	testSvcs := testinit(ctx, t)
	defer testfinish(testSvcs)

	dummy := regiondata.InMemoryStore{}
	dummy.Start()
	defer dummy.Stop()

	sync := regiondata.InitSync(&dummy)
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
