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

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/regiondata"
	"github.com/edgexr/edge-cloud-platform/test/testutil"
	"github.com/stretchr/testify/require"
)

func TestZoneApi(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelEtcd | log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	testSvcs := testinit(ctx, t)
	defer testfinish(testSvcs)

	dummy := regiondata.InMemoryStore{}
	dummy.Start()

	sync := regiondata.InitSync(&dummy)
	apis := NewAllApis(sync)
	sync.Start()
	defer sync.Done()

	testutil.InternalZoneTest(t, "cud", apis.zoneApi, testutil.ZoneData())

	// test that showPlatformFeaturesForZone does not crash with missing data
	show := testutil.NewShowServerStream[*edgeproto.PlatformFeatures](ctx)
	err := apis.platformFeaturesApi.ShowPlatformFeaturesForZone(&edgeproto.ZoneKey{}, show)
	require.Nil(t, err)
	require.Equal(t, 0, len(show.Data))
	// test that showPlatformFeaturesForZone does not crash with missing zone
	show = testutil.NewShowServerStream[*edgeproto.PlatformFeatures](ctx)
	filter := edgeproto.ZoneKey{
		Name: "missing",
	}
	err = apis.platformFeaturesApi.ShowPlatformFeaturesForZone(&filter, show)
	require.Nil(t, err)
	require.Equal(t, 0, len(show.Data))

	dummy.Stop()
}
