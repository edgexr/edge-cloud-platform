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

package autoprov

import (
	"context"
	"fmt"
	"testing"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/test/testutil"
	"github.com/stretchr/testify/require"
)

func TestRetry(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelNotify | log.DebugLevelApi | log.DebugLevelMetrics)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	retry := newRetryTracker()
	appInst := testutil.AppInstData()[0]

	// no error should not register a retry
	retry.registerDeployResult(ctx, &appInst, nil)
	require.Equal(t, 0, len(retry.allFailures))

	// already exists error should not register a retry
	retry.registerDeployResult(ctx, &appInst, appInst.Key.ExistsError())
	require.Equal(t, 0, len(retry.allFailures))

	// already exists error will have rpc related extra fields as part of err
	// we should not registry a retry for those errors as well
	retry.registerDeployResult(ctx, &appInst, fmt.Errorf("rpc error: code = Unknown desc = %v", appInst.Key.ExistsError()))
	require.Equal(t, 0, len(retry.allFailures))

	// if minmax requirement is already, then it should not register a retry
	retry.registerDeployResult(ctx, &appInst, fmt.Errorf("Create to satisfy min already met, ignoring"))
	require.Equal(t, 0, len(retry.allFailures))

	// an app could be deleted and it could be possible for autoprov service to deploy
	// an appInst against that app, ignore registering a retry for this
	retry.registerDeployResult(ctx, &appInst, fmt.Errorf("AppInst against App which is being deleted"))
	require.Equal(t, 0, len(retry.allFailures))

	// error should register a retry
	retry.registerDeployResult(ctx, &appInst, fmt.Errorf("failure"))
	require.Equal(t, 1, len(retry.allFailures))

	// retryTracker should return failure
	failure := retry.hasFailure(ctx, appInst.AppKey, appInst.ZoneKey)
	require.True(t, failure)

	cacheData.init(nil)
	minmax := newMinMaxChecker(&cacheData)
	runCount := 0
	minmax.workers.Init("test-retry", func(ctx context.Context, k interface{}) {
		appkey, ok := k.(edgeproto.AppKey)
		require.True(t, ok)
		require.Equal(t, appInst.AppKey, appkey)
		runCount++
	})
	// do retry should queue recheck and clear failure
	retry.doRetry(ctx, minmax)
	require.Equal(t, 0, len(retry.allFailures))
	minmax.workers.WaitIdle()
	require.Equal(t, 1, runCount)
}
