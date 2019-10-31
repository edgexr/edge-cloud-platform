package common

import (
	"context"
	"testing"

	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/testutil"
	"github.com/stretchr/testify/require"
)

// TestAutoScaleT primarily checks that AutoScale template parsing works, because
// otherwise cluster-svc could crash during runtime if template has an issue.
func TestAutoScaleT(t *testing.T) {
	log.InitTracer("")
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	clusterInst := testutil.ClusterInstData[0]

	policy := edgeproto.AutoScalePolicy{}
	policy.Key.Developer = clusterInst.Key.Developer
	policy.Key.Name = "test-policy"
	policy.MinNodes = 1
	policy.MaxNodes = 5
	policy.ScaleUpCpuThresh = 80
	policy.ScaleDownCpuThresh = 20
	policy.TriggerTimeSec = 60

	clusterInst.AutoScalePolicy = policy.Key.Name

	clusterSvc := ClusterSvc{}
	appInst := edgeproto.AppInst{}

	configs, err := clusterSvc.GetAppInstConfigs(ctx, &clusterInst, &appInst, &policy)
	require.Nil(t, err)
	require.Equal(t, 1, len(configs))
}
