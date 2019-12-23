package main

import (
	"context"
	"testing"

	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/testutil"
	"github.com/stretchr/testify/require"
)

func TestAutoProvPolicyApi(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelEtcd | log.DebugLevelApi)
	log.InitTracer("")
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())
	testinit()

	dummy := dummyEtcd{}
	dummy.Start()

	sync := InitSync(&dummy)
	InitApis(sync)
	sync.Start()
	defer sync.Done()

	testutil.InternalAutoProvPolicyTest(t, "cud", &autoProvPolicyApi, testutil.AutoProvPolicyData)

	testutil.InternalFlavorCreate(t, &flavorApi, testutil.FlavorData)
	testutil.InternalOperatorCreate(t, &operatorApi, testutil.OperatorData)
	testutil.InternalCloudletCreate(t, &cloudletApi, testutil.CloudletData)

	// test adding cloudlet to policy
	pc := edgeproto.AutoProvPolicyCloudlet{}
	pc.Key = testutil.AutoProvPolicyData[0].Key
	pc.CloudletKey = testutil.CloudletData[0].Key

	_, err := autoProvPolicyApi.AddAutoProvPolicyCloudlet(ctx, &pc)
	require.Nil(t, err, "add auto prov policy cloudlet")
	policy := edgeproto.AutoProvPolicy{}
	found := autoProvPolicyApi.cache.Get(&pc.Key, &policy)
	require.True(t, found, "get auto prov policy %v", pc.Key)
	require.Equal(t, 1, len(policy.Cloudlets))
	require.Equal(t, pc.CloudletKey, policy.Cloudlets[0].Key)

	// test adding another cloudlet to policy
	pc2 := edgeproto.AutoProvPolicyCloudlet{}
	pc2.Key = testutil.AutoProvPolicyData[0].Key
	pc2.CloudletKey = testutil.CloudletData[1].Key

	_, err = autoProvPolicyApi.AddAutoProvPolicyCloudlet(ctx, &pc2)
	require.Nil(t, err, "add auto prov policy cloudlet")
	found = autoProvPolicyApi.cache.Get(&pc2.Key, &policy)
	require.True(t, found, "get auto prov policy %v", pc2.Key)
	require.Equal(t, 2, len(policy.Cloudlets))
	require.Equal(t, pc2.CloudletKey, policy.Cloudlets[1].Key)

	// remove cloudlet from policy
	_, err = autoProvPolicyApi.RemoveAutoProvPolicyCloudlet(ctx, &pc)
	require.Nil(t, err, "remove auto prov policy cloudlet")
	found = autoProvPolicyApi.cache.Get(&pc.Key, &policy)
	require.True(t, found, "get auto prov policy %v", pc.Key)
	require.Equal(t, 1, len(policy.Cloudlets))
	require.Equal(t, pc2.CloudletKey, policy.Cloudlets[0].Key)

	// remove last cloudlet from policy
	_, err = autoProvPolicyApi.RemoveAutoProvPolicyCloudlet(ctx, &pc2)
	require.Nil(t, err, "remove auto prov policy cloudlet")
	found = autoProvPolicyApi.cache.Get(&pc2.Key, &policy)
	require.True(t, found, "get auto prov policy %v", pc2.Key)
	require.Equal(t, 0, len(policy.Cloudlets))

	// try to add policy for non-existent cloudlet
	pc.CloudletKey.Name = ""
	_, err = autoProvPolicyApi.AddAutoProvPolicyCloudlet(ctx, &pc)
	require.NotNil(t, err)

	dummy.Stop()
}
