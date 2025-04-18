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

package controller

import (
	"context"
	"testing"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/regiondata"
	"github.com/edgexr/edge-cloud-platform/test/testutil"
	"github.com/stretchr/testify/require"
	"go.etcd.io/etcd/client/v3/concurrency"
)

func TestFlavorApi(t *testing.T) {
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

	testutil.InternalFlavorTest(t, "cud", apis.flavorApi, testutil.FlavorData())
	testMasterFlavor(t, ctx, apis)
	dummy.Stop()
}

func testMasterFlavor(t *testing.T, ctx context.Context, apis *AllApis) {
	// We optionally maintain one generic modestly sized flavor for use
	// by the MasterNode of a nominal k8s cluster where numnodes (workers)
	// > 0 such that we don't run client workloads on that master. We can therefore
	// use a flavor size sufficent for that purpose only.
	// This mex flavor is created by the mexadmin when setting up a cloudlet that offers
	// optional resources that should not be requested by the master node.
	// The Name of the this flavor is stored in settings.MasterNodeFlavor, and in cases
	// of clusterInst creation per above, the name stored in settings will be looked up and
	// expected to exist. If not, the given nodeflavor in create cluster inst is used as was
	// prior to EC-1767
	var err error

	// ensure the master node default flavor is created, using the default value
	// of settings.MasterNodeFlavor
	cl := testutil.CloudletData()[1]
	var cli edgeproto.CloudletInfo = testutil.CloudletInfoData()[0]
	settings := apis.settingsApi.Get()
	masterFlavor := edgeproto.Flavor{}
	flavorKey := edgeproto.FlavorKey{}
	flavorKey.Name = settings.MasterNodeFlavor

	err = apis.cloudletApi.sync.ApplySTMWait(ctx, func(stm concurrency.STM) error {
		if !apis.flavorApi.store.STMGet(stm, &flavorKey, &masterFlavor) {
			// create the missing flavor
			masterFlavor.Key.Name = "MasterNodeFlavor"
			masterFlavor.Vcpus = 2
			masterFlavor.Disk = 40
			masterFlavor.Ram = 4096
			_, err = apis.flavorApi.CreateFlavor(ctx, &masterFlavor)
			require.Nil(t, err, "Create Master Node Flavor")
		}

		ostm := edgeproto.NewOptionalSTM(stm)
		vmspec, err := apis.resTagTableApi.GetVMSpec(ctx, ostm, masterFlavor.ToNodeResources(), "", cl, cli)
		require.Nil(t, err, "GetVmSpec masterNodeFlavor")
		require.Equal(t, "flavor.medium", vmspec.FlavorName)

		return nil
	})
	require.Nil(t, err)
}
