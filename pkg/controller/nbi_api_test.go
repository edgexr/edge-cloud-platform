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
	"net/http"
	"testing"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/api/nbi"
	"github.com/edgexr/edge-cloud-platform/pkg/ccrmdummy"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/regiondata"
	"github.com/edgexr/edge-cloud-platform/test/nbitest"
	"github.com/edgexr/edge-cloud-platform/test/testutil"
	"github.com/stretchr/testify/require"
)

func TestNBIAPI(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelEtcd | log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())
	_appDNSRoot := "testappinstapi.net"
	*appDNSRoot = _appDNSRoot
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
	ccrm := ccrmdummy.StartDummyCCRM(ctx, testSvcs.DummyVault.Config, &dummy)
	registerDummyCCRMConn(t, ccrm)
	defer ccrm.Stop()

	reduceInfoTimeouts(t, ctx, apis)

	// create supporting data
	addTestPlatformFeatures(t, ctx, apis, testutil.PlatformFeaturesData())
	testutil.InternalFlavorCreate(t, apis.flavorApi, testutil.FlavorData())
	testutil.InternalGPUDriverCreate(t, apis.gpuDriverApi, testutil.GPUDriverData())
	testutil.InternalResTagTableCreate(t, apis.resTagTableApi, testutil.ResTagTableData())
	testutil.InternalZoneCreate(t, apis.zoneApi, testutil.ZoneData())
	testutil.InternalCloudletCreate(t, apis.cloudletApi, testutil.CloudletData())
	insertCloudletInfo(ctx, apis, testutil.CloudletInfoData())

	nbiApis := NewNBIAPI(apis)

	// Test NBI by iterating over every App, creating the App,
	// deploying the App to every Zone, and then cleaning up.
	for _, appData := range nbitest.AppData() {
		req := nbi.SubmitAppRequestObject{
			Body: appData.NBI,
		}
		resp, err := nbiApis.SubmitApp(ctx, req)
		require.Nil(t, err)
		resp201, ok := resp.(nbi.SubmitApp201JSONResponse)
		require.True(t, ok)
		require.NotNil(t, resp201.Body.AppId)
		appID := *resp201.Body.AppId

		getReq := nbi.GetAppRequestObject{
			AppId: appID,
		}
		getResp, err := nbiApis.GetApp(ctx, getReq)
		require.Nil(t, err)
		getResp200, ok := getResp.(nbi.GetApp200JSONResponse)
		require.True(t, ok)
		// set AppID to make equal
		appData.NBI.AppId = &appID
		require.Equal(t, appData.NBI, getResp200.Body.AppManifest)

		// instance app across given zones
		zones := []*edgeproto.Zone{}
		err = apis.zoneApi.cache.Show(&edgeproto.Zone{}, func(obj *edgeproto.Zone) error {
			z := obj.Clone()
			zones = append(zones, z)
			return nil
		})
		require.Nil(t, err)

		for _, zone := range zones {
			if zone.Key.Name == "USWest" && !appData.Edgeproto.AllowServerless {
				// skip zone USWest for standalone apps, as that
				// zone only has a single cloudlet which requires
				// serverless apps.
				continue
			}

			// create the App Instance
			appInstName := appData.NBI.Name + "-" + zone.Key.Name
			body := nbi.CreateAppInstanceJSONBody{
				Name:            appInstName,
				AppId:           appID,
				EdgeCloudZoneId: zone.ObjId,
			}
			req := nbi.CreateAppInstanceRequestObject{}
			req.Body = (*nbi.CreateAppInstanceJSONRequestBody)(&body)
			resp, err := nbiApis.CreateAppInstance(ctx, req)
			require.Nil(t, err)
			resp202, ok := resp.(nbi.CreateAppInstance202JSONResponse)
			require.True(t, ok)
			require.NotNil(t, resp202.Body.AppInstanceId)
			appInstID := resp202.Body.AppInstanceId

			// do a get to check it
			getReq := nbi.GetAppInstanceRequestObject{}
			getReq.Params.AppInstanceId = &appInstID
			getResp, err := nbiApis.GetAppInstance(ctx, getReq)
			require.Nil(t, err)
			getResp200, ok := getResp.(nbi.GetAppInstance200JSONResponse)
			require.True(t, ok, "expect 200 but got %T", getResp)
			require.NotNil(t, getResp200.Body)
			require.Equal(t, 1, len(getResp200.Body))
			appInstOut := (getResp200.Body)[0]

			// craft the expected value
			expInst := appData.InstTemplate
			expInst.Name = appInstName
			expInst.AppInstanceId = appInstID
			expInst.AppId = appID
			expInst.EdgeCloudZoneId = zone.ObjId
			if appInstOut.ComponentEndpointInfo != nil {
				endpoints := *appInstOut.ComponentEndpointInfo
				// require FQDNs set, but don't check actual value because it
				// requires grabbing protobuf objects
				for ii := range endpoints {
					fqdn := endpoints[ii].AccessPoints.Fqdn
					require.NotNil(t, fqdn, endpoints[ii].InterfaceId)
					require.True(t, len(*fqdn) > 0)
					// nil out for compare
					endpoints[ii].AccessPoints.Fqdn = nil
				}
			}
			// require ClusterRef set, but it's a generated ID,
			// so don't check the actual value
			require.NotNil(t, appInstOut.KubernetesClusterRef)
			require.True(t, len(*appInstOut.KubernetesClusterRef) > 0)
			appInstOut.KubernetesClusterRef = nil
			require.Equal(t, *expInst, appInstOut)

			// delete the AppInst
			delReq := nbi.DeleteAppInstanceRequestObject{}
			delReq.AppInstanceId = appInstID
			delResp, err := nbiApis.DeleteAppInstance(ctx, delReq)
			require.Nil(t, err)
			_, ok = delResp.(nbi.DeleteAppInstance202Response)
			require.True(t, ok)

			// confirm AppInst is deleted
			getResp, err = nbiApis.GetAppInstance(ctx, getReq)
			require.Nil(t, err)
			getResp200, ok = getResp.(nbi.GetAppInstance200JSONResponse)
			require.True(t, ok, "expect 200 but got %T", getResp)
			if getResp200.Body != nil {
				require.Equal(t, 0, len(getResp200.Body))
			} else {
				require.Nil(t, 0, getResp200.Body)
			}
		}

		// delete app
		delReq := nbi.DeleteAppRequestObject{}
		delReq.AppId = appID
		delResp, err := nbiApis.DeleteApp(ctx, delReq)
		require.Nil(t, err)
		_, ok = delResp.(nbi.DeleteApp202Response)
		require.True(t, ok, delResp)

		// confirm App is deleted
		_, err = nbiApis.GetApp(ctx, getReq)
		requireErrRespCode(t, http.StatusNotFound, err)
	}
}

func requireErrRespCode(t *testing.T, code int, err error) {
	require.NotNil(t, err)
	errorInfo, ok := err.(*nbi.ErrorInfo)
	if !ok {
		errorInfo = &nbi.ErrorInfo{
			Status: http.StatusBadRequest,
		}
	}
	require.Equal(t, code, errorInfo.Status)
}
