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

package k8smgmt

import (
	"context"
	"testing"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/stretchr/testify/require"
)

func TestGetNetworkPolicy(t *testing.T) {
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	app := edgeproto.App{}
	app.Key.Organization = "devorg"
	app.Key.Name = "myapp"
	app.Key.Version = "1.0"
	app.Deployment = cloudcommon.DeploymentTypeKubernetes
	app.AllowServerless = true
	ci := edgeproto.ClusterInst{}
	ci.CloudletKey.Name = "cloudlet1"
	ci.CloudletKey.Organization = "operorg"
	ci.Key = *cloudcommon.GetDefaultMTClustKey(ci.CloudletKey)
	appInst := edgeproto.AppInst{}
	appInst.Key.Name = "appInst1"
	appInst.Key.Organization = app.Key.Organization
	appInst.AppKey = app.Key
	appInst.ClusterKey = ci.Key
	appInst.CompatibilityVersion = cloudcommon.GetAppInstCompatibilityVersion()

	// Non-multi-tenant cluster does not need a network policy
	ci.MultiTenant = false
	testGetNetworkPolicy(t, ctx, &app, &ci, &appInst, "only valid for namespaced", "")

	ci.MultiTenant = true
	// Network policy, no ports
	testGetNetworkPolicy(t, ctx, &app, &ci, &appInst, "", `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  labels:
    config: appinst1-devorg
  name: networkpolicy-appinst1-devorg
  namespace: appinst1-devorg
spec:
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: appinst1-devorg
`)

	// Network policy, with ports
	appInst.MappedPorts = []edgeproto.InstPort{
		{
			// http
			Proto:        dme.LProto_L_PROTO_HTTP,
			InternalPort: 443,
			PublicPort:   443,
		}, {
			// remapped port
			Proto:        dme.LProto_L_PROTO_TCP,
			InternalPort: 888,
			PublicPort:   818,
		}, {
			// udp
			Proto:        dme.LProto_L_PROTO_UDP,
			InternalPort: 10101,
			PublicPort:   10101,
		}, {
			// 1000 port range, mapped
			Proto:        dme.LProto_L_PROTO_TCP,
			InternalPort: 51000,
			EndPort:      51009,
			PublicPort:   61000,
		},
	}
	// backwards compatibility test
	oldAppInst := appInst
	oldAppInst.VirtualClusterKey.Name = "autocluster1"
	oldAppInst.VirtualClusterKey.Organization = edgeproto.OrganizationEdgeCloud
	oldAppInst.CompatibilityVersion = 0
	testGetNetworkPolicy(t, ctx, &app, &ci, &oldAppInst, "", `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  labels:
    config: devorg-myapp-10-autocluster1
  name: networkpolicy-devorg-myapp-10-autocluster1
  namespace: devorg-myapp-10-autocluster1
spec:
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: devorg-myapp-10-autocluster1
  - from:
    - ipBlock:
        cidr: 0.0.0.0/0
    ports:
    - port: 443
      protocol: TCP
    - port: 888
      protocol: TCP
    - port: 10101
      protocol: UDP
    - port: 51000
      protocol: TCP
    - port: 51001
      protocol: TCP
    - port: 51002
      protocol: TCP
    - port: 51003
      protocol: TCP
    - port: 51004
      protocol: TCP
    - port: 51005
      protocol: TCP
    - port: 51006
      protocol: TCP
    - port: 51007
      protocol: TCP
    - port: 51008
      protocol: TCP
    - port: 51009
      protocol: TCP
`)
	testGetNetworkPolicy(t, ctx, &app, &ci, &appInst, "", `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  labels:
    config: appinst1-devorg
  name: networkpolicy-appinst1-devorg
  namespace: appinst1-devorg
spec:
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: appinst1-devorg
  - from:
    - ipBlock:
        cidr: 0.0.0.0/0
    ports:
    - port: 443
      protocol: TCP
    - port: 888
      protocol: TCP
    - port: 10101
      protocol: UDP
    - port: 51000
      protocol: TCP
    - port: 51001
      protocol: TCP
    - port: 51002
      protocol: TCP
    - port: 51003
      protocol: TCP
    - port: 51004
      protocol: TCP
    - port: 51005
      protocol: TCP
    - port: 51006
      protocol: TCP
    - port: 51007
      protocol: TCP
    - port: 51008
      protocol: TCP
    - port: 51009
      protocol: TCP
`)
}

func testGetNetworkPolicy(t *testing.T, ctx context.Context, app *edgeproto.App, clusterInst *edgeproto.ClusterInst, appInst *edgeproto.AppInst, expectedErr string, expectedMF string) {
	names, err := GetKubeNames(clusterInst, app, appInst)
	require.Nil(t, err)
	mf, err := GetNetworkPolicy(ctx, app, appInst, names)
	if expectedErr != "" {
		require.NotNil(t, err)
		require.Contains(t, err.Error(), expectedErr)
	} else {
		require.Nil(t, err)
		require.Equal(t, expectedMF, mf)
	}
}
