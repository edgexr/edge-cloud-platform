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

package certs

import (
	"context"
	"testing"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/node"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/pc"
	"github.com/edgexr/edge-cloud-platform/pkg/redundancy"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
	"github.com/stretchr/testify/require"
)

type testGetPublicCert struct {
	count int
}

func (s *testGetPublicCert) GetPublicCert(ctx context.Context, commonName string) (*vault.PublicCert, error) {
	s.count++
	return &vault.PublicCert{
		Cert: "test-cert",
		Key:  "test-key",
		TTL:  3600,
	}, nil
}

type testRootLBAPI struct {
	clients map[string]platform.RootLBClient
}

func (s *testRootLBAPI) GetRootLBClients(ctx context.Context) (map[string]platform.RootLBClient, error) {
	return s.clients, nil
}

func TestProxyCerts(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelInfra)
	log.InitTracer(nil)
	defer log.FinishTracer()

	ctx := log.StartTestSpan(context.Background())

	// required input data
	cloudletKey := edgeproto.CloudletKey{
		Name:         "test-cloudlet",
		Organization: "operorg",
	}
	rootLBAPI := testRootLBAPI{
		clients: make(map[string]platform.RootLBClient),
	}
	publicCertAPI := testGetPublicCert{}
	nodeMgr := node.NodeMgr{}
	haMgr := &redundancy.HighAvailabilityManager{
		PlatformInstanceActive: true,
	}
	features := edgeproto.PlatformFeatures{}
	// fake local file
	AtomicCertsUpdater = "certifications_test.go"

	// create new ProxyCerts
	proxyCerts := NewProxyCerts(ctx, &cloudletKey, &rootLBAPI, &publicCertAPI, &nodeMgr, haMgr, &features, true)

	testClient := &pc.TestClient{}

	// start refresh with no rootLBs defined, should do nothing
	err := proxyCerts.refreshCerts(ctx)
	require.Nil(t, err)
	require.Equal(t, 0, len(proxyCerts.certs))
	require.Equal(t, 0, publicCertAPI.count)
	require.Equal(t, 0, len(testClient.Cmds))

	// Trigger creating a new cert and writing it to the LB
	fqdn := "test-fqdn.edgecloud.ut"
	wcFqdn := "*.edgecloud.ut"
	lbName := "test-lbname"
	lbClient := platform.RootLBClient{
		Client: testClient,
		FQDN:   fqdn,
	}
	testClient.Cmds = []string{}

	err = proxyCerts.SetupTLSCerts(ctx, fqdn, lbName, testClient)
	require.Nil(t, err)
	require.Equal(t, 1, publicCertAPI.count)
	require.Equal(t, 1, len(proxyCerts.certs))
	_, ok := proxyCerts.certs[wcFqdn]
	require.True(t, ok)
	require.True(t, len(testClient.Cmds) > 0)
	testClient.Cmds = []string{}

	// check that calling it again pulls from cache
	err = proxyCerts.SetupTLSCerts(ctx, fqdn, lbName, testClient)
	require.Nil(t, err)
	require.Equal(t, 1, publicCertAPI.count)
	require.Equal(t, 1, len(proxyCerts.certs))

	// check that wildcard picks same cert from cache
	fqdn2 := "test-fqdn2.edgecloud.ut"
	lbName2 := "test-lbname2"
	require.Equal(t, wcFqdn, getWildcardName(fqdn2))
	lbClient2 := platform.RootLBClient{
		Client: testClient,
		FQDN:   fqdn2,
	}
	testClient.Cmds = []string{}

	err = proxyCerts.SetupTLSCerts(ctx, fqdn2, lbName2, testClient)
	require.Nil(t, err)
	require.Equal(t, 1, publicCertAPI.count)
	require.Equal(t, 1, len(proxyCerts.certs))
	_, ok = proxyCerts.certs[wcFqdn]
	require.True(t, ok)
	require.True(t, len(testClient.Cmds) > 0)

	// Create a new cert for a different domain
	fqdn3 := "test-fqdn.glowcloud.ut"
	wcFqdn3 := "*.glowcloud.ut"
	lbName3 := "gc-lbname"
	lbClient3 := platform.RootLBClient{
		Client: testClient,
		FQDN:   fqdn3,
	}
	testClient.Cmds = []string{}

	err = proxyCerts.SetupTLSCerts(ctx, fqdn3, lbName3, testClient)
	require.Nil(t, err)
	require.Equal(t, 2, publicCertAPI.count)
	require.Equal(t, 2, len(proxyCerts.certs))
	_, ok = proxyCerts.certs[wcFqdn3]
	require.True(t, ok)
	require.True(t, len(testClient.Cmds) > 0)
	testClient.Cmds = []string{}

	// Test refresh not needed
	refreshThreshold = time.Second
	publicCertAPI.count = 0
	testClient.Cmds = []string{}
	rootLBAPI.clients = map[string]platform.RootLBClient{
		lbName:  lbClient,
		lbName2: lbClient2,
		lbName3: lbClient3,
	}
	err = proxyCerts.refreshCerts(ctx)
	require.Nil(t, err)
	require.Equal(t, 0, publicCertAPI.count)
	require.Equal(t, 0, len(testClient.Cmds))

	// Test refresh for expired certs (cert TTL is 60min)
	refreshThreshold = 24 * time.Hour
	publicCertAPI.count = 0
	err = proxyCerts.refreshCerts(ctx)
	require.Nil(t, err)
	require.Equal(t, 2, publicCertAPI.count)
	require.Equal(t, 2, len(proxyCerts.certs))
	require.True(t, len(testClient.Cmds) > 0)

	// remove LB2, refresh again (same effect)
	publicCertAPI.count = 0
	rootLBAPI.clients = map[string]platform.RootLBClient{
		lbName:  lbClient,
		lbName3: lbClient3,
	}
	err = proxyCerts.refreshCerts(ctx)
	require.Nil(t, err)
	require.Equal(t, 2, publicCertAPI.count)
	require.Equal(t, 2, len(proxyCerts.certs))
	require.True(t, len(testClient.Cmds) > 0)

	// remove other LB3, cert should be removed
	publicCertAPI.count = 0
	rootLBAPI.clients = map[string]platform.RootLBClient{
		lbName: lbClient,
	}
	err = proxyCerts.refreshCerts(ctx)
	require.Nil(t, err)
	require.Equal(t, 1, publicCertAPI.count)
	require.Equal(t, 1, len(proxyCerts.certs))
	require.True(t, len(testClient.Cmds) > 0)

	// remove other LB1, all certs now removed
	publicCertAPI.count = 0
	testClient.Cmds = []string{}
	rootLBAPI.clients = map[string]platform.RootLBClient{}
	err = proxyCerts.refreshCerts(ctx)
	require.Nil(t, err)
	require.Equal(t, 0, publicCertAPI.count)
	require.Equal(t, 0, len(proxyCerts.certs))
	require.Equal(t, 0, len(testClient.Cmds))

	// test start-up condition: no certs in cache, but LBs found
	require.Equal(t, 0, publicCertAPI.count)
	testClient.Cmds = []string{}
	rootLBAPI.clients = map[string]platform.RootLBClient{
		lbName:  lbClient,
		lbName2: lbClient2,
		lbName3: lbClient3,
	}
	err = proxyCerts.refreshCerts(ctx)
	require.Nil(t, err)
	require.Equal(t, 2, publicCertAPI.count)
	require.Equal(t, 2, len(proxyCerts.certs))
	require.True(t, len(testClient.Cmds) > 0)

	// check that we can get cert from cache after start-up condition
	publicCertAPI.count = 0
	testClient.Cmds = []string{}
	err = proxyCerts.SetupTLSCerts(ctx, fqdn, lbName, testClient)
	require.Nil(t, err)
	require.Equal(t, 0, publicCertAPI.count)
	require.True(t, len(testClient.Cmds) > 0)
}
