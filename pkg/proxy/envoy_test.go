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

package proxy

import (
	"context"
	"fmt"
	"testing"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/test/testutil"
	"github.com/stretchr/testify/require"
)

func TestPortMap(t *testing.T) {
	testPorts := "tcp:1,tcp:2,udp:5"
	testMap, err := buildPortsMapFromString(testPorts)
	require.Nil(t, err)
	_, found := testMap["tcp:1"]
	require.True(t, found)
	_, found = testMap["tcp:2"]
	require.True(t, found)
	_, found = testMap["udp:5"]
	require.True(t, found)
	require.Equal(t, 3, len(testMap))
	// test ranges
	testPorts = "tcp:1-10,tcp:23-28,udp:5-10"
	testMap, err = buildPortsMapFromString(testPorts)
	require.Nil(t, err)
	require.Equal(t, 22, len(testMap))
	for ii := 1; ii <= 10; ii++ {
		key := fmt.Sprintf("tcp:%d", ii)
		_, found = testMap[key]
		require.True(t, found)
	}
	for ii := 23; ii <= 28; ii++ {
		key := fmt.Sprintf("tcp:%d", ii)
		_, found = testMap[key]
		require.True(t, found)
	}
	for ii := 5; ii <= 10; ii++ {
		key := fmt.Sprintf("udp:%d", ii)
		_, found = testMap[key]
		require.True(t, found)
	}
	// test "all"
	testPorts = "all"
	testMap, err = buildPortsMapFromString(testPorts)
	require.Nil(t, err)
	require.Equal(t, 0, len(testMap))
	// invalid string
	testPorts = "nonport:12"
	testMap, err = buildPortsMapFromString(testPorts)
	require.NotNil(t, err)
	require.Nil(t, testMap)
}

func TestGenerateEnvoyYaml(t *testing.T) {
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	metricIP := cloudcommon.ProxyMetricsDefaultListenIP
	metricUDS := false
	config := &ProxyConfig{
		ListenIP:   "0.0.0.0",
		ListenIPV6: "::",
		DestIP:     "10.101.1.101",
		DestIPV6:   "fc00:101:ecec:1::65",
	}
	appInst := &edgeproto.AppInst{
		MappedPorts: []edgeproto.InstPort{{
			Proto:        dme.LProto_L_PROTO_TCP,
			InternalPort: 5677,
			PublicPort:   5677,
			Tls:          true,
		}, {
			Proto:        dme.LProto_L_PROTO_HTTP,
			InternalPort: 5678,
			PublicPort:   5678,
			Tls:          false,
		}},
	}
	envoyData, sdsData, isTLS, err := generateEnvoyYaml(ctx, "test", config, metricIP, metricUDS, appInst)
	require.Nil(t, err)
	require.True(t, isTLS)

	testutil.CompareExpectedFileData(t, "test-envoy-config", "yaml", envoyData)
	testutil.CompareExpectedFileData(t, "test-envoy-sds", "yaml", sdsData)
}
