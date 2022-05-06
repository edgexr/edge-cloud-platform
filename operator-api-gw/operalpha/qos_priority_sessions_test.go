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

package operalpha

import (
	"testing"

	dme "github.com/edgexr/edge-cloud/d-match-engine/dme-proto"
	operator "github.com/edgexr/edge-cloud/d-match-engine/operator"
	"github.com/edgexr/edge-cloud/log"
	"github.com/test-go/testify/require"
	"golang.org/x/net/context"
)

func TestBadIpv4(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelInfra)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	// Intialize OperatorApiGw
	gw := &OperatorApiGw{}
	servers := operator.OperatorApiGwServers{}
	servers.QosSesAddr = "http://localhost:8081" // Not actually used because all tests fail before getting to the REST call.
	gw.Init("OPERALPHA", &servers)
	gw.SetQosSessionsApiKey("xxxx") // Not actually used because all tests fail before getting to the REST call.

	badIps := [9]string{"mobiledgex.net", "localhost", "192.168.0.BAD",
		"2001:0db8:85a3:0000:0000:8a2e:0370:7334", "500.0.0.1", "1.1.1.1.1",
		"0", "a.b.c.d", "-1.0.0.1"}
	log.SpanLog(ctx, log.DebugLevelDmereq, "TestBadIpv4", "badIps", badIps)

	// Test bad IPs for IpApplicationServer
	for _, badIp := range badIps {
		req := dme.QosPrioritySessionCreateRequest{}
		req.IpApplicationServer = badIp
		req.IpUserEquipment = "127.0.0.1"
		req.Profile = dme.QosSessionProfile_QOS_LOW_LATENCY

		_, err := gw.CreatePrioritySession(ctx, &req)
		require.Equal(t, err.Error(), "rpc error: code = InvalidArgument desc = Invalid Address for IpApplicationServer: "+badIp)
	}

	// Test bad IPs for IpUserEquipment
	for _, badIp := range badIps {
		req := dme.QosPrioritySessionCreateRequest{}
		req.IpApplicationServer = "192.168.0.1"
		req.IpUserEquipment = badIp
		req.Profile = dme.QosSessionProfile_QOS_LOW_LATENCY

		_, err := gw.CreatePrioritySession(ctx, &req)
		require.Equal(t, err.Error(), "rpc error: code = InvalidArgument desc = Invalid Address for IpUserEquipment: "+badIp)
	}
}
