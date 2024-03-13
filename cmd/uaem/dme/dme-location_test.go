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

package main

import (
	"testing"
	"time"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
	uaemcommon "github.com/edgexr/edge-cloud-platform/pkg/uaem-common"
	uaemtest "github.com/edgexr/edge-cloud-platform/pkg/uaem-testutil"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"
)

func TestVerifyLoc(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelDmereq)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())
	span := log.SpanFromContext(ctx)

	eehandler, err := initEdgeEventsPlugin(ctx, "standalone")
	require.Nil(t, err, "init edge events plugin")
	uaemcommon.SetupMatchEngine(eehandler)
	uaemcommon.InitAppInstClients(time.Minute)
	defer uaemcommon.StopAppInstClients()
	operatorApiGw, _ = initOperator(ctx, "standalone")
	setupJwks()

	// add all data
	for _, app := range uaemtest.GenerateApps() {
		uaemcommon.AddApp(ctx, app)
	}
	for _, inst := range uaemtest.GenerateAppInsts() {
		uaemcommon.AddAppInst(ctx, inst)
	}
	serv := server{}
	// test verify location
	for ii, rr := range uaemtest.VerifyLocData {
		ctx := uaemcommon.PeerContext(context.Background(), "127.0.0.1", 123, span)

		regReply, err := serv.RegisterClient(ctx, &rr.Reg)
		assert.Nil(t, err, "register client")

		// Since we're directly calling functions, we end up
		// bypassing the interceptor which sets up the cookie key.
		// So set it on the context manually.
		ckey, err := uaemcommon.VerifyCookie(ctx, regReply.SessionCookie)
		require.Nil(t, err, "verify cookie")
		ctx = uaemcommon.NewCookieContext(ctx, ckey)

		reply, err := serv.VerifyLocation(ctx, &rr.Req)
		if err != nil {
			assert.Contains(t, err.Error(), rr.Error, "VerifyLocData[%d]", ii)
		} else {
			assert.Equal(t, &rr.Reply, reply, "VerifyLocData[%d]", ii)
		}
	}
}

func setupJwks() {
	// setup fake JWT key
	config := vault.NewConfig("foo", vault.NewAppRoleAuth("roleID", "secretID"))
	uaemcommon.Jwks.Init(config, "local", "dme")
	uaemcommon.Jwks.Meta.CurrentVersion = 1
	uaemcommon.Jwks.Keys[1] = &vault.JWK{
		Secret:  "12345",
		Refresh: "1s",
	}
}
