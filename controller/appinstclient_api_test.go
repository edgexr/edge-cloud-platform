package main

import (
	"context"
	"testing"

	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

// test server for ShowAppInstClient
type ShowAppInstClient struct {
	Data map[string]edgeproto.AppInstClient
	grpc.ServerStream
	Ctx context.Context
}

func (x *ShowAppInstClient) Init(ctx context.Context) {
	x.Data = make(map[string]edgeproto.AppInstClient)
	x.Ctx = ctx
}

func (x *ShowAppInstClient) Send(m *edgeproto.AppInstClient) error {
	x.Data[m.ClientKey.String()] = *m
	return nil
}

func (x *ShowAppInstClient) Context() context.Context {
	return x.Ctx
}

func TestAppInstClientApi(t *testing.T) {
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

	// Init settings default
	err := settingsApi.initDefaults(ctx)
	require.Nil(t, err, "settingsApi.initDefaults")

	// Init AppInstClient Server
	showServer := ShowAppInstClient{}
	showServer.Init(ctx)

	qSize := int(settingsApi.Get().MaxTrackedDmeClients)
	// Add a client for a non-existent AppInst
	appInstClientApi.Recv(ctx, &testutil.AppInstClientData[0])
	// Make sure that we didn't save it
	err = appInstClientApi.ShowAppInstClient(&testutil.AppInstClientKeyData[0], &showServer)
	require.NotNil(t, err, "Found an unexpected client")
	require.Contains(t, err.Error(), testutil.AppInstClientKeyData[0].Key.NotFoundError().Error())

	// Tests to verify that queue is being handled correctly
	// Add a channel for appInst1
	ch1 := make(chan edgeproto.AppInstClient, qSize)
	appInstClientApi.SetRecvChan(ctx, &testutil.AppInstClientKeyData[0], ch1)
	// Add Client for AppInst1
	appInstClientApi.AddAppInstClient(ctx, &testutil.AppInstClientData[0])
	// Check client is received in the channel
	appInstClient := <-ch1
	assert.Equal(t, testutil.AppInstClientData[0], appInstClient)
	// 3. Add a second channel for the different appInst
	ch2 := make(chan edgeproto.AppInstClient, qSize)
	appInstClientApi.SetRecvChan(ctx, &testutil.AppInstClientKeyData[1], ch2)
	// Add a Client for AppInst2
	appInstClientApi.AddAppInstClient(ctx, &testutil.AppInstClientData[3])
	// Check client is received in the channel 2
	appInstClient = <-ch2
	assert.Equal(t, testutil.AppInstClientData[3], appInstClient)
	// Delete channel 2 - check that list is 0
	count := appInstClientApi.ClearRecvChan(ctx, &testutil.AppInstClientKeyData[1], ch2)
	assert.Equal(t, 0, count)
	// Delete non-existent channel, return is -1
	count = appInstClientApi.ClearRecvChan(ctx, &testutil.AppInstClientKeyData[1], ch2)
	assert.Equal(t, -1, count)
	// Add a second Channel for AppInst1
	ch12 := make(chan edgeproto.AppInstClient, qSize)
	appInstClientApi.SetRecvChan(ctx, &testutil.AppInstClientKeyData[0], ch12)
	// Check that AppInst1 client is received
	appInstClient = <-ch12
	assert.Equal(t, testutil.AppInstClientData[0], appInstClient)
	// Add a client 2 for AppInst1
	appInstClientApi.AddAppInstClient(ctx, &testutil.AppInstClientData[1])
	// Check that both of the channels recieve the AppInstClient
	appInstClient = <-ch1
	assert.Equal(t, testutil.AppInstClientData[1], appInstClient)
	appInstClient = <-ch12
	assert.Equal(t, testutil.AppInstClientData[1], appInstClient)
	// Delete Channel 1 - verify that count is 1
	count = appInstClientApi.ClearRecvChan(ctx, &testutil.AppInstClientKeyData[0], ch1)
	assert.Equal(t, 1, count)
	// Add client 3 for AppInst1
	appInstClientApi.AddAppInstClient(ctx, &testutil.AppInstClientData[2])
	// Verify that it's received in channel 2 for appInst1
	appInstClient = <-ch12
	assert.Equal(t, testutil.AppInstClientData[2], appInstClient)
	// Delete channel 2 - verify that count is 0
	count = appInstClientApi.ClearRecvChan(ctx, &testutil.AppInstClientKeyData[0], ch12)
	assert.Equal(t, 0, count)

	dummy.Stop()
}