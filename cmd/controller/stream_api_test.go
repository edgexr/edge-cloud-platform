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
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/rediscache"
	"github.com/edgexr/edge-cloud-platform/test/testutil"
	"github.com/opentracing/opentracing-go"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func TestStreamObjs(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelEtcd | log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	t.Run("local-server", func(t *testing.T) {
		// Test with local server
		testSvcs := testinit(ctx, t, WithLocalRedis())
		defer testfinish(testSvcs)
		testStreamObjsWithServer(t, ctx)
	})
}

type ResCb struct {
	Data []string
	grpc.ServerStream
}

func (x *ResCb) Send(m *edgeproto.Result) error {
	x.Data = append(x.Data, m.Message)
	return nil
}

func testStreamObjsWithServer(t *testing.T, ctx context.Context) {
	// Simulate various API calls that use streams
	cctx := DefCallContext()
	streamKey := "testkey"
	streamObjApi := StreamObjApi{}
	StreamMsgReadTimeout = time.Second
	StreamMsgInfoReadTimeout = time.Second
	// Thread 1
	span1 := log.StartSpan(log.DebugLevelApi, "span1")
	ctx1 := log.ContextWithSpan(context.Background(), span1)
	defer span1.Finish()
	// Thread 2
	span2 := log.StartSpan(log.DebugLevelApi, "span2")
	ctx2 := log.ContextWithSpan(context.Background(), span2)
	defer span2.Finish()

	// convenience functions
	startStream := func(ctx context.Context, modRev int64) (*CbWrapper, *streamSend) {
		streamCb, _ := streamObjApi.newStream(ctx, cctx, streamKey, testutil.NewCudStreamoutAppInst(ctx))
		sendObj, err := streamObjApi.startStream(ctx, cctx, streamCb, modRev)
		require.Nil(t, err, modRev)
		return streamCb, sendObj
	}
	writeMsg := func(ctx context.Context, msg string) {
		addMsgToRedisStream(ctx, streamKey, map[string]interface{}{
			StreamMsgTypeMessage: msg,
		})
	}
	stop := func(ctx context.Context, sendObj *streamSend, cleanupStream CleanupStreamAction, objErr error) {
		err := streamObjApi.stopStream(ctx, cctx, streamKey, sendObj, objErr, cleanupStream)
		require.Nil(t, err)
	}
	verifyMsgs := func(expMsgs ...string) {
		cb := &ResCb{}
		err := streamObjApi.StreamMsgs(ctx, streamKey, cb)
		require.Nil(t, err)
		require.Equal(t, expMsgs, cb.Data)
	}
	verifyErr := func(e error) {
		cb := &ResCb{}
		err := streamObjApi.StreamMsgs(ctx, streamKey, cb)
		require.NotNil(t, err)
		require.Equal(t, e.Error(), err.Error())
	}
	verifyExists := func(exists bool) {
		exp := int64(0)
		if exists {
			exp = int64(1)
		}
		out, err := redisClient.Exists(ctx, streamKey).Result()
		require.Nil(t, err)
		require.Equal(t, exp, out)
	}
	var s1, s2 *streamSend
	wg := sync.WaitGroup{}

	// ============ Non-overlapping APIs ====================

	// create API
	_, s1 = startStream(ctx1, 1)
	writeMsg(ctx1, "createMsg1")
	writeMsg(ctx1, "createMsg2")
	stop(ctx1, s1, NoCleanupStream, nil)
	verifyExists(true)
	verifyMsgs("createMsg1", "createMsg2")

	// update API
	_, s1 = startStream(ctx1, 2)
	writeMsg(ctx1, "updateMsg1")
	writeMsg(ctx1, "updateMsg2")
	stop(ctx1, s1, NoCleanupStream, nil)
	verifyExists(true)
	verifyMsgs("updateMsg1", "updateMsg2")

	// delete API - stream should be deleted
	_, s1 = startStream(ctx1, 3)
	writeMsg(ctx1, "deleteMsg1")
	writeMsg(ctx1, "deleteMsg2")
	stop(ctx1, s1, CleanupStream, nil)
	verifyExists(false)

	// API with error
	_, s1 = startStream(ctx1, 4)
	writeMsg(ctx1, "errMsg1")
	expErr := errors.New("errorMsg1")
	stop(ctx1, s1, NoCleanupStream, expErr)
	verifyErr(expErr)

	// first messages should be SOM, but even if not,
	// start will reset the stream.
	writeMsg(ctx1, "badMsg1")
	_, s1 = startStream(ctx1, 5)
	writeMsg(ctx1, "goodMsg1")
	stop(ctx1, s1, NoCleanupStream, nil)
	verifyExists(true)
	verifyMsgs("goodMsg1")

	// =============== Overlapping APIs ===================

	// highest modRev wins (highest first)
	_, s1 = startStream(ctx1, 10)
	_, s2 = startStream(ctx2, 9)
	wg.Add(1)
	go func() {
		// test blocking read
		verifyMsgs("s1Msg1", "s1Msg2")
		wg.Done()
	}()
	writeMsg(ctx2, "s2Msg1")
	writeMsg(ctx1, "s1Msg1")
	writeMsg(ctx1, "s1Msg2")
	writeMsg(ctx2, "s2Msg2")
	stop(ctx1, s1, NoCleanupStream, nil)
	stop(ctx2, s2, NoCleanupStream, nil)
	verifyMsgs("s1Msg1", "s1Msg2")
	wg.Wait()

	// highest modRev wins (highest second)
	_, s1 = startStream(ctx1, 20)
	_, s2 = startStream(ctx2, 21)
	wg.Add(1)
	go func() {
		// test blocking read
		verifyMsgs("s2Msg1", "s2Msg2")
		wg.Done()
	}()
	writeMsg(ctx2, "s2Msg1")
	writeMsg(ctx1, "s1Msg1")
	writeMsg(ctx1, "s1Msg2")
	writeMsg(ctx2, "s2Msg2")
	stop(ctx1, s1, NoCleanupStream, nil)
	stop(ctx2, s2, NoCleanupStream, nil)
	verifyMsgs("s2Msg1", "s2Msg2")
	wg.Wait()

	// ensure non-winning API cannot delete stream
	_, s1 = startStream(ctx1, 30)
	_, s2 = startStream(ctx2, 31)
	wg.Add(1)
	go func() {
		// test blocking read
		verifyMsgs("s2Msg1", "s2Msg2")
		wg.Done()
	}()
	writeMsg(ctx2, "s2Msg1")
	writeMsg(ctx1, "s1Msg1")
	writeMsg(ctx1, "s1Msg2")
	writeMsg(ctx2, "s2Msg2")
	stop(ctx1, s1, CleanupStream, nil)
	stop(ctx2, s2, NoCleanupStream, nil)
	verifyMsgs("s2Msg1", "s2Msg2")
	wg.Wait()

	// Test Redis transaction code and modRev checks during
	// race conditions. Only the targetID should be left in the
	// stream, although other messages from stop may also be
	// present (but will be ignored during read).
	// Max numThread is 10, as redis connection pool is 10 connections
	// per CPU, and we don't know how many CPUs will be available for
	// the unit-tests.
	numThreads := 10
	numTimes := 10
	targetModRev := int64(numThreads*numTimes + 10)
	// precreate spans
	spans := []opentracing.Span{}
	for ii := 0; ii < numThreads; ii++ {
		spans = append(spans, log.StartSpan(log.DebugLevelApi, "testSpan"))
	}
	for ii := 0; ii < numThreads; ii++ {
		wg.Add(1)
		go func(_ii int) {
			xctx := log.ContextWithSpan(context.Background(), spans[_ii])
			defer spans[_ii].Finish()
			defer wg.Done()
			for jj := 0; jj < numTimes; jj++ {
				n := 10*_ii + jj
				// lower IDs and cleanup should be ignored
				modRev := int64(n)
				cleanup := CleanupStream
				// put target in the middle of the spawned threads
				if _ii == numThreads/2 && jj == numTimes/2 {
					modRev = targetModRev
					cleanup = NoCleanupStream
				}
				_, streamObj := startStream(xctx, modRev)
				writeMsg(xctx, fmt.Sprintf("msg%d", modRev))
				stop(xctx, streamObj, cleanup, nil)
			}
		}(ii)
	}
	wg.Wait()

	streamMsgs, err := redisClient.XRange(ctx, streamKey, rediscache.RedisSmallestId, rediscache.RedisGreatestId).Result()
	require.Nil(t, err, "get stream messages")
	require.Greater(t, len(streamMsgs), 0)
	// first entry should be target SOM
	require.Equal(t, targetModRev, getStreamModRev(streamMsgs[0].Values))
	// verify that only target ID msgs are read
	verifyMsgs(fmt.Sprintf("msg%d", targetModRev))
	for _, sm := range streamMsgs {
		log.SpanLog(ctx, log.DebugLevelApi, "debug stream", "msg", sm.Values)
	}
	// Cleanup stream
	keysRem, err := redisClient.Del(ctx, streamKey).Result()
	require.Nil(t, err, "delete stream")
	require.Equal(t, int64(1), keysRem, "stream deleted")
}
