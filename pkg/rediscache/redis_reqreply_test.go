package rediscache

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/stretchr/testify/require"
)

type testMessageRequest struct {
	RequestData string
}

type testMessageReply struct {
	ReplyData string
}

func TestRedisAPIMessages(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelInfo | log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	redisServer, err := NewMockRedisServer()
	require.Nil(t, err)
	defer redisServer.Close()

	client, err := NewClient(ctx, &RedisConfig{
		StandaloneAddr: redisServer.GetStandaloneAddr(),
	})
	require.Nil(t, err)

	unaryMethod := "doUnary"
	streamMethod := "doStream"
	streamReplyCount := 3
	var failHandlerErr error
	wg := sync.WaitGroup{}

	// set up unary echo server
	server := NewUnaryAPI(client)
	getReqBuf := func() interface{} {
		return &testMessageRequest{}
	}
	unaryTestHandler := func(ctx context.Context, req interface{}) (interface{}, error) {
		in, ok := req.(*testMessageRequest)
		if !ok {
			return nil, fmt.Errorf("not testMessageRequest Type")
		}
		if failHandlerErr != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "test unary return error", "err", failHandlerErr)
			return nil, failHandlerErr
		}
		reply := &testMessageReply{
			ReplyData: in.RequestData,
		}
		log.SpanLog(ctx, log.DebugLevelApi, "test unary send reply", "reply", reply)
		return reply, nil
	}
	unaryCtx, unaryCancel := context.WithTimeout(ctx, 2*time.Second)
	wg.Add(1)
	go func() {
		server.HandleRequests(unaryCtx, unaryMethod, getReqBuf, unaryTestHandler)
		wg.Done()
	}()

	// set up stream echo server
	streamTestHandler := func(ctx context.Context, req interface{}, sendReply StreamReplyCb) error {
		in, ok := req.(*testMessageRequest)
		if !ok {
			return fmt.Errorf("not testMessageRequest Type")
		}
		for ii := 0; ii < streamReplyCount; ii++ {
			reply := &testMessageReply{
				ReplyData: fmt.Sprintf("%s-%d", in.RequestData, ii),
			}
			log.SpanLog(ctx, log.DebugLevelApi, "test stream send reply", "reply", reply)
			err := sendReply(reply)
			if err != nil {
				return err
			}
		}
		if failHandlerErr != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "test stream send error", "err", failHandlerErr)
			return failHandlerErr
		}
		return nil
	}
	streamCtx, streamCancel := context.WithTimeout(ctx, 2*time.Second)
	wg.Add(1)
	go func() {
		server.HandleStreamRequests(streamCtx, streamMethod, getReqBuf, streamTestHandler)
		wg.Done()
	}()

	// client
	api := NewUnaryAPI(client)
	reqCtx, reqCancel := context.WithTimeout(ctx, 3*time.Second)
	defer reqCancel()

	// test unary - success
	unaryReq := testMessageRequest{
		RequestData: "unaryData",
	}
	replyBuf := testMessageReply{}
	err = api.DoRequest(reqCtx, unaryMethod, &unaryReq, &replyBuf)
	require.Nil(t, err)
	require.Equal(t, unaryReq.RequestData, replyBuf.ReplyData)

	// test streaming - success
	streamReq := testMessageRequest{
		RequestData: "streamData",
	}
	replyBuf = testMessageReply{}
	replyCount := 0
	streamCbFunc := func() error {
		replyCount++
		log.SpanLog(ctx, log.DebugLevelApi, "test got stream reply", "reply", replyBuf)
		if !strings.Contains(replyBuf.ReplyData, streamReq.RequestData) {
			return fmt.Errorf("unexpected reply data, expected contains %s but was %s", streamReq.RequestData, replyBuf.ReplyData)
		}
		return nil
	}
	err = api.DoStreamRequest(reqCtx, streamMethod, &streamReq, &replyBuf, streamCbFunc)
	require.Nil(t, err)
	require.Equal(t, streamReplyCount, replyCount)

	// force handler to fail
	failHandlerErr = fmt.Errorf("handler err")

	// test unary - failure
	replyBuf = testMessageReply{}
	err = api.DoRequest(reqCtx, unaryMethod, &unaryReq, &replyBuf)
	require.NotNil(t, err)
	require.Equal(t, failHandlerErr.Error(), err.Error())

	// test stream - failure
	replyCount = 0
	err = api.DoStreamRequest(reqCtx, streamMethod, &streamReq, &replyBuf, streamCbFunc)
	// still should have gotten intermediate replies
	require.Equal(t, streamReplyCount, replyCount)
	require.NotNil(t, err)
	require.Equal(t, failHandlerErr.Error(), err.Error())

	// --- cleanup ---

	// verify server handlers exit properly when cancelled
	waitCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitCh)
	}()
	unaryCancel()
	streamCancel()
	select {
	case <-time.After(time.Second):
		require.False(t, true, "Timed out waiting for handlers to exit")
	case <-waitCh:
	}
}
