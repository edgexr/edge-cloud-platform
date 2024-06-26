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

package rediscache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/go-redis/redis/v8"
	"github.com/google/uuid"
)

type APIMessageRequest struct {
	ID  string
	Msg interface{}
}

type APIMessageReply struct {
	Msg    interface{}
	Error  string
	Status ReplyStatus
}

type ReplyStatus int

const (
	ReplyStatusStreaming ReplyStatus = iota
	ReplyStatusSuccess
	ReplyStatusFailure
)

// UnaryAPI allows for request-reply over Redis.
type UnaryAPI struct {
	client *redis.Client
}

// NewUnaryAPI creates a new UnaryAPI for request-reply over Redis.
func NewUnaryAPI(client *redis.Client) *UnaryAPI {
	return &UnaryAPI{
		client: client,
	}
}

// DoRequest is a blocking call that sends the request and waits
// for the reply. The reply is written into replyBuf.
// The methodName identifies the API, it is analogous to the URL in
// an HTTP request or the method name in a GRPC service.
func (s *UnaryAPI) DoRequest(ctx context.Context, methodName string, request, replyBuf interface{}) error {
	return s.DoStreamRequest(ctx, methodName, request, replyBuf, nil)
}

// DoStreamRequest is a blocking call that sends the request and waits
// for multiple replies. Each reply is handled serially and written to
// the replyBuf parameter. The callback function is called and must
// return before it processes the next reply.
func (s *UnaryAPI) DoStreamRequest(ctx context.Context, methodName string, request, replyBuf interface{}, cb func() error) (reterr error) {
	// Set unique ID so we can only subscribe to responses from our request
	msgReq := APIMessageRequest{
		ID:  uuid.New().String(),
		Msg: request,
	}
	defer func() {
		if reterr != nil {
			reterr = fmt.Errorf("redis send request %s failed, %s", methodName, reterr)
			log.SpanLog(ctx, log.DebugLevelApi, "redis send request failed", "method", methodName, "err", reterr)
		}
	}()

	// subscribe to capture responses
	replyChannel := getReplyChannel(methodName, msgReq.ID)
	pubsub := s.client.Subscribe(ctx, replyChannel)
	defer pubsub.Close()
	// wait for confirmation that subscription is created
	_, err := pubsub.Receive(ctx)
	if err != nil {
		return fmt.Errorf("failed to subscribe to redis API reply channel %s, %s", replyChannel, err)
	}
	// note: channel is closed when pubsub is closed
	subCh := pubsub.Channel()

	// send request
	reqData, err := json.Marshal(msgReq)
	if err != nil {
		return err
	}
	requestChannel := getRequestChannel(methodName)
	log.SpanLog(ctx, log.DebugLevelApi, "redis send request", "method", methodName, "reqChan", requestChannel, "waitOnReplyChan", replyChannel, "reqData", string(reqData))

	err = s.client.RPush(ctx, requestChannel, string(reqData)).Err()
	if err != nil {
		return err
	}
	err = waitForMessage(ctx, subCh, func(payload string) (bool, error) {
		replyMsg := APIMessageReply{
			Msg: replyBuf,
		}
		err := json.Unmarshal([]byte(payload), &replyMsg)
		if err != nil {
			return false, err
		}
		if replyMsg.Status == ReplyStatusFailure {
			return false, errors.New(replyMsg.Error)
		}
		if cb == nil || replyMsg.Status == ReplyStatusSuccess {
			// we're done
			return true, nil
		}
		err = cb()
		if err != nil {
			return false, err
		}
		// continue to wait for more messages
		return false, nil
	})
	if err != nil {
		return err
	}
	return nil
}

func getRequestChannel(methodName string) string {
	return "msg/apitype/" + methodName
}

func getReplyChannel(id, methodName string) string {
	return getRequestChannel(methodName) + "/" + id
}

// GetRequestBuf should return an empty Message of the expected
// underlying type to unmarshal the message data into.
type GetRequestBuf func() interface{}

type StreamReplyCb func(reply interface{}) error

// RequestHandler shall handle the request and return the reply.
// It can return nil, nil to avoid sending a reply.
type RequestHandler func(ctx context.Context, req interface{}) (interface{}, error)

type StreamRequestHandler func(ctx context.Context, req interface{}, sendReply StreamReplyCb) error

// HandleRequests waits for requests, then calls the handler
// function to generate a reply. This is a blocking function,
// which spawns a go thread for each incoming request message.
func (s *UnaryAPI) HandleRequests(ctx context.Context, methodName string, getReqBuf GetRequestBuf, requestHandler RequestHandler) {
	s.handleRequestsInternal(ctx, methodName, getReqBuf, requestHandler, nil)
}

func (s *UnaryAPI) HandleStreamRequests(ctx context.Context, methodName string, getReqBuf GetRequestBuf, requestHandler StreamRequestHandler) {
	s.handleRequestsInternal(ctx, methodName, getReqBuf, nil, requestHandler)
}

func (s *UnaryAPI) handleRequestsInternal(ctx context.Context, methodName string, getReqBuf GetRequestBuf, handler RequestHandler, streamHandler StreamRequestHandler) {
	requestChan := getRequestChannel(methodName)
	log.SpanLog(ctx, log.DebugLevelApi, "redis handling api requests", "method", methodName, "reqChan", requestChan)
	for {
		vals, err := s.client.BLPop(ctx, 0, requestChan).Result()
		if ctx.Err() != nil {
			// context cancelled
			log.SpanLog(ctx, log.DebugLevelApi, "redis handle request cancelled", "method", methodName, "ctxErr", ctx.Err(), "err", err)
			return
		}
		// vals array has key name as [0] and value as [1]
		if err != nil || len(vals) != 2 {
			log.SpanLog(ctx, log.DebugLevelApi, "redis handle request blpop failed, will wait and try again", "method", methodName, "err", err, "vals", vals)
			// wait, try again
			time.Sleep(10 * time.Second)
			continue
		}
		// handle request
		go func(data string) {
			span := log.StartSpan(log.DebugLevelApi, "redis-handle-request")
			ctx := log.ContextWithSpan(context.Background(), span)
			defer span.Finish()
			log.SpanLog(ctx, log.DebugLevelApi, "redis handle request", "method", methodName, "data", data)

			reqMsg := APIMessageRequest{
				Msg: getReqBuf(),
			}
			err := json.Unmarshal([]byte(data), &reqMsg)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelApi, "redis handle request failed to unmarshal request", "method", methodName, "req", data, "err", err)
				return
			}

			sender := replySender{
				client:     s.client,
				ctx:        ctx,
				methodName: methodName,
				id:         reqMsg.ID,
				replyChan:  getReplyChannel(methodName, reqMsg.ID),
			}
			var handlerErr error
			var reply interface{}
			if handler != nil {
				// unary reply handler
				reply, handlerErr = handler(ctx, reqMsg.Msg)
			} else {
				// stream intermediate replies
				sendCb := func(reply interface{}) error {
					return sender.send(ctx, reply, "", ReplyStatusStreaming)
				}
				handlerErr = streamHandler(ctx, reqMsg.Msg, sendCb)
			}
			// Send handler result. For unary, this includes the reply
			// data. For streaming, this has no data, and just
			// terminates the stream.
			var status ReplyStatus
			var errMsg string
			if handlerErr == nil {
				status = ReplyStatusSuccess
			} else {
				status = ReplyStatusFailure
				reply = nil
				errMsg = handlerErr.Error()
			}
			sendErr := sender.send(ctx, reply, errMsg, status)
			// log
			log.SpanLog(ctx, log.DebugLevelApi, "redis handled request", "method", methodName, "reqID", reqMsg.ID, "handlerErr", handlerErr, "sendErr", sendErr)
		}(vals[1])
	}
}

type replySender struct {
	client     *redis.Client
	ctx        context.Context
	methodName string
	id         string
	sendFailed bool
	replyChan  string
}

func (s *replySender) send(ctx context.Context, reply interface{}, replyErr string, status ReplyStatus) error {
	replyMsg := APIMessageReply{
		Msg:    reply,
		Error:  replyErr,
		Status: status,
	}
	replyData, err := json.Marshal(replyMsg)
	if err != nil {
		return fmt.Errorf("Failed to marshal reply, %v", err)
	}
	err = s.client.Publish(s.ctx, s.replyChan, string(replyData)).Err()
	log.SpanLog(ctx, log.DebugLevelApi, "redis sent reply", "replyChan", s.replyChan, "err", err)
	if err != nil {
		s.sendFailed = true
		return fmt.Errorf("Failed to send reply, %v", err)
	}
	return nil
}
