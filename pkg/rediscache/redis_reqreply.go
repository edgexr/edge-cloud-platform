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
func (s *UnaryAPI) DoStreamRequest(ctx context.Context, methodName string, request, replyBuf interface{}, cb func() error) error {
	// Set unique ID so we can only subscribe to responses from our request
	msgReq := APIMessageRequest{
		ID:  uuid.New().String(),
		Msg: request,
	}

	// subscribe to capture responses
	pubsub := s.client.Subscribe(ctx, getReplyChannel(methodName, msgReq.ID))
	defer pubsub.Close()
	// note: channel is closed when pubsub is closed
	subCh := pubsub.Channel()

	// send request
	reqData, err := json.Marshal(msgReq)
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelApi, "redis send request", "method", methodName, "reqData", string(reqData))

	err = s.client.RPush(ctx, getRequestChannel(methodName), string(reqData)).Err()
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
	log.SpanLog(ctx, log.DebugLevelApi, "redis handling api requests", "method", methodName)
	for {
		vals, err := s.client.BLPop(ctx, 0, getRequestChannel(methodName)).Result()
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
			}
			var handlerErr error
			var reply interface{}
			if handler != nil {
				// unary reply handler
				reply, handlerErr = handler(ctx, reqMsg.Msg)
			} else {
				// stream intermediate replies
				sendCb := func(reply interface{}) error {
					return sender.send(reply, "", ReplyStatusStreaming)
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
			sendErr := sender.send(reply, errMsg, status)
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
}

func (s *replySender) send(reply interface{}, replyErr string, status ReplyStatus) error {
	replyMsg := APIMessageReply{
		Msg:    reply,
		Error:  replyErr,
		Status: status,
	}
	replyData, err := json.Marshal(replyMsg)
	if err != nil {
		return fmt.Errorf("Failed to marshal reply, %v", err)
	}
	err = s.client.Publish(s.ctx, getReplyChannel(s.methodName, s.id), string(replyData)).Err()
	if err != nil {
		s.sendFailed = true
		return fmt.Errorf("Failed to send reply, %v", err)
	}
	return nil
}
