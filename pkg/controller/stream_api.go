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

package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"time"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/rediscache"
	"github.com/edgexr/edge-cloud-platform/pkg/regiondata"
	"github.com/go-redis/redis/v8"
	grpc "google.golang.org/grpc"
)

// Streams are used by the UI to display the incremental steps
// of a long running process.
//
// Streams are only started after the etcd transaction for the
// action. We want to maintain the stream messages for only the
// most recent API action, which is defined by the etcd transation's
// modRev (modification revision).
//
// We do not want to have two transactional sources of truth,
// therefore we rely on etcd only as to whether an API action can
// proceed. Redis transactions do not gate progress, but are used
// to properly associate the redis stream with the latest etcd
// transaction.
//
// Each stream is associated with the etcd modRev of the transaction
// that gates the API action. Stream start always resets the stream
// unless it sees the stream has already been started with a higher
// modRev. This avoids race conditions between the etcd transaction
// and the stream start.
//
// Each stream is also associated with the trace ID of the context.
// This allows us to track messages to the stream that may come
// from different threads/processes, but are associated with the
// same initiating API action. The main example of this are
// info messages sent over notify from the CRM that may be
// handled by a complete different Controller instance.
//
// There is no guaranteed way to prevent messages from other
// traces from being written to the stream. There is an invalid
// marking that helps filter out messages, but that is purely
// an optimization. Instead, when reading messages from the stream,
// we use the trace ID on the SOM as the key during read, and ignore
// any messages from other IDs.

var (
	StreamMsgKeyID       = "id"
	StreamMsgKeyModRev   = "modRev"
	StreamMsgTypeMessage = "message"
	StreamMsgTypeError   = "error"
	StreamMsgTypeSOM     = "start-of-stream-message"
	StreamMsgTypeEOM     = "end-of-stream-message"
	StreamMsgTypeInfoEOM = "end-of-info-stream-message"

	StreamMsgReadTimeout     = 30 * time.Minute
	StreamMsgInfoReadTimeout = 3 * time.Second
)

type CleanupStreamAction bool

var (
	CleanupStream   CleanupStreamAction = true
	NoCleanupStream CleanupStreamAction = false
)

// For backwards compatibility, existing streams will have
// ID of "".
const streamNoID = "NO_ID"

type streamSend struct {
	cb        GenericCb
	mux       sync.Mutex
	crmPubSub *redis.PubSub
	crmMsgCh  <-chan *redis.Message
	invalid   bool
	id        string
	modRev    int64
}

type StreamObjApi struct {
	all *AllApis
}

type GenericCb interface {
	Send(*edgeproto.Result) error
	grpc.ServerStream
}

type CbWrapper struct {
	GenericCb
	ctx          context.Context
	streamKey    string
	started      bool
	invalid      bool
	streamBufMux sync.Mutex
	streamBuf    []edgeproto.Result
}

func NewStreamObjApi(sync *regiondata.Sync, all *AllApis) *StreamObjApi {
	streamObjApi := StreamObjApi{}
	streamObjApi.all = all
	return &streamObjApi
}

func addMsgToRedisStream(ctx context.Context, streamKey string, streamMsg map[string]interface{}) error {
	streamMsg[StreamMsgKeyID] = log.SpanTraceID(ctx)
	xaddArgs := redis.XAddArgs{
		Stream: streamKey,
		Values: streamMsg,
	}
	_, err := redisClient.XAdd(ctx, &xaddArgs).Result()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "Failed to add message to stream", "key", streamKey, "err", err)
		return err
	}
	return nil
}

func (s *CbWrapper) sendRedis(res *edgeproto.Result) error {
	if s.invalid {
		return nil
	}
	if res != nil {
		streamMsg := map[string]interface{}{
			StreamMsgTypeMessage: res.Message,
		}
		err := addMsgToRedisStream(s.ctx, s.streamKey, streamMsg)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *CbWrapper) Send(res *edgeproto.Result) error {
	if res == nil {
		return nil
	}
	if s.started {
		err := s.sendRedis(res)
		if err != nil {
			// failing to track stream messages should not fail
			// operations, as it's only used for UI status messages.
			log.SpanLog(s.ctx, log.DebugLevelApi, "failed to send redis stream", "key", s.streamKey, "res", *res, "err", err)
		}
	} else {
		// redis stream not started yet, buffer for now
		s.streamBufMux.Lock()
		s.streamBuf = append(s.streamBuf, *res)
		s.streamBufMux.Unlock()
	}
	return s.GenericCb.Send(res)
}

func (s *StreamObjApi) StreamMsgs(ctx context.Context, streamKey string, cb edgeproto.StreamObjApi_StreamAppInstServer) error {
	out, err := redisClient.Exists(ctx, streamKey).Result()
	if err != nil {
		return err
	}
	if out == 0 {
		// stream key does not exist
		return fmt.Errorf("Stream %s does not exist", streamKey)
	}

	streamMsgs, err := redisClient.XRange(ctx, streamKey, rediscache.RedisSmallestId, rediscache.RedisGreatestId).Result()
	if err != nil {
		return err
	}
	id := streamNoID

	decodeStreamMsg := func(sMsg map[string]interface{}) (bool, bool, error) {
		done := false
		infoDone := false
		msgID := getStreamID(sMsg)
		if id == streamNoID {
			if _, found := sMsg[StreamMsgTypeSOM]; found {
				id = msgID
			}
			// first message must be start of message
			// don't need to process SOM or invalid message.
			return false, false, nil
		}
		if id != streamNoID && msgID != id {
			// invalid id
			return false, false, nil
		}
		for k, v := range sMsg {
			switch k {
			case StreamMsgTypeMessage:
				val, ok := v.(string)
				if !ok {
					return done, infoDone, fmt.Errorf("Invalid stream message %v, must be of type string", v)
				}
				cb.Send(&edgeproto.Result{Message: val})
			case StreamMsgTypeError:
				val, ok := v.(string)
				if !ok {
					return done, infoDone, fmt.Errorf("Invalid stream error %v, must be of type string", v)
				}
				return done, infoDone, fmt.Errorf(val)
			case StreamMsgTypeEOM:
				done = true
			case StreamMsgTypeInfoEOM:
				infoDone = true
				// continue as there might be more messages after this
			case StreamMsgTypeSOM:
				// ignore
			case StreamMsgKeyID:
				// ignore
			case StreamMsgKeyModRev:
				// ignore
			default:
				return done, infoDone, fmt.Errorf("Unsupported message type received: %v", k)
			}
		}
		return done, infoDone, nil
	}

	lastStreamMsgId := ""
	done := false
	infoDone := false
	for _, sMsg := range streamMsgs {
		lastStreamMsgId = sMsg.ID
		done, infoDone, err = decodeStreamMsg(sMsg.Values)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
	// If infoDone is true, then exit as the CUD operation is done on the object.
	// If controller restarts during such operation, then EOM will not be set and
	// hence rely on InfoEOM to exit the stream
	if infoDone {
		return nil
	}
	if lastStreamMsgId == "" {
		lastStreamMsgId = rediscache.RedisSmallestId
	}

	readTimeout := StreamMsgReadTimeout
	for {
		// Blocking read for new stream messages until EOM is found
		xreadArgs := redis.XReadArgs{
			Streams: []string{streamKey, lastStreamMsgId},
			Count:   1,
			Block:   readTimeout,
		}
		sMsg, err := redisClient.XRead(ctx, &xreadArgs).Result()
		if err != nil {
			if err == redis.Nil {
				// timed out
				return nil
			}
			return fmt.Errorf("Error reading from stream %s, %v", streamKey, err)
		}
		if len(sMsg) != 1 {
			return fmt.Errorf("Output should only be for a single stream %s, but multiple found %v", streamKey, sMsg)
		}
		sMsgs := sMsg[0].Messages
		if len(sMsgs) != 1 {
			return fmt.Errorf("Output should only be for a single message, but multiple found %s, %v", streamKey, sMsgs)
		}
		lastStreamMsgId = sMsgs[0].ID
		done, infoDone, err := decodeStreamMsg(sMsgs[0].Values)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		if infoDone {
			// Since CUD operation on the object is done from CRM side,
			// reduce the timeout as it shouldn't take much time to end the operation
			readTimeout = StreamMsgInfoReadTimeout
		}
	}
}

type StreamOptions struct {
	NoResetStream bool
}

type StreamOp func(op *StreamOptions)

func WithNoResetStream() StreamOp {
	return func(op *StreamOptions) { op.NoResetStream = true }
}

// newStream buffers messages until the first Etcd transaction
// is done and we can actually start the stream.
func (s *StreamObjApi) newStream(ctx context.Context, cctx *CallContext, streamKey string, inCb GenericCb, opts ...StreamOp) (*CbWrapper, GenericCb) {
	log.SpanLog(ctx, log.DebugLevelApi, "new stream", "key", streamKey)

	outCb := &CbWrapper{
		GenericCb: inCb,
		ctx:       ctx,
		streamKey: streamKey,
	}
	if cctx.Undo {
		outCb.started = true
	}
	return outCb, outCb
}

// startStream is associated with the Etcd transaction's modRev,
// and initializes the Redis stream.
func (s *StreamObjApi) startStream(ctx context.Context, cctx *CallContext, streamCb *CbWrapper, modRev int64, opts ...StreamOp) (*streamSend, error) {
	id := log.SpanTraceID(ctx)
	streamKey := streamCb.streamKey

	log.SpanLog(ctx, log.DebugLevelApi, "start stream", "key", streamKey, "modRev", modRev, "id", id)

	streamOps := StreamOptions{}
	for _, fn := range opts {
		fn(&streamOps)
	}

	// If this is an undo, then caller has already performed
	// the same operation, so reuse the existing callback
	if cctx.Undo {
		streamSendObj := streamSend{cb: streamCb.GenericCb}
		return &streamSendObj, nil
	}

	streamInvalidErr := errors.New("stream invalid error")
	var streamModRev int64

	// Initialize the stream unless a stream for a later change
	// is present. Note that even if our modRev is not valid,
	// we do not fail the action - we simply avoid adding messages
	// if possible. We are not responsible for whether the action
	// should proceed or not, that is up to the Etcd transactions
	// in the caller.
	txf := func(tx *redis.Tx) error {
		initStream := true
		// check any modRev on the existing stream to
		// figure out if stream should be cleared or not
		streamMsgs, err := tx.XRangeN(ctx, streamKey,
			rediscache.RedisSmallestId, rediscache.RedisGreatestId, 1).Result()
		if err != nil {
			return err
		}
		streamModRev = 0
		if len(streamMsgs) > 0 {
			streamModRev = getStreamModRev(streamMsgs[0].Values)
		}
		if streamModRev > modRev {
			// do not write to the stream
			return streamInvalidErr
		}
		if streamOps.NoResetStream {
			// for unit-testing
			initStream = false
		}
		// Operation is commited only if the watched keys remain unchanged.
		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			if initStream {
				_, err := pipe.Del(ctx, streamKey).Result()
				if err != nil {
					return err
				}
			}
			xaddArgs := redis.XAddArgs{
				Stream: streamKey,
				Values: map[string]interface{}{
					StreamMsgTypeSOM:   "",
					StreamMsgKeyID:     id,
					StreamMsgKeyModRev: modRev,
				},
			}
			_, err := pipe.XAdd(ctx, &xaddArgs).Result()
			if err != nil {
				return err
			}
			return nil
		})
		return err
	}

	// Retry if the key has been changed.
	i := 0
	for i = 0; i < rediscache.RedisTxMaxRetries; i++ {
		err := redisClient.Watch(ctx, txf, streamKey)
		if err == nil {
			// Success.
			break
		}
		if err == streamInvalidErr {
			streamCb.invalid = true
			break
		}
		if err == redis.TxFailedErr {
			// Optimistic lock lost. Retry.
			time.Sleep(rediscache.GetRedisTxBackoff(i))
			continue
		}
		// Return any other error.
		return nil, err
	}

	// Note that invalid marking is just an optimization for later
	// messages, it does not prevent a streamObj started
	// earlier which was valid at the time from writing even
	// though it may not be invalid.
	if i == rediscache.RedisTxMaxRetries {
		log.SpanLog(ctx, log.DebugLevelApi, "start stream too many xact retries", "key", streamKey, "modRev", modRev)
		streamCb.invalid = true
	} else if streamCb.invalid {
		log.SpanLog(ctx, log.DebugLevelApi, "start stream modRev conflict", "key", streamKey, "modRev", modRev, "streamModRev", streamModRev)
	} else {
		log.SpanLog(ctx, log.DebugLevelApi, "start stream valid", "key", streamKey, "modRev", modRev, "streamModRev", streamModRev)
	}

	// Send any messages that have been buffered
	var bufferedCbs []edgeproto.Result
	streamCb.streamBufMux.Lock()
	bufferedCbs = streamCb.streamBuf
	streamCb.streamBuf = nil
	streamCb.streamBufMux.Unlock()
	for _, res := range bufferedCbs {
		streamCb.sendRedis(&res)
	}
	streamCb.started = true

	// Start subscription to redis channel identified by stream key.
	// Objects from CRM will be published to this channel and hence,
	// will be received by intended receiver
	// Note that this method does not wait on a response from redis, so the
	// subscription may not be active immediately. To force the connection to wait,
	// we call the Receive() method on the returned *PubSub
	pubsub := redisClient.Subscribe(ctx, streamKey)

	// Wait for confirmation that subscription is created before publishing anything.
	_, err := pubsub.Receive(ctx)
	if err != nil {
		pubsub.Close()
		return nil, fmt.Errorf("Failed to subscribe to stream %s, %v", streamKey, err)
	}

	// Go channel to receives messages.
	ch := pubsub.Channel()

	streamSendObj := streamSend{}
	streamSendObj.crmPubSub = pubsub
	streamSendObj.crmMsgCh = ch
	streamSendObj.cb = streamCb.GenericCb
	streamSendObj.invalid = streamCb.invalid
	streamSendObj.id = id
	streamSendObj.modRev = modRev

	return &streamSendObj, nil
}

func (s *StreamObjApi) stopStream(ctx context.Context, cctx *CallContext, streamKey string, streamSendObj *streamSend, objErr error, cleanupStream CleanupStreamAction) error {
	if streamSendObj == nil {
		log.SpanLog(ctx, log.DebugLevelApi, "stop stream no streamSendObj", "key", streamKey, "cctx", cctx, "err", objErr, "cleanup", cleanupStream)
		return nil
	}
	modRev := streamSendObj.modRev
	id := streamSendObj.id
	log.SpanLog(ctx, log.DebugLevelApi, "stop stream", "key", streamKey, "cctx", cctx, "modRev", modRev, "id", id, "err", objErr, "invalid", streamSendObj.invalid, "cleanup", cleanupStream)

	// If this is an undo, then caller has already performed the same operation,
	// so skip performing any cleanup
	if cctx.Undo {
		return nil
	}

	if streamSendObj.crmPubSub != nil {
		// Close() also closes channels
		streamSendObj.crmPubSub.Close()
	}

	if streamSendObj.invalid {
		return nil
	}

	streamSendObj.mux.Lock()
	defer streamSendObj.mux.Unlock()
	if objErr != nil {
		streamMsg := map[string]interface{}{
			StreamMsgTypeError: objErr.Error(),
		}
		err := addMsgToRedisStream(ctx, streamKey, streamMsg)
		if err != nil {
			return err
		}
	} else {
		streamMsg := map[string]interface{}{
			StreamMsgTypeEOM: "",
		}
		err := addMsgToRedisStream(ctx, streamKey, streamMsg)
		if err != nil {
			return err
		}
	}
	// Note that invalid marking is not a guarantee, so we still
	// need a transaction for cleanup check.
	if cleanupStream {
		// delete stream only if no other process has taken over the stream
		deleteOk := false
		streamID := ""
		streamModRev := int64(-1)
		txf := func(tx *redis.Tx) error {
			streamMsgs, err := tx.XRangeN(ctx, streamKey,
				rediscache.RedisSmallestId, rediscache.RedisGreatestId, 1).Result()
			if err != nil {
				return err
			}
			deleteOk = false
			if len(streamMsgs) > 0 {
				streamID = getStreamID(streamMsgs[0].Values)
				streamModRev = getStreamModRev(streamMsgs[0].Values)
				if id == streamID && modRev == streamModRev {
					deleteOk = true
				}
			}
			_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
				if deleteOk {
					_, err := pipe.Del(ctx, streamKey).Result()
					if err != nil {
						return err
					}
				}
				return nil
			})
			return err
		}
		var err error
		i := 0
		for i = 0; i < rediscache.RedisTxMaxRetries; i++ {
			err = redisClient.Watch(ctx, txf, streamKey)
			if err == redis.TxFailedErr {
				// retry
				time.Sleep(rediscache.GetRedisTxBackoff(i))
				continue
			}
			break
		}
		if i == rediscache.RedisTxMaxRetries {
			log.SpanLog(ctx, log.DebugLevelApi, "cleanup redis stream too many xact retries", "key", streamKey, "modRev", modRev, "err", err)
		} else if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "failed to cleanup redis stream", "key", streamKey, "modRev", modRev, "streamModRev", streamModRev, "id", id, "streamID", streamID, "err", err)
		} else if deleteOk {
			log.SpanLog(ctx, log.DebugLevelApi, "cleaned up redis stream", "key", streamKey, "modRev", modRev, "streamModRev", streamModRev, "id", id, "streamID", streamID)
		}
	}
	return nil
}

// Publish info object received from CRM to redis so that controller
// can act on status messages & info state accordingly
func (s *StreamObjApi) UpdateStatus(ctx context.Context, obj interface{}, state *edgeproto.TrackedState, cloudletState *dme.CloudletState, streamKey string) {
	inObj, err := json.Marshal(obj)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "Failed to marshal json object", "obj", obj, "err", err)
		return
	}
	_, err = redisClient.Publish(ctx, streamKey, string(inObj)).Result()
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "Failed to publish message on redis channel", "key", streamKey, "err", err)
	}
	infoDone := false
	if state != nil {
		if *state == edgeproto.TrackedState_READY ||
			*state == edgeproto.TrackedState_CREATE_ERROR ||
			*state == edgeproto.TrackedState_UPDATE_ERROR ||
			*state == edgeproto.TrackedState_DELETE_ERROR ||
			*state == edgeproto.TrackedState_NOT_PRESENT {
			infoDone = true
		}
	}
	if cloudletState != nil {
		if *cloudletState == dme.CloudletState_CLOUDLET_STATE_READY ||
			*cloudletState == dme.CloudletState_CLOUDLET_STATE_ERRORS {
			infoDone = true
		}
	}
	if infoDone {
		streamClosed := false
		streamMsgs, err := redisClient.XRange(ctx, streamKey, rediscache.RedisSmallestId, rediscache.RedisGreatestId).Result()
		if err == nil && len(streamMsgs) > 0 {
			for msgType, _ := range streamMsgs[len(streamMsgs)-1].Values {
				switch msgType {
				case StreamMsgTypeEOM:
					fallthrough
				case StreamMsgTypeError:
					streamClosed = true
				}
			}
		}
		if !streamClosed {
			streamMsg := map[string]interface{}{
				StreamMsgTypeInfoEOM: "",
			}
			err := addMsgToRedisStream(ctx, streamKey, streamMsg)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelApi, "Failed to add info EOM message to redis stream", "key", streamKey, "err", err)
			}
		}
	}
}

func getStreamModRev(values map[string]interface{}) int64 {
	val, ok := values[StreamMsgKeyModRev]
	if ok {
		mr, ok := val.(int64)
		if ok {
			return mr
		}
		// modRev is inserted as int64 but comes out as a string
		mrStr, ok := val.(string)
		if ok {
			mr, err := strconv.ParseInt(mrStr, 10, 64)
			if err == nil {
				return mr
			}
		}
	}
	return 0
}

func getStreamID(values map[string]interface{}) string {
	val, ok := values[StreamMsgKeyID]
	if ok {
		id, ok := val.(string)
		if ok {
			return id
		}
	}
	return ""
}
