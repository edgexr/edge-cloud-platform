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
	fmt "fmt"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/go-redis/redis/v8"
)

type Message interface {
	MessageKey() string
}

// MessageHandler is used to wait for a specific message.
type MessageHandler struct {
	pubsub  *redis.PubSub
	desired Message
	ch      <-chan *redis.Message
}

// Subscribe shall be done before the code that will trigger the
// message being sent. After that code, call WaitForMessage().
// The desired Message parameter must have its key value set.
// An example of this would be:
//
//	desired := &edgeproto.Info{
//	  Key: someKey,
//	}
//
// h := Subscribe(ctx, client, desired)
// defer h.Close()
// <code to trigger message send>
//
//	err := h.WaitForMessage(10*time.Second, func() bool {
//	  if desired.State == TARGET_STATE {
//	    return true
//	  }
//	  return false
//	})
func Subscribe(ctx context.Context, client *redis.Client, desired Message) (*MessageHandler, error) {
	h := MessageHandler{}
	h.desired = desired
	h.pubsub = client.Subscribe(ctx, desired.MessageKey())
	// wait for confirmation that subscription is created.
	// this avoids missing messages that are sent immediately after this call.
	if _, err := h.pubsub.Receive(ctx); err != nil {
		h.pubsub.Close()
		return nil, fmt.Errorf("failed to subscribe to redis channel %s, %s", desired.MessageKey(), err)
	}
	h.ch = h.pubsub.Channel()
	return &h, nil
}

// Close cleans up the MessageHandler.
func (s *MessageHandler) Close() {
	s.pubsub.Close()
}

// WaitForMessage waits for the desired message to be received.
// The message when received is copied into the desired Message parameter
// passed to Subscribe. The isDone callback should check the state of
// desired and return true if we're done.
// Context may have timeout set.
func (s *MessageHandler) WaitForMessage(ctx context.Context, isDone func() (bool, error)) error {
	return waitForMessage(ctx, s.ch, func(msgData string) (bool, error) {
		err := json.Unmarshal([]byte(msgData), s.desired)
		if err != nil {
			return true, err
		}
		return isDone()
	})
}

// SendMessage sends the message over Redis. It can be received by
// WaitForMessage().
func SendMessage(ctx context.Context, client *redis.Client, msg Message) error {
	msgData, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	return client.Publish(ctx, msg.MessageKey(), string(msgData)).Err()
}

type waitForHandler func(msgData string) (done bool, err error)

func waitForMessage(ctx context.Context, ch <-chan *redis.Message, cb waitForHandler) error {
	// wait for reply
	for {
		select {
		case <-ctx.Done():
			return errors.New("timed out waiting for reply")
		case msg, ok := <-ch:
			if !ok {
				return errors.New("unexpected channel close while waiting for reply")
			}
			log.SpanLog(ctx, log.DebugLevelApi, "redis got reply", "message", msg)
			done, err := cb(msg.Payload)
			if err != nil {
				return err
			}
			if done {
				return nil
			}
			// not done, continue to process messages
		}
	}
}
