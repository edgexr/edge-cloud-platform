package rediscache

import (
	"context"
	"encoding/json"
	"errors"

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
// desired := &edgeproto.Info{
//   Key: someKey,
// }
// h := Subscribe(ctx, client, desired)
// defer h.Close()
// <code to trigger message send>
// err := h.WaitForMessage(10*time.Second, func() bool {
//   if desired.State == TARGET_STATE {
//     return true
//   }
//   return false
// })
func Subscribe(ctx context.Context, client *redis.Client, desired Message) *MessageHandler {
	h := MessageHandler{}
	h.desired = desired
	h.pubsub = client.Subscribe(ctx, desired.MessageKey())
	h.ch = h.pubsub.Channel()
	return &h
}

// Close cleans up the MessageHandler.
func (s *MessageHandler) Close() {
	s.pubsub.Close()
}

// WaitForMessage waits for the desired message to be send.
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
