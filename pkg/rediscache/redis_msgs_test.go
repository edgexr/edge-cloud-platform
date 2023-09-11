package rediscache

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/stretchr/testify/require"
)

type testMessage struct {
	Key  string
	Data string
}

func (s *testMessage) MessageKey() string {
	return "testMessage" + s.Key
}

func TestRedisMessages(t *testing.T) {
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

	// Subscribe to receive messages
	tm := testMessage{
		Key: "12345",
	}
	handler := Subscribe(ctx, client, &tm)
	require.NotNil(t, handler)

	numMsgs := 3
	dataStr := "someData"
	go func() {
		// send messages
		for ii := 0; ii < numMsgs; ii++ {
			sendMsg := testMessage{
				Key:  tm.Key,
				Data: dataStr,
			}
			SendMessage(ctx, client, &sendMsg)
		}
	}()

	count := 0
	waitCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	err = handler.WaitForMessage(waitCtx, func() (bool, error) {
		count++
		if count == numMsgs {
			return true, nil
		}
		if tm.Data != dataStr {
			return true, fmt.Errorf("mismatched data, expected %s but was %s", dataStr, tm.Data)
		}
		// continue waiting
		return false, nil
	})
	require.Nil(t, err)
}
