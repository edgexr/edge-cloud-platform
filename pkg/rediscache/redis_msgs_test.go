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
	handler, err := Subscribe(ctx, client, &tm)
	require.Nil(t, err)
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
