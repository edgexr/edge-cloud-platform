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

package dmecommon

import (
	"context"
	"fmt"
	"math/rand"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/stretchr/testify/assert"
)

type testdb struct {
	stats map[StatKey]*ApiStat
	mux   sync.Mutex
}

func (n *testdb) Init() {
	n.stats = make(map[StatKey]*ApiStat)
}

func (n *testdb) send(ctx context.Context, metric *edgeproto.Metric) bool {
	key, stat := MetricToStat(metric)
	n.mux.Lock()
	n.stats[*key] = stat
	n.mux.Unlock()
	return true
}

func TestStatDrops(t *testing.T) {
	db := testdb{}
	db.Init()
	notifyInterval := 20 * time.Millisecond
	numThreads := 100
	stats := NewDmeStats(notifyInterval, 10, db.send)

	stats.Start()
	defer stats.Stop()
	count := uint64(0)
	wg := sync.WaitGroup{}

	for ii := 0; ii < numThreads; ii++ {
		wg.Add(1)
		go func(id int) {
			key := StatKey{}
			key.AppKey.Organization = "dev" + strconv.Itoa(id)
			key.AppKey.Name = "app"
			key.AppKey.Version = "1.0.0"
			key.Method = "findCloudlet"
			key.AppInstFound.Name = "appInstName"
			key.AppInstFound.Organization = "appInstOrg"
			key.Carrier = "unittest"

			ch := time.After(10 * notifyInterval)
			done := false
			for !done {
				select {
				case <-ch:
					done = true
				default:
					stats.RecordApiStatCall(&ApiStatCall{
						Key:     key,
						Fail:    rand.Intn(2) == 1,
						Latency: time.Duration(rand.Intn(200)) * time.Millisecond,
					})
					atomic.AddUint64(&count, 1)
					time.Sleep(100 * time.Microsecond)
				}
			}
			wg.Done()
		}(ii)
	}
	wg.Wait()

	var dbCount uint64
	numStats := 0
	for ii := 0; ii < 5; ii++ {
		dbCount = uint64(0)
		db.mux.Lock()
		for _, stat := range db.stats {
			dbCount += stat.reqs
		}
		numStats = len(db.stats)
		db.mux.Unlock()
		if numThreads == numStats && count == dbCount {
			break
		}
		time.Sleep(notifyInterval / 2)
	}
	assert.Equal(t, numThreads, len(db.stats), "stat count")
	assert.Equal(t, count, dbCount, "api requests expected %d but was %d", count, dbCount)
	fmt.Printf("served %d requests\n", count)
}

func TestStatChanged(t *testing.T) {
	db := testdb{}
	db.Init()
	notifyInterval := 20 * time.Millisecond
	stats := NewDmeStats(notifyInterval, 1, db.send)
	stats.Start()
	defer stats.Stop()
	var mux = &sync.Mutex{}

	key := StatKey{}
	key.AppKey.Organization = "dev"
	key.AppKey.Name = "app"
	key.AppKey.Version = "1.0.0"
	key.Method = "findCloudlet"
	key.AppInstFound.Name = "appInstName"
	key.AppInstFound.Organization = "appInstOrg"
	key.Carrier = "unittest"

	mux.Lock()
	stats.RecordApiStatCall(&ApiStatCall{
		Key:     key,
		Fail:    false,
		Latency: 50 * time.Millisecond,
	})
	time.Sleep(100 * time.Microsecond)
	assert.True(t, stats.shards[0].apiStatMap[key].changed)
	mux.Unlock()

	// sleep two intervals to make sure that stats are uploaded to the controller
	time.Sleep(2 * notifyInterval)
	assert.False(t, stats.shards[0].apiStatMap[key].changed)
}
