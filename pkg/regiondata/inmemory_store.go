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

package regiondata

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/objstore"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
	v3 "go.etcd.io/etcd/client/v3"
	"go.etcd.io/etcd/client/v3/concurrency"
)

type watcher struct {
	cb     objstore.SyncCb
	cbData chan *objstore.SyncCbData
	name   string
}

type inMemData struct {
	val    string
	vers   int64
	modRev int64
}

type InMemoryStore struct {
	db       map[string]*inMemData
	watchers map[string][]*watcher
	rev      int64
	syncCb   objstore.SyncCb
	mux      util.Mutex
}

type CommitData struct {
	data []*objstore.SyncCbData
}

func (e *InMemoryStore) Start() error {
	e.db = make(map[string]*inMemData)
	e.watchers = make(map[string][]*watcher)
	e.rev = 1
	return nil
}

func (e *InMemoryStore) Stop() {
	e.mux.Lock()
	defer e.mux.Unlock()
	e.db = nil
}

func (e *InMemoryStore) Create(ctx context.Context, key, val string) (int64, error) {
	e.mux.Lock()
	defer e.mux.Unlock()
	if e.db == nil {
		return 0, objstore.ErrKVStoreNotInitialized
	}
	_, ok := e.db[key]
	if ok {
		return 0, objstore.ExistsError(key)
	}
	e.rev++
	e.db[key] = &inMemData{
		val:    val,
		vers:   1,
		modRev: e.rev,
	}
	log.DebugLog(log.DebugLevelEtcd, "Created", "key", key, "val", val, "rev", e.rev)
	e.triggerWatchers(objstore.SyncUpdate, key, val, e.rev, false)
	return e.rev, nil
}

func (e *InMemoryStore) Update(ctx context.Context, key, val string, version int64) (int64, error) {
	e.mux.Lock()
	defer e.mux.Unlock()
	if e.db == nil {
		return 0, objstore.ErrKVStoreNotInitialized
	}
	data, ok := e.db[key]
	if !ok {
		return 0, objstore.NotFoundError(key)
	}
	if version != objstore.ObjStoreUpdateVersionAny && data.vers != version {
		return 0, errors.New("Invalid version")
	}

	e.rev++
	data.val = val
	data.vers++
	data.modRev = e.rev
	log.DebugLog(log.DebugLevelEtcd, "Updated", "key", key, "val", val, "ver", data.vers, "rev", e.rev)
	e.triggerWatchers(objstore.SyncUpdate, key, val, e.rev, false)
	return e.rev, nil
}

func (e *InMemoryStore) Put(ctx context.Context, key, val string, ops ...objstore.KVOp) (int64, error) {
	e.mux.Lock()
	defer e.mux.Unlock()
	if e.db == nil {
		return 0, objstore.ErrKVStoreNotInitialized
	}
	data, ok := e.db[key]
	if !ok {
		data = &inMemData{}
		e.db[key] = data
	}
	e.rev++
	data.val = val
	data.vers++
	data.modRev = e.rev
	log.DebugLog(log.DebugLevelEtcd, "Put", "key", key, "val", val, "ver", data.vers, "rev", e.rev)
	e.triggerWatchers(objstore.SyncUpdate, key, val, e.rev, false)
	return e.rev, nil
}

func (e *InMemoryStore) Delete(ctx context.Context, key string) (int64, error) {
	e.mux.Lock()
	defer e.mux.Unlock()
	if e.db == nil {
		return 0, objstore.ErrKVStoreNotInitialized
	}
	delete(e.db, key)
	e.rev++
	log.DebugLog(log.DebugLevelEtcd, "Delete", "key", key, "rev", e.rev)
	e.triggerWatchers(objstore.SyncDelete, key, "", e.rev, false)
	return e.rev, nil
}

func (e *InMemoryStore) Get(key string, opts ...objstore.KVOp) ([]byte, int64, int64, error) {
	e.mux.Lock()
	defer e.mux.Unlock()
	if e.db == nil {
		return nil, 0, 0, objstore.ErrKVStoreNotInitialized
	}
	data, ok := e.db[key]
	if !ok {
		return nil, 0, 0, objstore.NotFoundError(key)
	}
	log.DebugLog(log.DebugLevelEtcd, "Got", "key", key, "val", data.val, "ver", data.vers, "rev", e.rev)
	return ([]byte)(data.val), data.vers, data.modRev, nil
}

func (e *InMemoryStore) List(key string, cb objstore.ListCb) error {
	kvs := make(map[string]*inMemData)
	e.mux.Lock()
	if e.db == nil {
		e.mux.Unlock()
		return objstore.ErrKVStoreNotInitialized
	}
	for k, v := range e.db {
		if !strings.HasPrefix(k, key) {
			continue
		}
		dd := *v
		kvs[k] = &dd
	}
	rev := e.rev
	e.mux.Unlock()

	for k, v := range kvs {
		log.DebugLog(log.DebugLevelEtcd, "List", "key", k, "val", v.val, "rev", rev, "modRev", v.modRev)
		err := cb([]byte(k), []byte(v.val), rev, v.modRev)
		if err != nil {
			break
		}
	}
	return nil
}

func (e *InMemoryStore) Rev(key string) int64 {
	e.mux.Lock()
	defer e.mux.Unlock()
	return e.db[key].modRev
}

func (e *InMemoryStore) Sync(ctx context.Context, name, prefix string, cb objstore.SyncCb) error {
	e.mux.Lock()
	watch := watcher{
		cb:     cb,
		cbData: make(chan *objstore.SyncCbData, 20),
		name:   name,
	}
	e.watchers[prefix] = append(e.watchers[prefix], &watch)

	// initial callback of data
	data := objstore.SyncCbData{}
	data.Action = objstore.SyncListStart
	data.Rev = 0
	data.ModRev = 0
	cb(ctx, &data)
	for key, dd := range e.db {
		if strings.HasPrefix(key, prefix) {
			log.DebugLog(log.DebugLevelEtcd, "sync list data", "key", key, "val", dd.val, "rev", e.rev)
			data.Action = objstore.SyncList
			data.Key = []byte(key)
			data.Value = []byte(dd.val)
			data.Rev = e.rev
			data.ModRev = dd.modRev
			cb(ctx, &data)
		}
	}
	data.Action = objstore.SyncListEnd
	data.Key = nil
	data.Value = nil
	cb(ctx, &data)

	e.mux.Unlock()

	done := false
	for !done {
		select {
		case <-ctx.Done():
			done = true
		case data := <-watch.cbData:
			log.DebugLog(log.DebugLevelEtcd, "watch data", "name", name, "key", string(data.Key), "val", string(data.Value), "rev", data.Rev, "moreEvents", data.MoreEvents, "remaining", len(watch.cbData))
			watch.cb(ctx, data)
		}
	}
	e.mux.Lock()

	prefixWatchers, ok := e.watchers[prefix]
	if ok {
		for ii, watcher := range prefixWatchers {
			if watcher == &watch {
				prefixWatchers = append(prefixWatchers[:ii], prefixWatchers[ii+1:]...)
				break
			}
		}
		if len(prefixWatchers) == 0 {
			delete(e.watchers, prefix)
		} else {
			e.watchers[prefix] = prefixWatchers
		}
	}
	e.mux.Unlock()
	return nil
}

/*
func (e *InMemoryStore) queueWatchers(action objstore.SyncCbAction, key, val string, rev int64) {
	for prefix, prefixWatchers := range e.watchers {
		if strings.HasPrefix(key, prefix) {
			for _, watch := range prefixWatchers {
				data := objstore.SyncCbData{
					Action: action,
					Key:    []byte(key),
					Value:  []byte(val),
					Rev:    rev,
					ModRev: rev,
				}
				watch.cbData = append(watch.cbData, &data)
			}
		}
	}
}

func (e *InMemoryStore) triggerWatchers() {
	for _, prefixWatchers := range e.watchers {
		for _, watch := range prefixWatchers {
			if len(watch.cbData) == 0 {
				continue
			}
			select {
			case watch.cbGo <- true:
			default:
			}
		}
	}
}*/

func (e *InMemoryStore) triggerWatchers(action objstore.SyncCbAction, key, val string, rev int64, moreEvents bool) {
	for prefix, prefixWatchers := range e.watchers {
		if strings.HasPrefix(key, prefix) {
			for _, watch := range prefixWatchers {
				data := objstore.SyncCbData{
					Action:     action,
					Key:        []byte(key),
					Value:      []byte(val),
					Rev:        rev,
					ModRev:     rev,
					MoreEvents: moreEvents,
				}
				log.DebugLog(log.DebugLevelApi, "trigger watchers", "name", watch.name, "remaining", len(watch.cbData))
				watch.cbData <- &data
			}
		}
	}
}

func (e *InMemoryStore) Grant(ctx context.Context, ttl int64) (int64, error) {
	return 0, errors.New("dummy etcd grant unsupported")
}

func (e *InMemoryStore) Revoke(ctx context.Context, lease int64) error {
	return errors.New("dummy etcd revoke unsupported")
}

func (e *InMemoryStore) KeepAlive(ctx context.Context, leaseID int64) error {
	return errors.New("dummy etcd keepalive unsupported")
}

// Based on clientv3/concurrency/stm.go
func (e *InMemoryStore) ApplySTM(ctx context.Context, apply func(concurrency.STM) error) (int64, error) {
	stm := inMemorySTM{client: e}
	var err error
	var rev int64 = 0
	ii := 0
	for {
		stm.reset()
		err = apply(&stm)
		if err != nil {
			break
		}
		rev, err = e.commit(ctx, &stm)
		if err == nil {
			break
		}
		ii++
		if ii > 12 {
			err = errors.New("too many iterations")
			break
		}
		backoff := time.Millisecond * time.Duration((ii+1)*rand.Intn(10))
		time.Sleep(backoff)
	}
	return rev, err
}

func (e *InMemoryStore) commit(ctx context.Context, stm *inMemorySTM) (int64, error) {
	// This implements etcd's SerializableSnapshot isolation model,
	// which checks for both read and write conflicts.
	e.mux.Lock()
	defer e.mux.Unlock()
	if len(stm.wset) == 0 {
		return e.rev, nil
	}

	rev := int64(math.MaxInt64 - 1)
	// check that gets have not changed
	for key, resp := range stm.rset {
		modRev := int64(0)
		if dd, ok := e.db[key]; ok {
			modRev = dd.modRev
		}
		if modRev != resp.modRev {
			fmt.Printf("rset modRev mismatch %s e.modRev %d resp.modRev %d\n",
				key, modRev, resp.modRev)
			return 0, errors.New("rset rev mismatch")
		}
		if resp.rev < rev {
			// find the lowest rev among the reads
			// all write keys need to be at this rev
			rev = resp.rev
		}
	}
	// check that no write keys are past the database revision
	// of the first get. If rset is empty, rev will be a huge
	// number so all these checks will pass.
	for key, _ := range stm.wset {
		wrev := int64(0)
		dd, ok := e.db[key]
		if ok {
			wrev = dd.modRev
		}
		if wrev > rev {
			fmt.Printf("wset rev mismatch %s rev %d wrev %d\n",
				key, rev, wrev)
			return 0, errors.New("wset rev mismatch")
		}
	}
	// commit all changes in one revision
	e.rev++
	numWrites := len(stm.wset)
	curWrite := 1
	for key, val := range stm.wset {
		moreEvents := curWrite < numWrites
		if val == "" {
			// delete
			delete(e.db, key)
			log.DebugLog(log.DebugLevelEtcd, "Delete",
				"key", key, "rev", e.rev)
			e.triggerWatchers(objstore.SyncDelete, key, "", e.rev, moreEvents)
		} else {
			dd, ok := e.db[key]
			if !ok {
				dd = &inMemData{}
				e.db[key] = dd
			}
			dd.val = val
			dd.vers++
			dd.modRev = e.rev
			log.DebugLog(log.DebugLevelEtcd, "Commit", "key", key,
				"val", val, "ver", dd.vers, "rev", e.rev)
			e.triggerWatchers(objstore.SyncUpdate, key, val, e.rev, moreEvents)
		}
		curWrite++
	}
	return e.rev, nil
}

type inMemoryReadResp struct {
	val    string
	modRev int64
	rev    int64
}

type inMemorySTM struct {
	concurrency.STM
	client *InMemoryStore
	rset   map[string]*inMemoryReadResp
	wset   map[string]string
}

func (d *inMemorySTM) reset() {
	d.rset = make(map[string]*inMemoryReadResp)
	d.wset = make(map[string]string)
}

func (d *inMemorySTM) Get(keys ...string) string {
	key := keys[0]
	if wv, ok := d.wset[key]; ok {
		return wv
	}
	if rr, ok := d.rset[key]; ok {
		return rr.val
	}
	byt, _, modRev, err := d.client.Get(key)
	rev := d.client.rev
	if err != nil {
		byt = make([]byte, 0)
		modRev = 0
	}
	resp := inMemoryReadResp{
		val:    string(byt),
		rev:    rev,
		modRev: modRev,
	}
	d.rset[key] = &resp
	return string(byt)
}

func (d *inMemorySTM) Put(key, val string, opts ...v3.OpOption) {
	d.wset[key] = val
}

func (d *inMemorySTM) Rev(key string) int64 {
	return d.client.Rev(key)
}

func (d *inMemorySTM) Del(key string) {
	d.wset[key] = ""
}
