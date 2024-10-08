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

package tasks

import (
	"context"
	"sync"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
)

// KeyWorkers manages worker threads for keys. Each key gets its own thread,
// and subsequent calls to work on the same key will queue that work in the
// same thread, preventing parallel threads from working on the same key.
//
// This fits a common usage model where an object is updated via notify,
// and a worker thread is needed to respond to the change. The worker thread
// should pull the data from the caches based on the key. Subsequent changes
// via notify for the same key will be queued and compressed behind any
// running workfunc in the same thread, thereby avoiding unnecessary runs.

type WorkFunc func(ctx context.Context, key interface{})

type KeyWorkers struct {
	name        string
	workers     map[interface{}]*keyWorker
	workFunc    WorkFunc
	mux         sync.Mutex
	waitWorkers sync.WaitGroup
	pause       sync.WaitGroup
	paused      bool
	doneCb      func(key interface{})
}

func (s *KeyWorkers) Init(name string, workFunc WorkFunc) {
	s.name = name
	s.workers = make(map[interface{}]*keyWorker)
	s.workFunc = workFunc
}

type keyWorker struct {
	key       interface{}
	needsWork bool
	ctx       context.Context
	doneCb    chan (struct{})
}

func (s *KeyWorkers) NeedsWork(ctx context.Context, key interface{}) chan struct{} {
	s.mux.Lock()
	defer s.mux.Unlock()

	worker, found := s.workers[key]
	if !found {
		// start new go thread
		worker = &keyWorker{}
		worker.key = key
		worker.needsWork = true
		worker.ctx = ctx
		worker.doneCb = make(chan struct{})
		s.workers[key] = worker
		s.waitWorkers.Add(1)
		go s.runWorker(worker)
	} else {
		worker.needsWork = true
		worker.ctx = ctx
	}
	return worker.doneCb
}

func (s *KeyWorkers) runWorker(worker *keyWorker) {
	for {
		s.pause.Wait()
		s.mux.Lock()
		if !worker.needsWork {
			// we're done
			delete(s.workers, worker.key)
			s.mux.Unlock()
			close(worker.doneCb)
			break
		}
		span, ctx := log.ChildSpan(worker.ctx, log.DebugLevelApi, s.name+" KeyWorker")
		worker.needsWork = false
		s.mux.Unlock()

		s.workFunc(ctx, worker.key)
		span.Finish()
	}
	s.waitWorkers.Done()
}

func (s *KeyWorkers) WorkerCount() int {
	s.mux.Lock()
	defer s.mux.Unlock()
	return len(s.workers)
}

// WaitIdle waits until there are no workers. Mostly for unit testing.
func (s *KeyWorkers) WaitIdle() {
	s.waitWorkers.Wait()
}

func (s *KeyWorkers) Pause() {
	s.mux.Lock()
	defer s.mux.Unlock()

	if s.paused {
		return
	}
	s.pause.Add(1)
	s.paused = true
}

func (s *KeyWorkers) Resume() {
	s.mux.Lock()
	defer s.mux.Unlock()

	if !s.paused {
		return
	}
	s.pause.Done()
	s.paused = false
}
