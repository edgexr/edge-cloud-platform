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

package regiondata

import (
	"context"
	"testing"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/syncdata"
)

func TestKVStoreSyncReservations(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelInfo | log.DebugLevelApi)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	store := InMemoryStore{}
	store.Start()
	defer store.Stop()

	factory := NewKVStoreSyncFactory(&store, "ccrm", "cloudlet1")
	syncdata.SyncReservationsTest(ctx, factory)
}
