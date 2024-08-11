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

package syncdata

import (
	"context"
	"sync"
)

type MutexSyncReservations struct {
	name     string
	reserved map[string]string
	mux      sync.Mutex
}

func NewMutexSyncReservations(name string) *MutexSyncReservations {
	return &MutexSyncReservations{
		name: name,
	}
}

func (s *MutexSyncReservations) Get(ctx context.Context) (map[string]string, error) {
	s.mux.Lock()
	defer s.mux.Unlock()
	vals := make(map[string]string)
	for k, v := range s.reserved {
		vals[k] = v
	}
	return vals, nil
}

func (s *MutexSyncReservations) ReserveValues(ctx context.Context, updateFn func(ctx context.Context, reservations Reservations) error) error {
	s.mux.Lock()
	defer s.mux.Unlock()
	reservations := Reservations{}
	for k, v := range s.reserved {
		reservations[k] = v
	}
	err := updateFn(ctx, reservations)
	if err != nil {
		return err
	}
	s.reserved = reservations
	return nil
}

func (s *MutexSyncReservations) Release(ctx context.Context, keys ...string) error {
	s.mux.Lock()
	defer s.mux.Unlock()
	for _, k := range keys {
		delete(s.reserved, k)
	}
	return nil
}

func (s *MutexSyncReservations) ReleaseForOwner(ctx context.Context, ownerID string) error {
	s.mux.Lock()
	defer s.mux.Unlock()
	for k, v := range s.reserved {
		if v == ownerID {
			delete(s.reserved, k)
		}
	}
	return nil
}
