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

// Package syncdata provides for synchronizing data
package syncdata

import (
	"context"

	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
)

// SyncFactory allows for creating objects to synchronize data
// across multiple threads and processes.
type SyncFactory interface {
	NewSyncReservations(name string) SyncReservations
}

// SyncReservations allows for multiple threads/processes to coordinate
// reserving values, such as IPs or subnets.
// The intended use case is when needing to allocate a new subnet CIDR/IP
// that is not currently in use in the platform, and then commit that
// change to the platform, without allowing another thread/process
// running in parallel to choose the same value and cause a conflict.
// Keys for the reservations should be the values to reserve, the value
// associated with the key should be an ownerID. Associating an ownerID
// allows any stale reservations (cause by crashes) to be cleaned up
// later when the object is updated or deleted.
type SyncReservations interface {
	// Get the currently reserved values.
	// Get should not be used in the update function
	Get(ctx context.Context) (map[string]string, error)
	// ReserveValues allows for reserving new values. It is done as part of an update
	// function to synchronize write-after-read operations.
	// Changes to the reservations should be made to the values map.
	// The update function may be re-run if there is a conflict in updating
	// the reservations.
	ReserveValues(ctx context.Context, updateFn func(ctx context.Context, reservations Reservations) error) error
	// Release removes reserved values
	Release(ctx context.Context, keys ...string) error
	// ReleaseForOwner release all values for the given owner
	ReleaseForOwner(ctx context.Context, ownerID string) error
}

type Reservations map[string]string

// Add a value to the reservations with the given ownerID.
// The ownerID is used to clean up stale reservations.
func (s Reservations) Add(value, ownerID string) {
	s[value] = ownerID
}

// AddIfMissing adds a reservation that should already be present
// because it was found to be in use, typically by an external database or
// underlying infrastructure. In this case we don't know the ownerID,
// but we'll keep track of it so we can check all actively used values
// in once place.
func (s Reservations) AddIfMissing(value string) {
	if _, found := s[value]; !found {
		s[value] = cloudcommon.UnknownOwner
	}
}

func (s Reservations) Has(value string) (string, bool) {
	owner, found := s[value]
	return owner, found
}

func (s Reservations) RemoveForOwner(ownerID string) {
	for k, v := range s {
		if v == ownerID {
			delete(s, k)
		}
	}
}
