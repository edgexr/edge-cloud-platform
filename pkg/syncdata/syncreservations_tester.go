package syncdata

import (
	"context"
	"fmt"
	"strconv"
	"sync"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/test-go/testify/require"
)

func SyncReservationsTest(ctx context.Context, factory SyncFactory) {
	// faking testing, to avoid including real testing lib
	// in real binaries (it adds testing command line args)
	t := &testingT{}

	// ==== basic tests
	sr := factory.NewSyncReservations("basic")
	// check no reservations to start
	reservations, err := sr.Get(ctx)
	require.Nil(t, err)
	require.Equal(t, 0, len(reservations))
	// make reservations
	keys := []string{"a", "b", "c"}
	for _, k := range keys {
		err := sr.ReserveValues(ctx, func(ctx context.Context, reservations Reservations) error {
			reservations.Add(k, k)
			return nil
		})
		require.Nil(t, err)
	}
	// check that keys were reserved
	reservations, err = sr.Get(ctx)
	require.Nil(t, err)
	require.Equal(t, len(keys), len(reservations))
	for _, k := range keys {
		_, ok := reservations[k]
		require.True(t, ok, k)
	}
	// release a reservation, ensure that it's no longer reserved
	delKey := keys[1]
	err = sr.Release(ctx, delKey)
	require.Nil(t, err)
	reservations, err = sr.Get(ctx)
	require.Nil(t, err)
	require.Equal(t, len(keys)-1, len(reservations))
	_, ok := reservations[delKey]
	require.False(t, ok, delKey)
	// release by owner, ensure key is no longer reserved
	delOwner := keys[2]
	err = sr.ReleaseForOwner(ctx, delOwner)
	require.Nil(t, err)
	reservations, err = sr.Get(ctx)
	require.Nil(t, err)
	require.Equal(t, len(keys)-2, len(reservations))
	_, ok = reservations[delOwner]
	require.False(t, ok, delOwner)

	// ==== infra data test
	numThreads := 50
	data := testData{
		data: map[string]struct{}{},
	}
	wg := sync.WaitGroup{}

	sr = factory.NewSyncReservations("infratest")
	for ii := 0; ii < numThreads; ii++ {
		wg.Add(1)
		go func(ii int) {
			defer wg.Done()
			//span := log.StartSpan(log.DebugLevelApi, "test", log.WithNoLogStartFinish{})
			span := log.StartSpan(log.DebugLevelApi, "test")
			ctx := log.ContextWithSpan(context.Background(), span)
			defer span.Finish()
			ownerID := strconv.Itoa(ii)

			// the reservation will protect write-after-read races when dealing
			// with infra data.
			key := ""
			err := sr.ReserveValues(ctx, func(ctx context.Context, reservations Reservations) error {
				key = ""
				// remove for owner clears stale data if there was a crash.
				// it's technically not needed here, but we include it to ensure
				// if it's used here (to clean up stale reservations for the owner)
				// that it doesn't interfere with anything else.
				reservations.RemoveForOwner(ownerID)
				dt := data.Read()
				// get a free value, that is not in infra data, and not reserved
				for k := 0; k < numThreads; k++ {
					kstr := strconv.Itoa(k)
					if _, found := reservations.Has(kstr); found {
						continue
					}
					if _, found := dt[kstr]; found {
						continue
					}
					key = kstr
					break
				}
				if key == "" {
					return fmt.Errorf("no reservations available")
				}
				// reserve key
				reservations.Add(key, ownerID)
				return nil
			})
			require.Nil(t, err, "reservation failed")
			log.SpanLog(ctx, log.DebugLevelApi, "thread reserved key", "thread", ii, "key", key, "owner", ownerID)
			// we have the reservation, so we can now commit to data
			data.Write(key)
			// reservation could be released now, or could be released
			// when owner object is deleted. If the reservation implementation preserves
			// data after a crash (i.e. uses persistent storage, not in-memory storage),
			// it is necessary to clean up when the object is deleted anyway, in
			// case a process dies after the reservation, but before it could be released.
			// We call it here to test it out
			err = sr.ReleaseForOwner(ctx, ownerID)
			require.Nil(t, err, "release for owner failed")
		}(ii)
	}
	wg.Wait()
	require.Equal(t, numThreads, len(data.data))
	sr = factory.NewSyncReservations("testdata")
	reservations, err = sr.Get(ctx)
	require.Nil(t, err)
	require.Equal(t, 0, len(reservations))
}

type testingT struct {
}

func (t *testingT) Errorf(format string, args ...interface{}) {
	fmt.Printf(format, args...)
}

func (t *testingT) FailNow() {
	panic("test failed")
}

type testData struct {
	data map[string]struct{}
	mux  sync.Mutex
}

func (s *testData) Read() map[string]struct{} {
	cp := map[string]struct{}{}
	s.mux.Lock()
	defer s.mux.Unlock()
	for k := range s.data {
		cp[k] = struct{}{}
	}
	return cp
}

func (s *testData) Write(k string) {
	s.mux.Lock()
	defer s.mux.Unlock()
	if _, found := s.data[k]; found {
		panic("data already present")
	}
	s.data[k] = struct{}{}
}
