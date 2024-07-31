package regiondata

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/edgexr/edge-cloud-platform/pkg/objstore"
	"github.com/edgexr/edge-cloud-platform/pkg/syncdata"
	"go.etcd.io/etcd/client/v3/concurrency"
)

type KVStoreSyncReservations struct {
	kvstore       objstore.KVStore
	name          string
	rootKeyPrefix string
}

func (s *KVStoreSyncReservations) getKey() string {
	return s.rootKeyPrefix + "/" + s.name
}

func (s *KVStoreSyncReservations) Get(ctx context.Context) (map[string]string, error) {
	key := s.getKey()
	valB, _, _, err := s.kvstore.Get(key)
	if err != nil && strings.Contains(err.Error(), objstore.NotFoundError(key).Error()) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	val := map[string]string{}
	err = json.Unmarshal(valB, &val)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal %s key data %s, %s", key, string(valB), err)
	}
	return val, nil
}

func (s *KVStoreSyncReservations) ReserveValues(ctx context.Context, updateFn func(ctx context.Context, reservations syncdata.Reservations) error) error {
	_, err := s.kvstore.ApplySTM(ctx, func(stm concurrency.STM) error {
		val, err := s.stmGet(stm)
		if err != nil {
			return err
		}
		err = updateFn(ctx, val)
		if err != nil {
			return err
		}
		return s.stmPut(stm, val)
	})
	return err
}

func (s *KVStoreSyncReservations) Release(ctx context.Context, keys ...string) error {
	_, err := s.kvstore.ApplySTM(ctx, func(stm concurrency.STM) error {
		val, err := s.stmGet(stm)
		if err != nil {
			return err
		}
		for _, k := range keys {
			delete(val, k)
		}
		return s.stmPut(stm, val)
	})
	return err
}

func (s *KVStoreSyncReservations) ReleaseForOwner(ctx context.Context, ownerID string) error {
	_, err := s.kvstore.ApplySTM(ctx, func(stm concurrency.STM) error {
		val, err := s.stmGet(stm)
		if err != nil {
			return err
		}
		for k, v := range val {
			if v == ownerID {
				delete(val, k)
			}
		}
		return s.stmPut(stm, val)
	})
	return err
}

func (s *KVStoreSyncReservations) stmGet(stm concurrency.STM) (map[string]string, error) {
	valS := stm.Get(s.getKey())
	if valS == "" {
		return map[string]string{}, nil
	}
	val := map[string]string{}
	err := json.Unmarshal([]byte(valS), &val)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal %s key data %s, %s", s.getKey(), valS, err)
	}
	return val, nil
}

func (s *KVStoreSyncReservations) stmPut(stm concurrency.STM, val map[string]string) error {
	newVal, err := json.Marshal(val)
	if err != nil {
		return fmt.Errorf("failed to marshal %s key data %v, %s", s.getKey(), val, err)
	}
	oldVal := stm.Get(s.getKey())
	if string(newVal) == oldVal {
		// no change
		return nil
	}
	stm.Put(s.getKey(), string(newVal))
	return nil
}
