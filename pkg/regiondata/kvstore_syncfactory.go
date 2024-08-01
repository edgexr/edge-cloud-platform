package regiondata

import (
	"github.com/edgexr/edge-cloud-platform/pkg/objstore"
	"github.com/edgexr/edge-cloud-platform/pkg/syncdata"
)

const SyncFactoryRootPrefix = "syncfactory"

type KVStoreSyncFactory struct {
	kvstore   objstore.KVStore
	nodeType  string
	keyPrefix string
}

func NewKVStoreSyncFactory(kvstore objstore.KVStore, nodeType string, keyPrefix string) *KVStoreSyncFactory {
	return &KVStoreSyncFactory{
		kvstore:   kvstore,
		nodeType:  nodeType,
		keyPrefix: keyPrefix,
	}
}

func (s *KVStoreSyncFactory) NewSyncReservations(name string) syncdata.SyncReservations {
	return &KVStoreSyncReservations{
		name:          name,
		kvstore:       s.kvstore,
		rootKeyPrefix: SyncFactoryRootPrefix + "/" + s.nodeType + "/" + s.keyPrefix,
	}
}
