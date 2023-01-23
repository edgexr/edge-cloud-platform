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

package edgeproto

import (
	"encoding/json"
	fmt "fmt"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/objstore"
	"go.etcd.io/etcd/client/v3/concurrency"
)

type AppInstIdStore struct{}

func AppInstIdDbKey(id string) string {
	return fmt.Sprintf("%s/%s", objstore.DbKeyPrefixString("AppInstId"), id)
}

func (s *AppInstIdStore) STMHas(stm concurrency.STM, id string) bool {
	keystr := AppInstIdDbKey(id)
	valstr := stm.Get(keystr)
	if valstr == "" {
		return false
	}
	return true
}

func (s *AppInstIdStore) STMPut(stm concurrency.STM, id string, obj *AppInstKey) {
	keystr := AppInstIdDbKey(id)
	val, err := json.Marshal(obj)
	if err != nil {
		log.InfoLog("AppInstId -> AppInstKey json marshal failed", "obj", obj, "err", err)
	}
	stm.Put(keystr, string(val))
}

func (s *AppInstIdStore) STMDel(stm concurrency.STM, id string) {
	keystr := AppInstIdDbKey(id)
	stm.Del(keystr)
}

func (s *AppInstIdStore) STMGet(stm concurrency.STM, id string, buf *AppInstKey) bool {
	keystr := AppInstIdDbKey(id)
	valstr := stm.Get(keystr)
	return s.parseGetData([]byte(valstr), buf)
}

func (s *AppInstIdStore) parseGetData(val []byte, buf *AppInstKey) bool {
	if len(val) == 0 {
		return false
	}
	if buf != nil {
		// clear buf, because empty values in val won't
		// overwrite non-empty values in buf.
		*buf = AppInstKey{}
		err := json.Unmarshal(val, buf)
		if err != nil {
			return false
		}
	}
	return true
}

type AppGlobalIdStore struct{}

func AppGlobalIdDbKey(id string) string {
	return fmt.Sprintf("%s/%s", objstore.DbKeyPrefixString("AppGlobalId"), id)
}

func (s *AppGlobalIdStore) STMHas(stm concurrency.STM, id string) bool {
	keystr := AppGlobalIdDbKey(id)
	valstr := stm.Get(keystr)
	if valstr == "" {
		return false
	}
	return true
}

func (s *AppGlobalIdStore) STMPut(stm concurrency.STM, id string) {
	keystr := AppGlobalIdDbKey(id)
	stm.Put(keystr, id)
}

func (s *AppGlobalIdStore) STMDel(stm concurrency.STM, id string) {
	keystr := AppGlobalIdDbKey(id)
	stm.Del(keystr)
}
