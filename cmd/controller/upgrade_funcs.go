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

package main

import (
	"encoding/json"
	fmt "fmt"
	"reflect"
	"strconv"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/objstore"
	"go.etcd.io/etcd/client/v3/concurrency"
	context "golang.org/x/net/context"
)

func getDbObjectKeys(objStore objstore.KVStore, dbPrefix string) (map[string]struct{}, error) {
	keys := make(map[string]struct{})
	keystr := fmt.Sprintf("%s/", objstore.DbKeyPrefixString(dbPrefix))
	err := objStore.List(keystr, func(key, val []byte, rev, modRev int64) error {
		keys[string(key)] = struct{}{}
		return nil
	})
	return keys, err
}

func unmarshalUpgradeObj(ctx context.Context, str string, obj interface{}) error {
	err2 := json.Unmarshal([]byte(str), obj)
	if err2 != nil {
		log.SpanLog(ctx, log.DebugLevelUpgrade, "Upgrade unmarshal object failed", "objType", reflect.TypeOf(obj).String(), "val", str, "err", err2)
		return err2
	}
	return nil
}

// New ClusterInstRefKey is just the ClusterKey
type ClusterInstRefKeyV1 struct {
	ClusterKey   edgeproto.ClusterKeyV1 `json:"cluster_key"`
	Organization string                 `json:"organization,omitempty"`
}

// New AppInstRefKey is the AppInst Name and Org
type AppInstRefKeyV1 struct {
	AppKey         edgeproto.AppKey    `json:"app_key"`
	ClusterInstKey ClusterInstRefKeyV1 `json:"cluster_inst_key"`
}

type CloudletRefsV1 struct {
	ClusterInsts []ClusterInstRefKeyV1 `json:"cluster_insts"`
	VmAppInsts   []AppInstRefKeyV1     `json:"vm_app_insts"`
	K8SAppInsts  []AppInstRefKeyV1     `json:"k8s_app_insts"`
}

type ClusterRefsV1 struct {
	Apps []AppInstRefKeyV1 `json:"apps"`
}

func AppInstKeyName(ctx context.Context, objStore objstore.KVStore, allApis *AllApis) error {
	log.SpanLog(ctx, log.DebugLevelUpgrade, "AppInstKeyName")

	// Track key refs so we can upgrade references
	clusterInstKeyRefs := make(map[ClusterInstRefKeyV1]edgeproto.ClusterKey)
	type ClusterInstV1 struct {
		Key edgeproto.ClusterInstKeyV1 `json:"key"`
	}
	// Upgrade ClusterInst keys
	clusterInstKeys, err := getDbObjectKeys(objStore, "ClusterInst")
	if err != nil {
		return err
	}
	for key, _ := range clusterInstKeys {
		_, err = objStore.ApplySTM(ctx, func(stm concurrency.STM) error {
			clusterInstStr := stm.Get(key)
			if clusterInstStr == "" {
				return nil // was deleted
			}
			clusterInst := edgeproto.ClusterInst{}
			if err2 := unmarshalUpgradeObj(ctx, clusterInstStr, &clusterInst); err2 != nil {
				return err2
			}
			if clusterInst.Key.ClusterKey.Organization == "" {
				// upgrade to new key. first load old version.
				v1 := ClusterInstV1{}
				if err2 := unmarshalUpgradeObj(ctx, clusterInstStr, &v1); err2 != nil {
					return err2
				}
				clusterInst.Key.ClusterKey.Name = v1.Key.ClusterKey.Name
				clusterInst.Key.ClusterKey.Organization = v1.Key.Organization
				clusterInst.Key.CloudletKey = v1.Key.CloudletKey
				stm.Del(key)
				allApis.clusterInstApi.store.STMPut(stm, &clusterInst)
			}
			oldRef := ClusterInstRefKeyV1{}
			oldRef.ClusterKey.Name = clusterInst.Key.ClusterKey.Name
			oldRef.Organization = clusterInst.Key.ClusterKey.Organization
			clusterInstKeyRefs[oldRef] = clusterInst.Key.ClusterKey
			return nil
		})
	}

	// Track key refs so we can upgrade references
	appInstKeyRefs := make(map[AppInstRefKeyV1]edgeproto.AppInstRefKey)
	appInstKeyJsonRefs := make(map[string]string)
	type AppInstV1 struct {
		Key             edgeproto.AppInstKeyV1 `json:"key"`
		RealClusterName string                 `json:"real_cluster_name"`
	}
	// Upgrade AppInst keys
	appInstKeys, err := getDbObjectKeys(objStore, "AppInst")
	if err != nil {
		return err
	}
	for appInstKey, _ := range appInstKeys {
		_, err := objStore.ApplySTM(ctx, func(stm concurrency.STM) error {
			appInstStr := stm.Get(appInstKey)
			if appInstStr == "" {
				// deleted in the meantime
				return nil
			}
			var appInst edgeproto.AppInst
			if err2 := unmarshalUpgradeObj(ctx, appInstStr, &appInst); err2 != nil {
				return err2
			}
			if appInst.Key.Name == "" {
				// upgrade to new key. first load old version.
				v1 := AppInstV1{}
				if err2 := unmarshalUpgradeObj(ctx, appInstStr, &v1); err2 != nil {
					return err2
				}
				appInst.Key.Organization = v1.Key.AppKey.Organization
				appInst.Key.CloudletKey = v1.Key.ClusterInstKey.CloudletKey
				appInst.AppKey = v1.Key.AppKey
				appInst.ClusterKey.Organization = v1.Key.ClusterInstKey.Organization
				// The "real" cluster name becomes the cluster.
				// The "virtual" cluster name is no longer
				// needed because uniqueness is provided by the
				// AppInst Name. We need to keep it for
				// backwards compatibility, however.
				if v1.RealClusterName != "" {
					appInst.ClusterKey.Name = v1.RealClusterName
					appInst.VirtualClusterKey.Name = v1.Key.ClusterInstKey.ClusterKey.Name
					appInst.VirtualClusterKey.Organization = v1.Key.ClusterInstKey.Organization
				} else {
					appInst.ClusterKey.Name = v1.Key.ClusterInstKey.ClusterKey.Name
				}
				// generate a new name for the AppInst
				// number of iterations must be low to avoid
				// STM limits.
				baseName := appInst.Key.Name
				for ii := 0; ii < 10; ii++ {
					appInst.Key.Name = baseName
					if ii > 0 {
						appInst.Key.Name += strconv.Itoa(ii)
					}
					if allApis.appInstApi.store.STMHas(stm, &appInst.Key) {
						// conflict, can't use
						appInst.Key.Name = ""
						continue
					}
					break
				}
				if appInst.Key.Name == "" {
					return fmt.Errorf("Failed to compute new AppInst Name for %s", v1.Key.GetKeyString())
				}
				allApis.appInstApi.store.STMPut(stm, &appInst)
				stm.Del(appInstKey)
			}
			// mapping to fix AppInstRefs
			v1Key := edgeproto.AppInstKeyV1{}
			v1Key.AppKey = appInst.AppKey
			v1Key.ClusterInstKey.CloudletKey = appInst.Key.CloudletKey
			v1Key.ClusterInstKey.ClusterKey.Name = appInst.ClusterKey.Name
			v1Key.ClusterInstKey.Organization = appInst.ClusterKey.Organization
			v1KeyJson, err := json.Marshal(v1Key)
			if err != nil {
				return err
			}
			keyJson, err := json.Marshal(appInst.Key)
			if err != nil {
				return err
			}
			appInstKeyJsonRefs[string(v1KeyJson)] = string(keyJson)
			// mapping to fix other refs
			oldRef := AppInstRefKeyV1{}
			oldRef.AppKey = appInst.AppKey
			oldRef.ClusterInstKey.ClusterKey.Name = appInst.ClusterKey.Name
			oldRef.ClusterInstKey.Organization = appInst.ClusterKey.Organization
			newRef := edgeproto.AppInstRefKey{}
			newRef.Name = appInst.Key.Name
			newRef.Organization = appInst.Key.Organization
			appInstKeyRefs[oldRef] = newRef
			return nil
		})
		if err != nil {
			return err
		}
	}

	// Fix cloudlet refs
	cloudletRefsKeys, err := getDbObjectKeys(objStore, "CloudletRefs")
	if err != nil {
		return err
	}
	for refsKey, _ := range cloudletRefsKeys {
		_, err := objStore.ApplySTM(ctx, func(stm concurrency.STM) error {
			refsStr := stm.Get(refsKey)
			var refs edgeproto.CloudletRefs
			if err2 := unmarshalUpgradeObj(ctx, refsStr, &refs); err2 != nil {
				return err2
			}
			var refsV1 CloudletRefsV1
			if err2 := unmarshalUpgradeObj(ctx, refsStr, &refsV1); err2 != nil {
				return err2
			}
			updated := false
			if len(refs.ClusterInsts) == len(refsV1.ClusterInsts) {
				for ii := 0; ii < len(refs.ClusterInsts); ii++ {
					oldRef := refsV1.ClusterInsts[ii]
					newRef, found := clusterInstKeyRefs[oldRef]
					if found {
						refs.ClusterInsts[ii] = newRef
						updated = true
					}
				}
			}
			if len(refs.VmAppInsts) == len(refsV1.VmAppInsts) {
				for ii := 0; ii < len(refs.VmAppInsts); ii++ {
					oldRef := refsV1.VmAppInsts[ii]
					newRef, found := appInstKeyRefs[oldRef]
					if found {
						refs.VmAppInsts[ii] = newRef
						updated = true
					}
				}
			}
			if len(refs.K8SAppInsts) == len(refsV1.K8SAppInsts) {
				for ii := 0; ii < len(refs.K8SAppInsts); ii++ {
					oldRef := refsV1.K8SAppInsts[ii]
					newRef, found := appInstKeyRefs[oldRef]
					if found {
						refs.K8SAppInsts[ii] = newRef
						updated = true
					}
				}
			}
			if updated {
				allApis.cloudletRefsApi.store.STMPut(stm, &refs)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	// Fix cluster refs
	clusterRefsKeys, err := getDbObjectKeys(objStore, "ClusterRefs")
	if err != nil {
		return err
	}
	for refsKey, _ := range clusterRefsKeys {
		_, err := objStore.ApplySTM(ctx, func(stm concurrency.STM) error {
			refsStr := stm.Get(refsKey)
			var refs edgeproto.ClusterRefs
			if err2 := unmarshalUpgradeObj(ctx, refsStr, &refs); err2 != nil {
				return err2
			}
			var refsV1 ClusterRefsV1
			if err2 := unmarshalUpgradeObj(ctx, refsStr, &refsV1); err2 != nil {
				return err2
			}
			updated := false
			if len(refs.Apps) == len(refsV1.Apps) {
				for ii := 0; ii < len(refs.Apps); ii++ {
					oldRef := refsV1.Apps[ii]
					newRef, found := appInstKeyRefs[oldRef]
					if found {
						refs.Apps[ii] = newRef
						updated = true
					}
				}
			}
			if updated {
				allApis.clusterRefsApi.store.STMPut(stm, &refs)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	// Fix AppInst refs
	appInstRefsKeys, err := getDbObjectKeys(objStore, "AppInstRefs")
	if err != nil {
		return err
	}
	for refsKey, _ := range appInstRefsKeys {
		_, err := objStore.ApplySTM(ctx, func(stm concurrency.STM) error {
			refsStr := stm.Get(refsKey)
			var refs edgeproto.AppInstRefs
			if err2 := unmarshalUpgradeObj(ctx, refsStr, &refs); err2 != nil {
				return err2
			}
			updated := false
			for k, v := range refs.Insts {
				newKey, found := appInstKeyJsonRefs[k]
				if found {
					delete(refs.Insts, k)
					refs.Insts[newKey] = v
					updated = true
				}
			}
			for k, v := range refs.DeleteRequestedInsts {
				newKey, found := appInstKeyJsonRefs[k]
				if found {
					delete(refs.Insts, k)
					refs.DeleteRequestedInsts[newKey] = v
					updated = true
				}
			}
			if updated {
				allApis.appInstRefsApi.store.STMPut(stm, &refs)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	return nil
}
