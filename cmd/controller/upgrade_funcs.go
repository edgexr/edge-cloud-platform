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
	"sort"
	"strconv"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/objstore"
	gonanoid "github.com/matoous/go-nanoid/v2"
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

func removeKeyDbPrefix(key, dbPrefix string) string {
	pre := objstore.DbKeyPrefixString(dbPrefix)
	if len(key) > len(pre)+1 {
		return key[len(pre)+1:]
	}
	return key
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
	appInstKeyRefsUpgrade := make(map[AppInstRefKeyV1]edgeproto.AppInstRefKey)
	appInstKeyRefsCurrent := make(map[edgeproto.AppInstRefKey]struct{})
	appInstKeyJsonRefsUpgrade := make(map[string]string)
	appInstKeyJsonRefsCurrent := make(map[string]struct{})
	type AppInstV1 struct {
		Key             edgeproto.AppInstKeyV1 `json:"key"`
		RealClusterName string                 `json:"real_cluster_name"`
	}
	// Upgrade AppInst keys
	appInstKeys, err := getDbObjectKeys(objStore, "AppInst")
	if err != nil {
		return err
	}
	appInstKeysOrdered := []string{}
	for appInstKey, _ := range appInstKeys {
		// in order to have consistent results of unique name
		// generation for unit tests, the order the instances
		// are processed in must be consistent, so we sort them.
		appInstKeysOrdered = append(appInstKeysOrdered, appInstKey)
	}
	sort.Strings(appInstKeysOrdered)
	for _, appInstKey := range appInstKeysOrdered {
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
			appInstKeyNoPrefix := removeKeyDbPrefix(appInstKey, "AppInst")
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
				clusterName := appInst.VirtualClusterKey.Name
				if clusterName == "" {
					clusterName = appInst.ClusterKey.Name
				}
				// generate a new name for the AppInst
				// number of iterations must be low to avoid
				// STM limits.
				baseName := appInst.AppKey.Name
				for ii := 0; ii < 10; ii++ {
					appInst.Key.Name = baseName
					if ii > 0 && ii < 7 {
						appInst.Key.Name += strconv.Itoa(ii)
					} else if ii == 7 {
						appInst.Key.Name += "-" + clusterName
					} else if ii > 7 {
						// use random suffix
						suffix := gonanoid.MustGenerate(cloudcommon.IdAlphabetLC, 3)
						appInst.Key.Name += suffix
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

				// fix AppInstRefs, map old to new
				oldRef := AppInstRefKeyV1{}
				oldRef.AppKey = appInst.AppKey
				oldRef.ClusterInstKey.ClusterKey.Name = appInst.ClusterKey.Name
				oldRef.ClusterInstKey.Organization = appInst.ClusterKey.Organization
				appInstKeyRefsUpgrade[oldRef] = *appInst.Key.GetRefKey()
				// fix AppInstRefs json, map old to new
				keyJson, err := json.Marshal(appInst.Key)
				if err != nil {
					return err
				}
				appInstKeyJsonRefsUpgrade[appInstKeyNoPrefix] = string(keyJson)
			} else {
				// register current for AppInstRefs
				appInstKeyRefsCurrent[*appInst.Key.GetRefKey()] = struct{}{}
				appInstKeyJsonRefsCurrent[appInstKeyNoPrefix] = struct{}{}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	fixAppInstRefs := func(refKey, refType string, refs []edgeproto.AppInstRefKey, refsV1 []AppInstRefKeyV1, updated *bool) error {
		if len(refs) != len(refsV1) {
			return fmt.Errorf("%s unexpected %s refs count difference between parsing as new (%d) vs old (%d) format", refKey, refType, len(refs), len(refsV1))
		}
		for ii := 0; ii < len(refs); ii++ {
			oldRef := refsV1[ii]
			newRef, found := appInstKeyRefsUpgrade[oldRef]
			if found {
				refs[ii] = newRef
				*updated = true
				continue
			}
			curRef := refs[ii]
			_, found = appInstKeyRefsCurrent[curRef]
			if !found {
				return fmt.Errorf("%s %s ref %v not found for either new or old AppInstKeyName versions", refKey, refType, curRef)
			}
		}
		return nil
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
			if err2 := fixAppInstRefs(refsKey, "VmAppInsts", refs.VmAppInsts, refsV1.VmAppInsts, &updated); err != nil {
				return err2
			}
			if err2 := fixAppInstRefs(refsKey, "K8SAppInsts", refs.K8SAppInsts, refsV1.K8SAppInsts, &updated); err != nil {
				return err2
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
			if err2 := fixAppInstRefs(refsKey, "Apps", refs.Apps, refsV1.Apps, &updated); err != nil {
				return err2
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
	fixRefs := func(refsKey string, insts map[string]uint32, updated *bool) error {
		for k, v := range insts {
			if _, found := appInstKeyJsonRefsCurrent[k]; found {
				// already current
				continue
			}
			if newKey, found := appInstKeyJsonRefsUpgrade[k]; found {
				delete(insts, k)
				insts[newKey] = v
				*updated = true
				continue
			}
			return fmt.Errorf("%s unknown AppInstRef %s", refsKey, k)
		}
		return nil
	}
	for refsKey, _ := range appInstRefsKeys {
		_, err := objStore.ApplySTM(ctx, func(stm concurrency.STM) error {
			refsStr := stm.Get(refsKey)
			var refs edgeproto.AppInstRefs
			if err2 := unmarshalUpgradeObj(ctx, refsStr, &refs); err2 != nil {
				return err2
			}
			updated := false
			err := fixRefs(refsKey, refs.Insts, &updated)
			if err != nil {
				return err
			}
			err = fixRefs(refsKey, refs.DeleteRequestedInsts, &updated)
			if err != nil {
				return err
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
