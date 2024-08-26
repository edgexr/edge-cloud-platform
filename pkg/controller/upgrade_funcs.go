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

package controller

import (
	"encoding/json"
	fmt "fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/objstore"
	"github.com/oklog/ulid/v2"
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

func getDbObjectKeysList(objStore objstore.KVStore, dbPrefix string) ([]string, error) {
	keys, err := getDbObjectKeys(objStore, dbPrefix)
	if err != nil {
		return nil, err
	}
	keyList := []string{}
	for k := range keys {
		keyList = append(keyList, k)
	}
	sort.Strings(keyList)
	return keyList, nil
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
	AppKey     edgeproto.AppKey    `json:"app_key"`
	ClusterKey ClusterInstRefKeyV1 `json:"cluster_inst_key"`
}

type CloudletRefsV1 struct {
	ClusterInsts []ClusterInstRefKeyV1 `json:"cluster_insts"`
	VmAppInsts   []AppInstRefKeyV1     `json:"vm_app_insts"`
	K8SAppInsts  []AppInstRefKeyV1     `json:"k8s_app_insts"`
}

type ClusterRefsV1 struct {
	Apps []AppInstRefKeyV1 `json:"apps"`
}

func AddStaticFqdn(ctx context.Context, objStore objstore.KVStore, allApis *AllApis, sup *UpgradeSupport, dbModelID int32) error {
	// 1. Update cloudlets - set StaticRootLbFqdn
	cloudletKeys, err := getDbObjectKeys(objStore, "Cloudlet")
	if err != nil {
		return err
	}
	for cloudletKey := range cloudletKeys {
		_, err := objStore.ApplySTM(ctx, func(stm concurrency.STM) error {
			cloudletStr := stm.Get(cloudletKey)
			if cloudletStr == "" {
				// deleted in the meantime
				return nil
			}
			cloudlet := edgeproto.Cloudlet{}
			if err2 := unmarshalUpgradeObj(ctx, cloudletStr, &cloudlet); err2 != nil {
				return err2
			}
			// sanity check
			if cloudlet.StaticRootLbFqdn == "" {
				cloudlet.StaticRootLbFqdn = cloudlet.RootLbFqdn
				allApis.cloudletApi.store.STMPut(stm, &cloudlet)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	// 2. Update clusters
	clusterKeys, err := getDbObjectKeys(objStore, "ClusterInst")
	if err != nil {
		return err
	}
	for clusterKey := range clusterKeys {
		_, err := objStore.ApplySTM(ctx, func(stm concurrency.STM) error {
			clusterInstStr := stm.Get(clusterKey)
			if clusterInstStr == "" {
				return nil
			}
			// Note that we cannot use edgeproto.ClusterInst because
			// it has changed in later versions.
			data := map[string]any{}
			err := json.Unmarshal([]byte(clusterInstStr), &data)
			if err != nil {
				return err
			}
			if fqdn, ok := data["static_fqdn"]; ok && fqdn != "" {
				// already upgraded
				return nil
			}
			if _, ok := data["fqdn"]; !ok {
				return nil // no fqdn to copy in
			}
			data["static_fqdn"] = data["fqdn"]
			out, err := json.Marshal(&data)
			if err != nil {
				return err
			}
			stm.Put(clusterKey, string(out))
			return nil
		})
		if err != nil {
			return err
		}
	}
	// 3. Update AppInsts
	appInstKeys, err := getDbObjectKeys(objStore, "AppInst")
	if err != nil {
		return err
	}
	for appInstKey := range appInstKeys {
		_, err := objStore.ApplySTM(ctx, func(stm concurrency.STM) error {
			appInstString := stm.Get(appInstKey)
			if appInstString == "" {
				return nil
			}
			// Note that we cannot use edgeproto.ClusterInst because
			// it has changed in later versions.
			data := map[string]any{}
			err := json.Unmarshal([]byte(appInstString), &data)
			if err != nil {
				return err
			}
			if uri, ok := data["static_uri"]; ok && uri != "" {
				// already upgraded
				return nil
			}
			if _, ok := data["uri"]; !ok {
				return nil // no uri to copy in
			}
			data["static_uri"] = data["uri"]
			out, err := json.Marshal(&data)
			if err != nil {
				return err
			}
			stm.Put(appInstKey, string(out))
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func UpgradeCrmOnEdge(ctx context.Context, objStore objstore.KVStore, allApis *AllApis, sup *UpgradeSupport, dbModelID int32) error {
	log.SpanLog(ctx, log.DebugLevelUpgrade, "CrmOnEdge")

	cloudletKeys, err := getDbObjectKeys(objStore, "Cloudlet")
	if err != nil {
		return err
	}
	for cloudletKey := range cloudletKeys {
		_, err := objStore.ApplySTM(ctx, func(stm concurrency.STM) error {
			cloudletStr := stm.Get(cloudletKey)
			if cloudletStr == "" {
				// deleted in the meantime
				return nil
			}
			cloudlet := edgeproto.Cloudlet{}
			if err2 := unmarshalUpgradeObj(ctx, cloudletStr, &cloudlet); err2 != nil {
				return err2
			}
			if cloudlet.ObjId != "" {
				// already upgraded
				return nil
			}
			// all cloudlets before upgrade were designed for
			// CRM on the edge site
			cloudlet.CrmOnEdge = true
			cloudlet.ObjId = ulid.Make().String()
			allApis.cloudletApi.store.STMPut(stm, &cloudlet)
			return nil
		})
		if err != nil {
			return err
		}
	}

	// Upgrade AppInst keys
	appInstKeys, err := getDbObjectKeys(objStore, "AppInst")
	if err != nil {
		return err
	}
	for appInstKey := range appInstKeys {
		_, err := objStore.ApplySTM(ctx, func(stm concurrency.STM) error {
			appInstStr := stm.Get(appInstKey)
			if appInstStr == "" {
				// deleted in the meantime
				return nil
			}
			// Note that we cannot use edgeproto.AppInst because
			// it has changed in later versions.
			data := map[string]any{}
			err := json.Unmarshal([]byte(appInstStr), &data)
			if err != nil {
				return err
			}
			if _, ok := data["obj_id"]; ok {
				// already upgraded
				return nil
			}
			data["obj_id"] = ulid.Make().String()
			out, err := json.Marshal(data)
			if err != nil {
				return err
			}
			stm.Put(appInstKey, string(out))
			return nil
		})
		if err != nil {
			return err
		}
	}

	// Upgrade ClusterInst keys
	clusterKeys, err := getDbObjectKeys(objStore, "ClusterInst")
	if err != nil {
		return err
	}
	for key, _ := range clusterKeys {
		_, err = objStore.ApplySTM(ctx, func(stm concurrency.STM) error {
			clusterInstStr := stm.Get(key)
			if clusterInstStr == "" {
				return nil // was deleted
			}
			// Note that we cannot use edgeproto.AppInst because
			// it has changed in later versions.
			data := map[string]any{}
			err := json.Unmarshal([]byte(clusterInstStr), &data)
			if err != nil {
				return err
			}
			if _, ok := data["obj_id"]; ok {
				// already upgraded
				return nil
			}
			data["obj_id"] = ulid.Make().String()
			out, err := json.Marshal(data)
			if err != nil {
				return err
			}
			stm.Put(key, string(out))
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// InstanceKeysRegionScopedName deals with moving the CloudletKey out
// of the AppInst/ClusterInst Key and onto the object body, changing
// the unique key. Also, this requires the instance name to be unique
// within the entire region instead of within a cloudlet scope.
func InstanceKeysRegionScopedName(ctx context.Context, objStore objstore.KVStore, allApis *AllApis, sup *UpgradeSupport, dbModelID int32) error {
	// Unfortunately the last upgrade func had a bug which failed to
	// asign object IDs to AppInsts and ClusterInsts. We run the fixed
	// version here again. Note that all upgrade functions must be idempotent.
	err := UpgradeCrmOnEdge(ctx, objStore, allApis, sup, dbModelID)
	if err != nil {
		return err
	}

	// We may rename some ClusterInst and AppInst key names.
	// We need to track what the new names are, because there
	// are two objects that use the same key, i.e. ClusterInst and
	// ClusterInstInfo, or there are references by name, i.e.
	// CloudletRefs/ClusterRefs/AppInstRefs. Whatever renaming is
	// done for one must match for the others.
	ciUpdatedNames := map[edgeproto.ClusterInstKeyV2]edgeproto.ClusterKey{}
	aiUpdatedNames := map[edgeproto.AppInstKeyV2]edgeproto.AppInstKey{}
	trackCIName := func(clusterInst *edgeproto.ClusterInst) {
		v2 := edgeproto.ClusterInstKeyV2{
			ClusterKey:  clusterInst.Key,
			CloudletKey: clusterInst.CloudletKey,
		}
		// get old name
		v2.ClusterKey.Name = cloudcommon.GetClusterInstCloudletScopedName(clusterInst)
		ciUpdatedNames[v2] = clusterInst.Key
	}
	trackAIName := func(appInst *edgeproto.AppInst) {
		v2 := edgeproto.AppInstKeyV2{
			Name:         appInst.Key.Name,
			Organization: appInst.Key.Organization,
			CloudletKey:  appInst.CloudletKey,
		}
		// get old name
		v2.Name = cloudcommon.GetAppInstCloudletScopedName(appInst)
		aiUpdatedNames[v2] = appInst.Key
	}

	// in order to have consistent results of unique name
	// generation for unit tests, the order of the instances
	// is sorted for determinism.
	appInstKeys, err := getDbObjectKeysList(objStore, "AppInst")
	if err != nil {
		return err
	}
	for _, appInstKey := range appInstKeys {
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
			// move cloudlet key info to appInst body
			err := edgeproto.BindJSONAppInstV2(&appInst, []byte(appInstStr))
			if err != nil {
				return err
			}

			if !strings.Contains(appInstStr, `"cloudlet_key":{`) {
				// already upgraded, just track name transformation
				trackAIName(&appInst)
				return nil
			}

			// Check for conflicts due to the scope of the name changing.
			// We may need to calculate a new name. Number of iterations must
			// be low to avoid STM limits.
			for ii := 0; ii < 7; ii++ {
				buf := edgeproto.AppInst{}
				buf.Key = appInst.Key
				if ii > 0 && ii < 6 {
					buf.Key.Name += strconv.Itoa(ii)
				} else if ii == 6 {
					// append cloudlet hash, this should work because
					// the old name was unique in the scope of the cloudlet.
					buf.Key.Name += "-" + cloudcommon.GetCloudletKeyHash(&appInst.CloudletKey)
				}
				if allApis.appInstApi.store.STMGet(stm, &buf.Key, &buf) {
					if appInst.ObjId == buf.ObjId {
						// same object, another process already upgraded it
						trackAIName(&buf)
						return nil
					}
					// conflict, try again
					continue
				}
				// no conflict
				if appInst.Key.Name != buf.Key.Name {
					// save old name to annotations
					if appInst.Annotations == nil {
						appInst.Annotations = map[string]string{}
					}
					appInst.Annotations[cloudcommon.AnnotationCloudletScopedName] = appInst.Key.Name
				}
				log.SpanLog(ctx, log.DebugLevelUpgrade, "update old AppInst", "oldkey", appInst.Key, "newName", buf.Key.Name, "cloudlet", appInst.CloudletKey)
				// set new name, save new obj, delete old obj
				appInst.Key.Name = buf.Key.Name
				allApis.appInstApi.store.STMPut(stm, &appInst)
				stm.Del(appInstKey)
				trackAIName(&appInst)
				return nil
			}
			return fmt.Errorf("failed to upgrade AppInst %s on Cloudlet %s, unable to assign new non-conflicting name", appInst.Key.GetKeyString(), appInst.CloudletKey.GetKeyString())
		})
		if err != nil {
			return err
		}
	}

	// in order to have consistent results of unique name
	// generation for unit tests, the order of the instances
	// is sorted for determinism.
	clusterKeys, err := getDbObjectKeysList(objStore, "ClusterInst")
	if err != nil {
		return err
	}
	for _, clusterKey := range clusterKeys {
		_, err = objStore.ApplySTM(ctx, func(stm concurrency.STM) error {
			clusterInstStr := stm.Get(clusterKey)
			if clusterInstStr == "" {
				return nil // was deleted
			}
			clusterInst := edgeproto.ClusterInst{}
			if err2 := unmarshalUpgradeObj(ctx, clusterInstStr, &clusterInst); err2 != nil {
				return err2
			}
			// move cloudlet key info to clusterInst body
			err := edgeproto.BindJSONClusterInstV2(&clusterInst, []byte(clusterInstStr))
			if err != nil {
				return err
			}

			if !strings.Contains(clusterInstStr, `"cloudlet_key":{`) {
				// already upgraded, just track name transformation
				trackCIName(&clusterInst)
				return nil
			}

			// Check for conflicts due to the scope of the name changing.
			// We may need to calculate a new name. Number of iterations must
			// be low to avoid STM limits.
			for ii := 0; ii < 7; ii++ {
				buf := edgeproto.ClusterInst{}
				buf.Key = clusterInst.Key
				if ii > 0 && ii < 6 {
					buf.Key.Name += strconv.Itoa(ii)
				} else if ii == 6 {
					// append cloudlet hash, this should work because
					// the old name was unique in the scope of the cloudlet.
					buf.Key.Name += "-" + cloudcommon.GetCloudletKeyHash(&clusterInst.CloudletKey)
				}
				if allApis.clusterInstApi.store.STMGet(stm, &buf.Key, &buf) {
					if clusterInst.ObjId == buf.ObjId {
						// same object, another process already upgraded it
						trackCIName(&buf)
						return nil
					}
					// conflict, try again
					continue
				}
				// no conflict
				if clusterInst.Key.Name != buf.Key.Name {
					// save old name to annotations
					if clusterInst.Annotations == nil {
						clusterInst.Annotations = map[string]string{}
					}
					clusterInst.Annotations[cloudcommon.AnnotationCloudletScopedName] = clusterInst.Key.Name
				}
				log.SpanLog(ctx, log.DebugLevelUpgrade, "update old ClusterInst", "oldkey", clusterInst.Key, "newName", buf.Key.Name, "cloudlet", clusterInst.CloudletKey)
				// set new name, save new obj, delete old obj
				clusterInst.Key.Name = buf.Key.Name
				allApis.clusterInstApi.store.STMPut(stm, &clusterInst)
				stm.Del(clusterKey)
				trackCIName(&clusterInst)
				return nil
			}
			return fmt.Errorf("failed to upgrade AppInst %s on Cloudlet %s, unable to assign new non-conflicting name", clusterInst.Key.GetKeyString(), clusterInst.CloudletKey.GetKeyString())
		})
		if err != nil {
			return err
		}
	}

	cloudletRefsKeys, err := getDbObjectKeysList(objStore, "CloudletRefs")
	if err != nil {
		return err
	}
	for _, cloudletRefsKey := range cloudletRefsKeys {
		_, err = objStore.ApplySTM(ctx, func(stm concurrency.STM) error {
			cloudletRefsStr := stm.Get(cloudletRefsKey)
			if cloudletRefsStr == "" {
				return nil // was deleted
			}
			refs := edgeproto.CloudletRefs{}
			if err2 := unmarshalUpgradeObj(ctx, cloudletRefsStr, &refs); err2 != nil {
				return err2
			}
			updated := false
			// update ClusterInsts from ClusterInstKeyV2 to ClusterKey
			for ii, cikey := range refs.ClusterInsts {
				v2 := edgeproto.ClusterInstKeyV2{
					ClusterKey:  cikey,
					CloudletKey: refs.Key,
				}
				if newKey, ok := ciUpdatedNames[v2]; ok && !newKey.Matches(&cikey) {
					refs.ClusterInsts[ii] = newKey
					updated = true
				}
			}
			// update VmAppInsts from AppInstKeyV2 to AppInstKey
			for ii, aikey := range refs.VmAppInsts {
				v2 := edgeproto.AppInstKeyV2{
					Name:         aikey.Name,
					Organization: aikey.Organization,
					CloudletKey:  refs.Key,
				}
				if newKey, ok := aiUpdatedNames[v2]; ok && !newKey.Matches(&aikey) {
					refs.VmAppInsts[ii] = newKey
					updated = true
				}
			}
			// update K8SAppInsts from AppInstKeyV2 to AppInstKey
			for ii, aikey := range refs.K8SAppInsts {
				v2 := edgeproto.AppInstKeyV2{
					Name:         aikey.Name,
					Organization: aikey.Organization,
					CloudletKey:  refs.Key,
				}
				if newKey, ok := aiUpdatedNames[v2]; ok && !newKey.Matches(&aikey) {
					refs.K8SAppInsts[ii] = newKey
					updated = true
				}
			}
			if !updated {
				return nil
			}
			allApis.cloudletRefsApi.store.STMPut(stm, &refs)
			return nil
		})
		if err != nil {
			return err
		}
	}

	clusterRefsKeys, err := getDbObjectKeysList(objStore, "ClusterRefs")
	if err != nil {
		return err
	}
	for _, clusterRefsKey := range clusterRefsKeys {
		if !strings.Contains(clusterRefsKey, `"cloudlet_key":{`) {
			// not the old version
			continue
		}
		_, err = objStore.ApplySTM(ctx, func(stm concurrency.STM) error {
			clusterRefsStr := stm.Get(clusterRefsKey)
			if clusterRefsStr == "" {
				return nil // was deleted
			}
			refs := edgeproto.ClusterRefs{}
			if err2 := unmarshalUpgradeObj(ctx, clusterRefsStr, &refs); err2 != nil {
				return err2
			}
			// update key from ClusterInstKeyV2 to ClusterKey
			cloudletKey, err := edgeproto.BindJSONClusterRefsV2(&refs, []byte(clusterRefsStr))
			if err != nil {
				return err
			}
			if cloudletKey == nil {
				// shouldn't happen, as cloudletKey info is in key
				return fmt.Errorf("no cloudletKey info found for old key %s", clusterRefsKey)
			}
			// update key if renamed
			v2 := edgeproto.ClusterInstKeyV2{
				ClusterKey:  refs.Key,
				CloudletKey: *cloudletKey,
			}
			if newKey, ok := ciUpdatedNames[v2]; ok && !newKey.Matches(&refs.Key) {
				refs.Key = newKey
			}
			// update Apps refs from AppInstKeyV2 to AppInstKey
			for ii, aikey := range refs.Apps {
				v2 := edgeproto.AppInstKeyV2{
					Name:         aikey.Name,
					Organization: aikey.Organization,
					CloudletKey:  *cloudletKey,
				}
				if newKey, ok := aiUpdatedNames[v2]; ok && !newKey.Matches(&aikey) {
					refs.Apps[ii] = newKey
				}
			}
			allApis.clusterRefsApi.store.STMPut(stm, &refs)
			stm.Del(clusterRefsKey)
			return nil
		})
		if err != nil {
			return err
		}
	}

	appInstRefsKeys, err := getDbObjectKeysList(objStore, "AppInstRefs")
	if err != nil {
		return err
	}
	for _, key := range appInstRefsKeys {
		_, err = objStore.ApplySTM(ctx, func(stm concurrency.STM) error {
			appInstRefsStr := stm.Get(key)
			if appInstRefsStr == "" {
				return nil // was deleted
			}
			refs := edgeproto.AppInstRefs{}
			if err2 := unmarshalUpgradeObj(ctx, appInstRefsStr, &refs); err2 != nil {
				return err2
			}
			// update insts refs from AppInstKeyV2 to AppInstKey
			updated := false
			for str, val := range refs.Insts {
				key, v2, err := edgeproto.BindJSONAppInstKeyV2([]byte(str))
				if err != nil {
					return err
				}
				if v2 == nil {
					// already upgraded
					continue
				}
				if newKey, ok := aiUpdatedNames[*v2]; ok && !newKey.Matches(key) {
					newStr, err := json.Marshal(newKey)
					if err != nil {
						return err
					}
					refs.Insts[string(newStr)] = val
					delete(refs.Insts, str)
					updated = true
				}
			}
			if !updated {
				return nil
			}
			allApis.appInstRefsApi.store.STMPut(stm, &refs)
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}
