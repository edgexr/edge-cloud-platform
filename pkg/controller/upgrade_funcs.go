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

	"github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/objstore"
	"github.com/edgexr/jsonparser"
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

func getDbObjects(objStore objstore.KVStore, dbPrefix string, cb func(key, val string) error) error {
	keystr := fmt.Sprintf("%s/", objstore.DbKeyPrefixString(dbPrefix))
	err := objStore.List(keystr, func(key, val []byte, rev, modRev int64) error {
		return cb(string(key), string(val))
	})
	return err
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

// AppInstKeyName fixes an issue with the original AppInstKeyName
// upgrade function which failed to upgrade ClusterRefs properly, as it was
// looking for the wrong AppInst ref format.
func AppInstKeyName(ctx context.Context, objStore objstore.KVStore, allApis *AllApis, sup *UpgradeSupport, dbModelID int32) error {
	log.SpanLog(ctx, log.DebugLevelUpgrade, "AppInstKeyNameClusterRefs")

	// Track key refs so we can upgrade references
	appInstsByCluster := map[edgeproto.ClusterKey]map[edgeproto.AppInstKey]*edgeproto.AppInst{}

	// AppInst keys
	err := getDbObjects(objStore, "AppInst", func(key, val string) error {
		var appInst edgeproto.AppInst
		if err2 := unmarshalUpgradeObj(ctx, val, &appInst); err2 != nil {
			return err2
		}
		if appInst.ClusterKey.Name == "" || appInst.ClusterKey.Organization == "" {
			// VM app inst
			return nil
		}
		insts, ok := appInstsByCluster[appInst.ClusterKey]
		if !ok {
			insts = map[edgeproto.AppInstKey]*edgeproto.AppInst{}
			appInstsByCluster[appInst.ClusterKey] = insts
		}
		insts[appInst.Key] = &appInst
		return nil
	})
	if err != nil {
		return err
	}

	// ensure cluster refs exist and are up to date
	for clusterKey, appInsts := range appInstsByCluster {
		_, err := objStore.ApplySTM(ctx, func(stm concurrency.STM) error {
			refs := edgeproto.ClusterRefs{}
			if !allApis.clusterRefsApi.store.STMGet(stm, &clusterKey, &refs) {
				refs.Key = clusterKey
			}
			curRefs := map[edgeproto.AppInstKey]struct{}{}
			refsList := []edgeproto.AppInstKey{}
			for _, aikey := range refs.Apps {
				buf := edgeproto.AppInst{}
				if !allApis.appInstApi.store.STMGet(stm, &aikey, &buf) {
					// invalid ref
					continue
				}
				refsList = append(refsList, aikey)
				curRefs[aikey] = struct{}{}
			}
			updated := false
			if len(refsList) != len(refs.Apps) {
				// some invalid apps were removed
				refs.Apps = refsList
				updated = true
			}
			// add any appinsts that were missing
			for aikey, _ := range appInsts {
				if _, found := curRefs[aikey]; found {
					continue
				}
				// make sure it hasn't been deleted
				ai := edgeproto.AppInst{}
				if !allApis.appInstApi.store.STMGet(stm, &aikey, &ai) {
					continue
				}
				// double check cluster
				if !ai.ClusterKey.Matches(&refs.Key) {
					continue
				}
				refs.Apps = append(refs.Apps, aikey)
				updated = true
			}
			if updated {
				// sort refs for determinism
				sort.Slice(refs.Apps, func(i, j int) bool {
					return refs.Apps[i].GetKeyString() < refs.Apps[j].GetKeyString()
				})
				allApis.clusterRefsApi.store.STMPut(stm, &refs)
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	// Delete orphaned clusterrefs. These may have come from bad upgrades.
	clusterRefsKeys, err := getDbObjectKeys(objStore, "ClusterRefs")
	if err != nil {
		return err
	}
	for clusterRefsKey := range clusterRefsKeys {
		_, err = objStore.ApplySTM(ctx, func(stm concurrency.STM) error {
			clusterRefsStr := stm.Get(clusterRefsKey)
			if clusterRefsStr == "" {
				return nil // was deleted
			}
			refs := edgeproto.ClusterRefs{}
			if err2 := unmarshalUpgradeObj(ctx, clusterRefsStr, &refs); err2 != nil {
				return err2
			}
			ci := edgeproto.ClusterInst{}
			if !allApis.clusterInstApi.store.STMGet(stm, &refs.Key, &ci) {
				// no cluster
				stm.Del(clusterRefsKey)
				return nil
			}
			// validate appinsts exist
			apps := []edgeproto.AppInstKey{}
			for _, aikey := range refs.Apps {
				ai := edgeproto.AppInst{}
				if allApis.appInstApi.store.STMGet(stm, &aikey, &ai) {
					apps = append(apps, aikey)
				}
			}
			if len(apps) != len(refs.Apps) {
				// changed
				if len(apps) == 0 {
					// no apps, delete it
					stm.Del(clusterRefsKey)
				} else {
					refs.Apps = apps
					allApis.clusterRefsApi.store.STMPut(stm, &refs)
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
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
				log.SpanLog(ctx, log.DebugLevelUpgrade, "Upgrade unmarshal object failed", "objType", "appInst", "key", appInstKey, "val", appInstStr, "err", err)
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
				log.SpanLog(ctx, log.DebugLevelUpgrade, "Upgrade unmarshal object failed", "objType", "clusterInst", "key", key, "val", clusterInstStr, "err", err)
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
	// invalid reservable clusterInst names for previous version of this
	// upgrade function
	ciBadNames := map[edgeproto.ClusterKey]edgeproto.ClusterKey{}
	trackCINameBad := func(ci *edgeproto.ClusterInst) {
		badName, ok := ci.Annotations[cloudcommon.AnnotationBadUpgrade55Name]
		if ok {
			badKey := ci.Key
			badKey.Name = badName
			ciBadNames[badKey] = ci.Key
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
			keyName := clusterInst.Key.Name

			// previous version of upgrade function did not upgrade
			// reservable ClusterInst names correctly. We need to append
			// the cloudlet hash instead of iterating to determine a new
			// name, because the name needs to preserve the id value
			// in the name to release the reservation from the etcd database.
			var badKey edgeproto.ClusterKey
			if clusterInst.Reservable {
				_, hash, err := cloudcommon.ParseReservableClusterName(clusterInst.Key.Name)
				if err != nil {
					return fmt.Errorf("upgrade clusterInst %s failed, %s", clusterKey, err)
				}
				if hash == "" {
					// ClusterInst was either not upgraded yet, or upgraded to
					// invalid name.
					name := cloudcommon.GetClusterInstCloudletScopedName(&clusterInst)
					if clusterInst.Key.Name != name {
						// previous name annotation exists, so this was upgraded.
						// this means current name is invalid format.
						badKey = clusterInst.Key
						// reset name to original so we can set new name properly.
						clusterInst.Key.Name = name
					}
				}
			}

			// Check for conflicts due to the scope of the name changing.
			// We may need to calculate a new name. Number of iterations must
			// be low to avoid STM limits.
			for ii := 0; ii < 7; ii++ {
				buf := edgeproto.ClusterInst{}
				buf.Key = clusterInst.Key
				if clusterInst.Reservable {
					id, hash, err := cloudcommon.ParseReservableClusterName(clusterInst.Key.Name)
					if err != nil {
						return fmt.Errorf("upgrade clusterInst %s failed, %s", clusterKey, err)
					}
					if hash == "" {
						// old name format, upgrade to new format
						buf.Key.Name = cloudcommon.BuildReservableClusterName(id, &clusterInst.CloudletKey)
					}
				} else {
					if ii > 0 && ii < 6 {
						buf.Key.Name += strconv.Itoa(ii)
					} else if ii == 6 {
						// append cloudlet hash, this should work because
						// the old name was unique in the scope of the cloudlet.
						buf.Key.Name += "-" + cloudcommon.GetCloudletKeyHash(&clusterInst.CloudletKey)
					}
					if allApis.clusterInstApi.store.STMGet(stm, &buf.Key, &buf) {
						if clusterInst.ObjId != buf.ObjId {
							// conflict, try again
							continue
						}
						// object already exists
						trackCIName(&clusterInst)
						return nil
					}
				}
				// no conflict
				if clusterInst.Key.Name != buf.Key.Name {
					// save old name to annotations
					clusterInst.AddAnnotationNoClobber(cloudcommon.AnnotationCloudletScopedName, clusterInst.Key.Name)
				}
				log.SpanLog(ctx, log.DebugLevelUpgrade, "update old ClusterInst", "oldkey", clusterInst.Key, "newName", buf.Key.Name, "cloudlet", clusterInst.CloudletKey)
				// set new name, save new obj, delete old obj
				clusterInst.Key.Name = buf.Key.Name
				if badKey.Name != "" {
					clusterInst.AddAnnotationNoClobber(cloudcommon.AnnotationBadUpgrade55Name, badKey.Name)
				}
				allApis.clusterInstApi.store.STMPut(stm, &clusterInst)
				if strings.Contains(clusterKey, `"cloudlet_key":{`) || keyName != clusterInst.Key.Name {
					stm.Del(clusterKey)
				}
				trackCIName(&clusterInst)
				trackCINameBad(&clusterInst)
				return nil
			}
			return fmt.Errorf("failed to upgrade AppInst %s on Cloudlet %s, unable to assign new non-conflicting name", clusterInst.Key.GetKeyString(), clusterInst.CloudletKey.GetKeyString())
		})
		if err != nil {
			return err
		}
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

			// if clusterInst changed name, get the new name
			// Note that newClusterKey will be nil for VM AppInsts.
			var newClusterKey *edgeproto.ClusterKey
			clustV2Key := edgeproto.ClusterInstKeyV2{
				CloudletKey: appInst.CloudletKey,
				ClusterKey:  appInst.ClusterKey,
			}
			if key, ok := ciUpdatedNames[clustV2Key]; ok {
				if appInst.ClusterKey.Name != key.Name || appInst.ClusterKey.Organization != key.Organization {
					newClusterKey = &key
				}
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
					if appInst.ObjId != buf.ObjId {
						// conflict, try again
						continue
					}
					// object exists, but we may need update ClusterKey,
					// as a previous version of this upgrade function
					// did not do so.
					if newClusterKey == nil {
						// no need to update ClusterKey
						trackAIName(&buf)
						return nil
					}
				}
				// no conflict
				if appInst.Key.Name != buf.Key.Name {
					// save old name to annotations
					appInst.AddAnnotationNoClobber(cloudcommon.AnnotationCloudletScopedName, appInst.Key.Name)
				}
				if newClusterKey != nil {
					appInst.ClusterKey = *newClusterKey
				}
				log.SpanLog(ctx, log.DebugLevelUpgrade, "update old AppInst", "oldkey", appInst.Key, "newName", buf.Key.Name, "cloudlet", appInst.CloudletKey)
				// set new name, save new obj, delete old obj
				appInst.Key.Name = buf.Key.Name
				allApis.appInstApi.store.STMPut(stm, &appInst)
				if strings.Contains(appInstKey, `"cloudlet_key":{`) {
					stm.Del(appInstKey)
				}
				trackAIName(&appInst)
				return nil
			}
			return fmt.Errorf("failed to upgrade AppInst %s on Cloudlet %s, unable to assign new non-conflicting name", appInst.Key.GetKeyString(), appInst.CloudletKey.GetKeyString())
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
				if newKey, ok := ciUpdatedNames[v2]; ok {
					refs.ClusterInsts[ii] = newKey
					updated = true
				}
				// check if ref is for bad reservable cluster inst name
				if newKey, ok := ciBadNames[cikey]; ok {
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
				if newKey, ok := aiUpdatedNames[v2]; ok {
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
				if newKey, ok := aiUpdatedNames[v2]; ok {
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
		_, err = objStore.ApplySTM(ctx, func(stm concurrency.STM) error {
			clusterRefsStr := stm.Get(clusterRefsKey)
			if clusterRefsStr == "" {
				return nil // was deleted
			}
			refs := edgeproto.ClusterRefs{}
			if err2 := unmarshalUpgradeObj(ctx, clusterRefsStr, &refs); err2 != nil {
				return err2
			}
			inKey := refs.Key
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
			if newKey, ok := ciUpdatedNames[v2]; ok {
				refs.Key = newKey
			}
			// check if ref is for bad reservable cluster inst name
			if newKey, ok := ciBadNames[refs.Key]; ok {
				refs.Key = newKey
			}
			// update Apps refs from AppInstKeyV2 to AppInstKey
			for ii, aikey := range refs.Apps {
				v2 := edgeproto.AppInstKeyV2{
					Name:         aikey.Name,
					Organization: aikey.Organization,
					CloudletKey:  *cloudletKey,
				}
				if v2.Name == "" {
					// invalid ref, skip it, we'll rebuild clusterRefs
					// at the end anyway.
				}
				if newKey, ok := aiUpdatedNames[v2]; ok {
					refs.Apps[ii] = newKey
				}
			}
			allApis.clusterRefsApi.store.STMPut(stm, &refs)
			if inKey.Name != refs.Key.Name {
				// name changed, delete entry with old name
				stm.Del(clusterRefsKey)
			}
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
				_, v2, err := edgeproto.BindJSONAppInstKeyV2([]byte(str))
				if err != nil {
					return err
				}
				if v2 == nil {
					// already upgraded
					continue
				}
				if newKey, ok := aiUpdatedNames[*v2]; ok {
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

	// AppInstKeyName had a bug where clusterRefs were not upgraded properly.
	// The fix assumes clusterRefs are stored with a key in the current
	// format, so this must be run after the instance key upgrade.
	err = AppInstKeyName(ctx, objStore, allApis, sup, dbModelID)
	if err != nil {
		return err
	}

	return nil
}

type CloudletPoolKey struct {
	// Name of the organization this pool belongs to
	Organization string `protobuf:"bytes,1,opt,name=organization,proto3" json:"organization,omitempty"`
	// CloudletPool Name
	Name string `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
}

type CloudletPool struct {
	// Fields are used for the Update API to specify which fields to apply
	Fields []string `protobuf:"bytes,1,rep,name=fields,proto3" json:"fields,omitempty"`
	// CloudletPool key
	Key CloudletPoolKey `protobuf:"bytes,2,opt,name=key,proto3" json:"key"`
	// Cloudlets part of the pool
	Cloudlets []edgeproto.CloudletKey `protobuf:"bytes,3,rep,name=cloudlets,proto3" json:"cloudlets"`
	// Created at time
	CreatedAt distributed_match_engine.Timestamp `protobuf:"bytes,4,opt,name=created_at,json=createdAt,proto3" json:"created_at"`
	// Updated at time
	UpdatedAt distributed_match_engine.Timestamp `protobuf:"bytes,5,opt,name=updated_at,json=updatedAt,proto3" json:"updated_at"`
	// Preparing to be deleted
	DeletePrepare bool `protobuf:"varint,6,opt,name=delete_prepare,json=deletePrepare,proto3" json:"delete_prepare,omitempty"`
}

type AutoProvCloudlet struct {
	// Cloudlet key
	Key edgeproto.CloudletKey `protobuf:"bytes,1,opt,name=key,proto3" json:"key"`
	// Cloudlet location
	Loc distributed_match_engine.Loc `protobuf:"bytes,2,opt,name=loc,proto3" json:"loc"`
}

type TrustPolicyExceptionKey struct {
	// App Key
	AppKey edgeproto.AppKey `protobuf:"bytes,1,opt,name=app_key,json=appKey,proto3" json:"app_key"`
	// CloudletPool Key
	CloudletPoolKey CloudletPoolKey `protobuf:"bytes,2,opt,name=cloudlet_pool_key,json=cloudletPoolKey,proto3" json:"cloudlet_pool_key"`
	// TrustPolicyExceptionKey name
	Name string `protobuf:"bytes,3,opt,name=name,proto3" json:"name,omitempty"`
}

// ZoneFeature adds support for a Zone feature. Each pre-existing cloudlet
// will get a Zone of the same name created it for, and assigned to it.
// Existing cloudlet pools will be rewritten as zone pools, with the same
// membership (because on upgrade, cloudlets and zones are 1:1).
func ZoneFeature(ctx context.Context, objStore objstore.KVStore, allApis *AllApis, sup *UpgradeSupport, dbModelID int32) error {
	log.SpanLog(ctx, log.DebugLevelUpgrade, "Zone Feature")

	// Create a new Zone for every Cloudlet and assign the cloudlet to the zone.
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
			if cloudlet.DbModelId >= dbModelID {
				// already upgraded
				return nil
			}
			// create a new zone if needed for the cloudlet
			zoneKey := cloudletKeyToZoneKey(&cloudlet.Key)
			zone := edgeproto.Zone{}
			if !allApis.zoneApi.store.STMGet(stm, zoneKey, &zone) {
				zone.Key = *zoneKey
				zone.ObjId = strings.ToLower(ulid.Make().String())
				zone.Location = cloudlet.Location
				zone.CreatedAt = cloudlet.CreatedAt
				allApis.zoneApi.store.STMPut(stm, &zone)
			}
			cloudlet.DbModelId = dbModelID
			cloudlet.Zone = zoneKey.Name
			allApis.cloudletApi.store.STMPut(stm, &cloudlet)
			return nil
		})
		if err != nil {
			return err
		}
	}

	// Set ZoneKey field for ClusterInst
	clusterKeys, err := getDbObjectKeys(objStore, "ClusterInst")
	if err != nil {
		return err
	}
	for clusterKey := range clusterKeys {
		_, err := objStore.ApplySTM(ctx, func(stm concurrency.STM) error {
			clusterStr := stm.Get(clusterKey)
			if clusterStr == "" {
				// deleted in the meantime
				return nil
			}
			ci := edgeproto.ClusterInst{}
			if err2 := unmarshalUpgradeObj(ctx, clusterStr, &ci); err2 != nil {
				return err2
			}
			if ci.DbModelId >= dbModelID {
				// already upgraded
				return nil
			}
			ci.DbModelId = dbModelID
			ci.ZoneKey = *cloudletKeyToZoneKey(&ci.CloudletKey)
			allApis.clusterInstApi.store.STMPut(stm, &ci)
			return nil
		})
		if err != nil {
			return err
		}
	}

	// Set ZoneKey field for AppInst
	aiKeys, err := getDbObjectKeys(objStore, "AppInst")
	if err != nil {
		return err
	}
	for aiKey := range aiKeys {
		_, err := objStore.ApplySTM(ctx, func(stm concurrency.STM) error {
			aiStr := stm.Get(aiKey)
			if aiStr == "" {
				// deleted in the meantime
				return nil
			}
			ai := edgeproto.AppInst{}
			if err2 := unmarshalUpgradeObj(ctx, aiStr, &ai); err2 != nil {
				return err2
			}
			if ai.DbModelId >= dbModelID {
				// already upgraded
				return nil
			}
			ai.DbModelId = dbModelID
			ai.ZoneKey = *cloudletKeyToZoneKey(&ai.CloudletKey)
			allApis.appInstApi.store.STMPut(stm, &ai)
			return nil
		})
		if err != nil {
			return err
		}
	}

	// Convert CloudletPools to ZonePools
	cpKeys, err := getDbObjectKeys(objStore, "CloudletPool")
	if err != nil {
		return err
	}
	for cpKey := range cpKeys {
		_, err := objStore.ApplySTM(ctx, func(stm concurrency.STM) error {
			cpStr := stm.Get(cpKey)
			if cpStr == "" {
				// deleted in the meantime
				return nil
			}
			cp := CloudletPool{}
			if err2 := unmarshalUpgradeObj(ctx, cpStr, &cp); err2 != nil {
				return err2
			}
			zp := edgeproto.ZonePool{}
			zp.Key.Name = cp.Key.Name
			zp.Key.Organization = cp.Key.Organization
			if allApis.zonePoolApi.store.STMGet(stm, &zp.Key, &zp) {
				// already exists
				return nil
			}
			zp.CreatedAt = cp.CreatedAt
			zp.UpdatedAt = cp.UpdatedAt
			zp.DeletePrepare = cp.DeletePrepare
			for _, ckey := range cp.Cloudlets {
				zkey := cloudletKeyToZoneKey(&ckey)
				zp.Zones = append(zp.Zones, zkey)
			}
			stm.Del(cpKey)
			allApis.zonePoolApi.store.STMPut(stm, &zp)
			return nil
		})
		if err != nil {
			return err
		}
	}

	// Change AutoProvPolicy to use Zones instead of Cloudlets
	autoprovKeys, err := getDbObjectKeys(objStore, "AutoProvPolicy")
	if err != nil {
		return err
	}
	for key := range autoprovKeys {
		_, err := objStore.ApplySTM(ctx, func(stm concurrency.STM) error {
			autoprovStr := stm.Get(key)
			if autoprovStr == "" {
				// deleted in the meantime
				return nil
			}
			cloudlets := []AutoProvCloudlet{}
			cloudletsStr, dt, _, err := jsonparser.Get([]byte(autoprovStr), "cloudlets")
			if err != nil && dt == jsonparser.NotExist {
				// already upgraded
				return nil
			}
			if err != nil {
				return fmt.Errorf("failed to read autoprovpolicy json %s, %s", autoprovStr, err)
			}
			err = json.Unmarshal(cloudletsStr, &cloudlets)
			if err != nil {
				return fmt.Errorf("failed to unmarshal autoprovpolicy cloudlets string %s, %s", string(cloudletsStr), err)
			}
			policy := edgeproto.AutoProvPolicy{}
			if err2 := unmarshalUpgradeObj(ctx, autoprovStr, &policy); err2 != nil {
				return err2
			}
			for _, cl := range cloudlets {
				policy.Zones = append(policy.Zones, cloudletKeyToZoneKey(&cl.Key))
			}
			allApis.autoProvPolicyApi.store.STMPut(stm, &policy)
			return nil
		})
		if err != nil {
			return err
		}
	}

	// Change TrustPolicyException Key to use ZonePool instead of CloudletPool
	tpeKeys, err := getDbObjectKeys(objStore, "TrustPolicyException")
	if err != nil {
		return err
	}
	for key := range tpeKeys {
		if !strings.Contains(key, `"cloudlet_pool_key":{`) {
			continue
		}
		_, err := objStore.ApplySTM(ctx, func(stm concurrency.STM) error {
			tpeStr := stm.Get(key)
			if tpeStr == "" {
				// deleted in the meantime
				return nil
			}
			tpeKeyOld := TrustPolicyExceptionKey{}
			keyJSON := removeKeyDbPrefix(key, "TrustPolicyException")
			if err := json.Unmarshal([]byte(keyJSON), &tpeKeyOld); err != nil {
				return fmt.Errorf("failed to unmarshal old trust policy exception key using cloudlet pool %s, %s", key, err)
			}
			if tpeKeyOld.CloudletPoolKey.Name == "" || tpeKeyOld.CloudletPoolKey.Organization == "" {
				return fmt.Errorf("old trust policy exception key missing cloudlet pool information or unable to extract using json unmarshal, %s", key)
			}
			tpe := edgeproto.TrustPolicyException{}
			if err2 := unmarshalUpgradeObj(ctx, tpeStr, &tpe); err2 != nil {
				return err2
			}
			tpe.Key.ZonePoolKey.Name = tpeKeyOld.CloudletPoolKey.Name
			tpe.Key.ZonePoolKey.Organization = tpeKeyOld.CloudletPoolKey.Organization
			buf := edgeproto.TrustPolicyException{}
			if allApis.trustPolicyExceptionApi.store.STMGet(stm, &tpe.Key, &buf) {
				// already exists
				return nil
			}
			allApis.trustPolicyExceptionApi.store.STMPut(stm, &tpe)
			stm.Del(key)
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func cloudletKeyToZoneKey(key *edgeproto.CloudletKey) *edgeproto.ZoneKey {
	return &edgeproto.ZoneKey{
		Name:                  key.Name,
		Organization:          key.Organization,
		FederatedOrganization: key.FederatedOrganization,
	}
}
