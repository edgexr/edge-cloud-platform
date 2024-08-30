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

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/objstore"
	"github.com/opentracing/opentracing-go"
	context "golang.org/x/net/context"
)

var testDataKeyPrefix = "_testdatakey"

// Prototype for the upgrade function - takes an objectstore and stm to ensure
// automicity of each upgrade function
type VersionUpgradeFunc func(context.Context, objstore.KVStore, *AllApis, *UpgradeSupport, int32) error

// Helper function to run a single upgrade function across all the elements of a KVStore
// fn will be called for each of the entries, and therefore it's up to the
// fn implementation to filter based on the prefix
func RunSingleUpgrade(ctx context.Context, objStore objstore.KVStore, allApis *AllApis, upgradeSupport *UpgradeSupport, fn VersionUpgradeFunc, upgradeID int32) error {
	err := fn(ctx, objStore, allApis, upgradeSupport, upgradeID)
	if err != nil {
		return fmt.Errorf("Could not upgrade objects store entries, err: %v\n", err)
	}
	return nil
}

func checkAndUpgrade(ctx context.Context, objStore objstore.KVStore, allApis *AllApis, autoUpgrade bool, targetVers *edgeproto.DataModelVersion, upgradeFuncs []VersionUpgrade) error {
	// First off - check version of the objectStore we are running
	version, err := getDataVersion(ctx, objStore, targetVers)
	if err != nil {
		return fmt.Errorf("database version check failed, %s", err)
	}
	if autoUpgrade && targetVers.Hash != version.Hash {
		upgradeSupport := &UpgradeSupport{
			region:      *region,
			vaultConfig: vaultConfig,
		}
		err = upgradeToLatest(version, objStore, allApis, upgradeSupport, upgradeFuncs)
		if err != nil {
			return fmt.Errorf("Failed to ugprade data model: %v", err)
		}
	} else if targetVers.Hash != version.Hash {
		return fmt.Errorf("Running version %s doesn't match the etcd database version %s, and autoUpgrade is not enabled", targetVers.Hash, version.Hash)
	}
	return nil
}

// This function walks all upgrade functions from the fromVersion to current
// and upgrades the KVStore using those functions one-by-one
func upgradeToLatest(fromVersion *edgeproto.DataModelVersion, objStore objstore.KVStore, allApis *AllApis, upgradeSupport *UpgradeSupport, upgradeFuncs []VersionUpgrade) error {
	verID := fromVersion.ID
	span := log.StartSpan(log.DebugLevelInfo, "upgrade")
	span.SetTag("fromVersion", fromVersion)
	span.SetTag("verID", verID)
	defer span.Finish()
	ctx := opentracing.ContextWithSpan(context.Background(), span)
	for _, upgrade := range upgradeFuncs {
		if verID >= upgrade.id {
			continue
		}
		// run upgrade
		verID = upgrade.id
		fn := upgrade.upgradeFunc
		if fn == nil {
			continue
		}
		name := upgrade.name

		uspan := log.StartSpan(log.DebugLevelInfo, name, opentracing.ChildOf(span.Context()))
		uctx := log.ContextWithSpan(context.Background(), uspan)
		if fn != nil {
			// Call the upgrade with an appropriate callback
			if err := RunSingleUpgrade(uctx, objStore, allApis, upgradeSupport, fn, verID); err != nil {
				uspan.Finish()
				return fmt.Errorf("Failed to run %s: %v\n",
					name, err)
			}
			log.SpanLog(uctx, log.DebugLevelUpgrade, "Upgrade complete", "upgradeID", verID, "upgradeFunc", name)
		}
		// Write out the new version
		upgradedVers := edgeproto.DataModelVersion{
			Hash: upgrade.hash,
			ID:   verID,
		}
		err := writeDataModelVersionV2(uctx, objStore, &upgradedVers)
		uspan.Finish()
		if err != nil {
			return fmt.Errorf("Failed to update version for the db: %v\n", err)
		}
	}
	log.SpanLog(ctx, log.DebugLevelInfo, "Upgrade done")
	return nil
}

func TestUpgradeExample(ctx context.Context, objStore objstore.KVStore) error {
	log.DebugLog(log.DebugLevelUpgrade, "TestUpgradeExample - reverse keys and values")
	// Define a prefix for a walk
	keystr := fmt.Sprintf("%s/", testDataKeyPrefix)
	err := objStore.List(keystr, func(key, val []byte, rev, modRev int64) error {
		objStore.Delete(ctx, string(key))
		objStore.Put(ctx, string(val), string(key))
		return nil
	})
	return err
}

// DataModelVersion0's db value is a string which was the hash value.
// DataModelVersion2's db value is the JSON of edgeproto.DataModelVersion.
const (
	DataModelVersion0Prefix = "Version"
	DataModelVersion2Prefix = "VersionV2"
)

func writeDataModelVersionV2(ctx context.Context, objStore objstore.KVStore, vers *edgeproto.DataModelVersion) error {
	out, err := json.Marshal(vers)
	if err != nil {
		return fmt.Errorf("failed to marshal data model version %v, %s", vers, err)
	}

	keyV2 := objstore.DbKeyPrefixString(DataModelVersion2Prefix)
	_, err = objStore.Put(ctx, keyV2, string(out))
	if err != nil {
		return err
	}
	return nil
}
