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
	fmt "fmt"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/objstore"
	"github.com/opentracing/opentracing-go"
	context "golang.org/x/net/context"
)

var testDataKeyPrefix = "_testdatakey"

// Prototype for the upgrade function - takes an objectstore and stm to ensure
// automicity of each upgrade function
type VersionUpgradeFunc func(context.Context, objstore.KVStore, *AllApis, *UpgradeSupport) error

// Helper function to run a single upgrade function across all the elements of a KVStore
// fn will be called for each of the entries, and therefore it's up to the
// fn implementation to filter based on the prefix
func RunSingleUpgrade(ctx context.Context, objStore objstore.KVStore, allApis *AllApis, upgradeSupport *UpgradeSupport, fn VersionUpgradeFunc) error {
	err := fn(ctx, objStore, allApis, upgradeSupport)
	if err != nil {
		return fmt.Errorf("Could not upgrade objects store entries, err: %v\n", err)
	}
	return nil
}

// This function walks all upgrade functions from the fromVersion to current
// and upgrades the KVStore using those functions one-by-one
func UpgradeToLatest(fromVersion *VersionV2, objStore objstore.KVStore, allApis *AllApis, upgradeSupport *UpgradeSupport) error {
	verID := fromVersion.Number
	span := log.StartSpan(log.DebugLevelInfo, "upgrade")
	span.SetTag("fromVersion", fromVersion.Hash)
	span.SetTag("verID", verID)
	defer span.Finish()
	ctx := opentracing.ContextWithSpan(context.Background(), span)
	for _, upgradeFunc := range VersionHash_UpgradeFuncs {
		if upgradeFunc.Number <= fromVersion.Number {
			continue
		}
		name := upgradeFunc.FuncName
		fn := upgradeFunc.Func

		uspan := log.StartSpan(log.DebugLevelInfo, name, opentracing.ChildOf(span.Context()))
		uctx := log.ContextWithSpan(context.Background(), uspan)
		if fn != nil {
			// Call the upgrade with an appropriate callback
			if err := RunSingleUpgrade(uctx, objStore, allApis, upgradeSupport, fn); err != nil {
				uspan.Finish()
				return fmt.Errorf("Failed to run %s: %v\n",
					name, err)
			}
			log.SpanLog(uctx, log.DebugLevelUpgrade, "Upgrade complete", "upgradeFunc", name)
		}
		// Write out the new version
		v2 := VersionV2{
			Hash:   upgradeFunc.Hash,
			Number: upgradeFunc.Number,
		}
		err := writeVersionV2(uctx, objStore, &v2)
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
