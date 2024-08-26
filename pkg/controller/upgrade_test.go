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
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/node"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/objstore"
	"github.com/edgexr/edge-cloud-platform/pkg/process"
	"github.com/edgexr/edge-cloud-platform/pkg/regiondata"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
	"github.com/edgexr/edge-cloud-platform/test/testutil"
	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml" // used to unmarshal data into map[string]interface{} instead of map[interface{}]interface{} for JSON marshal compatibility
)

var upgradeTestFileLocation = "./upgrade_testfiles"
var upgradeTestFilePreSuffix = "_pre.etcd"
var upgradeTestFilePostSuffix = "_post.etcd"
var upgradeVaultTestFilePreSuffix = "_pre.vault"
var upgradeVaultTestFilePostSuffix = "_post.vault"
var upgradeVaultTestFileExpectedSuffix = "_expected.vault"

// Walk testutils data and populate objStore
func buildDbFromTestData(objStore objstore.KVStore, funcName string) error {
	var key, val string
	ctx := context.Background()

	filename := upgradeTestFileLocation + "/" + funcName + upgradeTestFilePreSuffix
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("Unable to find preupgrade testdata file at %s", filename)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for {
		// double for loop to skip empty lines
		for {
			if !scanner.Scan() {
				return nil
			}
			key = scanner.Text()
			if key != "" {
				break
			}
		}
		for {
			if !scanner.Scan() {
				return fmt.Errorf("Improper formatted preupgrade .etcd file - Unmatched key without a value.")
			}
			val = scanner.Text()
			if val != "" {
				break
			}
		}
		if _, err := objStore.Put(ctx, key, val); err != nil {
			return err
		}
	}
}

// walk testutils data and see if the entries exist in the objstore
func compareDbToExpected(objStore objstore.KVStore, funcName string) error {
	var dbObjCount, fileObjCount int

	var key, val string

	filename := upgradeTestFileLocation + "/" + funcName + upgradeTestFilePostSuffix
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("Unable to find postupgrade testdata file at %s", filename)
	}
	defer file.Close()

	fileExpected, err := os.Create(upgradeTestFileLocation + "/" + funcName + "_expected.etcd")
	if err != nil {
		return err
	}
	defer fileExpected.Close()
	type kv struct {
		key string
		val string
	}
	var compareErr error
	scanner := bufio.NewScanner(file)
	for {
		if !scanner.Scan() {
			break
		}
		key = scanner.Text()
		if !scanner.Scan() {
			return fmt.Errorf("Improper formatted postupgrade .etcd file - Unmatched key, without a value.")
		}
		val = scanner.Text()
		dbVal, _, _, err := objStore.Get(key)
		if err != nil {
			return fmt.Errorf("Unable to get value for key[%s], %v", key, err)
		}
		// data may be in json format or non-json string
		compareDone, err := compareJson(funcName, key, val, string(dbVal))
		if !compareDone {
			err = compareString(funcName, key, val, string(dbVal))
		}
		if err != nil && compareErr == nil {
			// continue writing to expected file
			compareErr = err
		}
		fileObjCount++
	}
	kvs := []kv{}
	err = objStore.List("", func(key, val []byte, rev, modRev int64) error {
		kvs = append(kvs, kv{string(key), string(val)})
		return nil
	})
	sort.Slice(kvs, func(i, j int) bool {
		return kvs[i].key < kvs[j].key
	})
	for _, obj := range kvs {
		fileExpected.WriteString(obj.key + "\n")
		fileExpected.WriteString(obj.val + "\n")
		dbObjCount++
	}
	if compareErr != nil {
		return compareErr
	}
	if err != nil {
		return err
	}
	if fileObjCount != dbObjCount {
		return fmt.Errorf("Number of objects in the etcd db[%d] doesn't match the number of expected objects[%d]\n",
			dbObjCount, fileObjCount)
	}
	return nil
}

func compareJson(funcName, key, expected, actual string) (bool, error) {
	expectedMap := make(map[string]interface{})
	actualMap := make(map[string]interface{})
	err := json.Unmarshal([]byte(expected), &expectedMap)
	if err != nil {
		return false, fmt.Errorf("Unmarshal failed, %v, %s\n", err, expected)
	}
	err = json.Unmarshal([]byte(actual), &actualMap)
	if err != nil {
		return false, fmt.Errorf("Unmarshal failed, %v, %s\n", err, actual)
	}
	randomValKeys := []string{"obj_id"}
	normalizeRandomFields(expectedMap, randomValKeys...)
	normalizeRandomFields(actualMap, randomValKeys...)
	if !cmp.Equal(expectedMap, actualMap) {
		fmt.Printf("[%s] comparsion fail for key: %s\n", funcName, key)
		fmt.Printf("expected vs actual:\n")
		fmt.Printf(cmp.Diff(expectedMap, actualMap))
		return true, fmt.Errorf("Values don't match for the key, upgradeFunc: %s", funcName)
	}
	return true, nil
}

func compareString(funcName, key, expected, actual string) error {
	if expected != actual {
		fmt.Printf("[%s] values don't match for the key: %s\n", funcName, key)
		fmt.Printf("[%s] expected: \n%s\n", funcName, expected)
		fmt.Printf("[%s] actual: \n%s\n", funcName, actual)
		return fmt.Errorf("Values don't match for the key, upgradeFunc: %s", funcName)
	}
	return nil
}

// comparison fails for fields with random values (UUIDs, etc)
func normalizeRandomFields(m map[string]interface{}, keys ...string) {
	for _, key := range keys {
		val, ok := m[key]
		if !ok {
			continue
		}
		switch v := val.(type) {
		case string:
			if len(v) > 0 {
				m[key] = "normalizedStringVal"
			}
		}
	}
}

type VaultUpgradeData struct {
	KVs []VaultUpgradeKV
}

type VaultUpgradeKV struct {
	Path string
	Data map[string]interface{}
}

func loadVaultTestData(ctx context.Context, vaultConfig *vault.Config, funcName string) (*VaultUpgradeData, bool, error) {
	filename := getTestFileName(funcName, upgradeVaultTestFilePreSuffix)
	fileData, err := os.ReadFile(filename)
	if err != nil && os.IsNotExist(err) {
		// skip vault data for this test
		return nil, false, nil
	} else if err != nil {
		return nil, false, err
	}
	data := VaultUpgradeData{}
	err = yaml.Unmarshal(fileData, &data)
	if err != nil {
		return nil, false, fmt.Errorf("Failed to unmarshal %s: %s", filename, err)
	}
	for _, kv := range data.KVs {
		err = vault.PutData(vaultConfig, kv.Path, kv.Data)
		if err != nil {
			return nil, false, fmt.Errorf("Failed to write data to vault path %s: %v", kv.Path, err)
		}
	}
	return &data, true, nil
}

func compareVaultData(ctx context.Context, vaultConfig *vault.Config, funcName, region string, preData *VaultUpgradeData, cleanup bool) error {
	postFile := getTestFileName(funcName, upgradeVaultTestFilePostSuffix)
	postFileData, err := os.ReadFile(postFile)
	if err != nil {
		return err
	}
	postData := VaultUpgradeData{}
	err = yaml.Unmarshal(postFileData, &postData)
	if err != nil {
		return fmt.Errorf("Failed to unmarshal %s: %s", postFile, err)
	}

	expData := VaultUpgradeData{}
	failures := 0
	for _, kv := range postData.KVs {
		kvData := map[string]interface{}{}
		err = vault.GetData(vaultConfig, kv.Path, 0, &kvData)
		if err != nil {
			if vault.IsErrNoSecretsAtPath(err) {
				fmt.Printf("[%s] Vault comparison fail for path: %s\n", funcName, kv.Path)
				fmt.Printf("  Secret not found\n")
				failures++
				continue
			}
			return fmt.Errorf("Failed to read data from Vault path %s: %s", kv.Path, err)
		}
		diff := cmp.Diff(kv.Data, kvData)
		if diff != "" {
			fmt.Printf("[%s] Vault comparison fail for path: %s\n", funcName, kv.Path)
			fmt.Println(diff)
			failures++
		}
		expData.KVs = append(expData.KVs, VaultUpgradeKV{
			Path: kv.Path,
			Data: kvData,
		})
	}
	if failures == 0 {
		// actual matches expected
		if cleanup {
			for _, kv := range expData.KVs {
				vault.DeleteData(vaultConfig, kv.Path)
			}
			for _, kv := range preData.KVs {
				vault.DeleteData(vaultConfig, kv.Path)
			}
		}
		return nil
	}
	// write out what was found
	expFileName := getTestFileName(funcName, upgradeVaultTestFileExpectedSuffix)
	expOut, err := yaml.Marshal(expData)
	if err != nil {
		return fmt.Errorf("Failed to marshal actual vault data, %s", err)
	}
	err = os.WriteFile(expFileName, expOut, 0644)
	if err != nil {
		return fmt.Errorf("Failed to write file %s: %s", expFileName, err)
	}
	return fmt.Errorf("Vault data comparison failure for %s", funcName)
}

func getTestFileName(funcName, suffix string) string {
	return upgradeTestFileLocation + "/" + funcName + suffix
}

// Run each upgrade function after populating dummy etcd with test data.
// Verify that the resulting content in etcd matches expected
func TestAllUpgradeFuncs(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelUpgrade | log.DebugLevelApi)
	objStore := regiondata.InMemoryStore{}
	log.InitTracer(nil)
	defer log.FinishTracer()

	// There are timestamp fields which are stored in RFC3339 format.
	// Hence, fix a timezone for consistent comparison
	time.Local = time.UTC

	cplookup := &node.CloudletPoolCache{}
	cplookup.Init()
	nodeMgr.CloudletPoolLookup = cplookup
	cloudletLookup := &node.CloudletCache{}
	cloudletLookup.Init()
	nodeMgr.CloudletLookup = cloudletLookup
	nodeMgr.DeploymentName = "edgecloud"

	// this is needed for AddSetupSpecificAppDNSRootForCloudlets,
	// because the appinst_api_test sets it to something else.
	*appDNSRoot = "appdnsroot.net"

	sync := regiondata.InitSync(&objStore)
	apis := NewAllApis(sync)

	// Start in-memory Vault for upgrade funcs that upgrade Vault data
	region := "local"
	vp := process.Vault{
		Common: process.Common{
			Name: "vault",
		},
		ListenAddr: "TestAllUpgradeFuncs",
		PKIDomain:  "edgecloud.net",
		Regions:    region, // comma separated list
	}
	_, vroles, vaultCleanup := testutil.NewVaultTestCluster(t, &vp)
	defer vaultCleanup()
	vaultConfig := vault.NewAppRoleConfig(vp.ListenAddr, vroles.RegionRoles[region].CtrlRoleID, vroles.RegionRoles[region].CtrlSecretID)
	sup := &UpgradeSupport{
		region:      region,
		vaultConfig: vaultConfig,
	}

	ctx := log.StartTestSpan(context.Background())
	for ii, fn := range VersionHash_UpgradeFuncs {
		if fn == nil {
			continue
		}
		objStore.Start()
		funcName := VersionHash_UpgradeFuncNames[ii]
		err := buildDbFromTestData(&objStore, funcName)
		require.Nil(t, err, "Unable to build db from testData")
		vaultPreData, vaultDataLoaded, err := loadVaultTestData(ctx, vaultConfig, funcName)
		require.Nil(t, err, "Load Vault test data")
		err = RunSingleUpgrade(ctx, &objStore, apis, sup, fn, ii)
		require.Nil(t, err, "Upgrade failed")
		err = compareDbToExpected(&objStore, funcName)
		require.Nil(t, err, "Unexpected result from upgrade function(%s)", funcName)
		if vaultDataLoaded {
			cleanupVault := false
			err = compareVaultData(ctx, vaultConfig, funcName, region, vaultPreData, cleanupVault)
			require.Nil(t, err)
		}
		// Run the upgrade again to make sure it's idempotent
		err = RunSingleUpgrade(ctx, &objStore, apis, sup, fn, ii)
		require.Nil(t, err, "Upgrade second run failed")
		err = compareDbToExpected(&objStore, funcName)
		require.Nil(t, err, "Unexpected result from upgrade function second run (idempotency check) (%s)", funcName)
		if vaultDataLoaded {
			cleanupVault := true
			err = compareVaultData(ctx, vaultConfig, funcName, region, vaultPreData, cleanupVault)
			require.Nil(t, err)
		}
		// Stop it, so it's re-created again
		objStore.Stop()
	}
}

func TestGetDataVersion(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelEtcd | log.DebugLevelApi | log.DebugLevelNotify)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	kvstore := &regiondata.InMemoryStore{}
	kvstore.Start()

	// inject db version and check that it can be read back
	keyV2 := objstore.DbKeyPrefixString("VersionV2")
	vers := &edgeproto.DataModelVersion{
		Hash: "myhash",
		ID:   234,
	}
	out, err := json.Marshal(vers)
	require.Nil(t, err)
	_, err = kvstore.Put(ctx, keyV2, string(out))
	require.Nil(t, err)
	outVers, err := getDataVersion(ctx, kvstore)
	require.Nil(t, err)
	require.Equal(t, vers, outVers)
	_, err = kvstore.Delete(ctx, keyV2)
	require.Nil(t, err)

	// write an older format version
	key := objstore.DbKeyPrefixString("Version")
	_, err = kvstore.Put(ctx, key, vers.Hash)
	require.Nil(t, err)
	outVers, err = getDataVersion(ctx, kvstore)
	require.Nil(t, err)
	require.Equal(t, vers.Hash, outVers.Hash)
	require.Equal(t, int32(0), outVers.ID)
	_, err = kvstore.Delete(ctx, key)
	require.Nil(t, err)

	// check no version
	_, err = kvstore.Delete(ctx, keyV2)
	require.Nil(t, err)
	outVers, err = getDataVersion(ctx, kvstore)
	curVers := edgeproto.GetDataModelVersion()
	require.Nil(t, err)
	require.Equal(t, curVers, outVers)
	// check that current version was written to db
	out, _, _, err = kvstore.Get(keyV2)
	require.Nil(t, err)
	writtenVers := &edgeproto.DataModelVersion{}
	err = json.Unmarshal([]byte(out), writtenVers)
	require.Nil(t, err)
	require.Equal(t, curVers, writtenVers)
}
