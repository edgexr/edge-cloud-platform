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

package ormutil

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud/cli"
)

// Convert a regionObj to a generic map[string]interface{}, including only
// data that is flagged by the enclosed protobuf object's Fields flag set.
func GetRegionObjStructMapForUpdate(regionObj ormapi.RegionObjWithFields) (*cli.MapData, error) {
	objData, err := cli.GetStructMap(regionObj.GetObj(), cli.WithStructMapFieldFlags(regionObj.GetObjFields()))
	if err != nil {
		return nil, err
	}
	// populate regionObj map
	regionObjMap := make(map[string]interface{})
	regionObjMap["Region"] = regionObj.GetRegion()
	regionObjMap[regionObj.GetObjName()] = objData.Data
	// replace object data with regionObj data
	objData.Data = regionObjMap
	return objData, nil
}

// For the given regionObj, set the enclosed protobuf object's field flags based
// on what data is included in the json data.
func SetRegionObjFields(jsonData []byte, regionObj ormapi.RegionObjWithFields) error {
	if fields := regionObj.GetObjFields(); fields != nil && len(fields) > 0 {
		// fields already set
		return nil
	}
	regionObjMap := make(map[string]interface{})
	err := json.Unmarshal(jsonData, &regionObjMap)
	if err != nil {
		return err
	}

	objName := regionObj.GetObjName()
	// json allows case insensitive matching so we can't just do
	// a map lookup. Fortunately there should only be 2 entries.
	// Note that json prefers case sensitive matching.
	var objMap map[string]interface{}
	var objMapCI map[string]interface{}
	for k, i := range regionObjMap {
		m, ok := i.(map[string]interface{})
		if !ok {
			continue
		}
		if k == objName {
			// exact match
			objMap = m
			break
		}
		if strings.ToLower(k) == strings.ToLower(objName) {
			// case insensitive match
			objMapCI = m
		}
	}
	if objMap == nil {
		objMap = objMapCI
	}
	if objMap == nil {
		return fmt.Errorf("Invalid object data for %s", regionObj.GetObjName())
	}

	// calculate fields from what is specified in objMap
	md := &cli.MapData{
		Namespace: cli.JsonNamespace,
		Data:      objMap,
	}
	fields := cli.GetSpecifiedFields(md, regionObj.GetObj())
	sort.Strings(fields)
	regionObj.SetObjFields(fields)
	return nil
}
