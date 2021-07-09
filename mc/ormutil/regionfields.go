package ormutil

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cli"
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
	objMap, ok := regionObjMap[regionObj.GetObjName()].(map[string]interface{})
	if !ok {
		return fmt.Errorf("Invalid object data for %s", regionObj.GetObjName())
	}
	// Json should be consistent with regionObj, but for unit-tests
	// we delete the fields from regionObj, while the json data still has them.
	// We don't want the Fields to be included as a flag in the new fields flags,
	// so delete them if they exist. This should only happen for unit-tests.
	delete(objMap, "fields")

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
