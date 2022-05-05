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

package vcd

import (
	"context"
	"fmt"
	"time"

	"github.com/edgexr/edge-cloud/log"
	"github.com/vmware/go-vcloud-director/v2/govcd"
)

// catalog releated functionality

const uploadChunkSize = 10 * 1024 * 1024 // 10 MB
func (v *VcdPlatform) GetCatalog(ctx context.Context, catName string, vcdClient *govcd.VCDClient) (*govcd.Catalog, error) {

	org, err := v.GetOrg(ctx, vcdClient)
	if err != nil {
		return nil, err
	}
	catName = v.GetCatalogName()
	if catName == "" {
		return nil, fmt.Errorf("MEX_CATALOG name not found")
	}
	cat, err := org.GetCatalogByName(catName, true)
	if err != nil {
		return nil, err
	}
	return cat, nil
}

// UploadOvaFile uploads either an OVF or OVA
func (v *VcdPlatform) UploadOvaFile(ctx context.Context, fileName, itemName, descr string, vcdClient *govcd.VCDClient) error {
	log.SpanLog(ctx, log.DebugLevelInfra, "UploadOvaFile", "fileName", fileName, "itemName", itemName)
	cat, err := v.GetCatalog(ctx, v.GetCatalogName(), vcdClient)
	if err != nil {
		return err
	}
	_, err = cat.GetCatalogItemByName(itemName, true)
	if err == nil {
		log.SpanLog(ctx, log.DebugLevelInfra, "OVA already in catalog", "itemName", itemName)
		return nil
	}
	elapse_start := time.Now()
	// 8*1024 MB chunk size for the download.
	task, err := cat.UploadOvf(fileName, itemName, descr, uploadChunkSize)
	if err != nil {
		return fmt.Errorf("UploadOvf to catalog start failed: %v", err)
	}
	err = task.WaitTaskCompletion()
	elapsed := time.Since(elapse_start).String()
	log.SpanLog(ctx, log.DebugLevelInfra, "OVA uploaded ", "itemName", itemName, "elapsed time", elapsed)
	if err != nil {
		return fmt.Errorf("UploadOvf to catalog task failed: %v", err)
	}
	return nil
}

func (v *VcdPlatform) DeleteTemplate(ctx context.Context, name string, vcdClient *govcd.VCDClient) error {
	cat, err := v.GetCatalog(ctx, v.GetCatalogName(), vcdClient)
	if err != nil {
		return err
	}
	cItem, err := cat.GetCatalogItemByName(name, false)
	if err != nil {
		return err
	}
	return cItem.Delete()
}
