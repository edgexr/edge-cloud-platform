package vcd

import (
	"context"
	"fmt"
	"time"

	"github.com/mobiledgex/edge-cloud/log"
	"github.com/vmware/go-vcloud-director/v2/govcd"
)

// catalog releated functionality

const uploadChunkSize = 12 * 1024 // MB
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

// generic upload in cats_test
func (v *VcdPlatform) UploadOvaFile(ctx context.Context, tmplName string, vcdClient *govcd.VCDClient) error {

	baseurl := "" // ovaLocation
	tname := tmplName
	url := baseurl + "/tmplName" + "ova"

	log.SpanLog(ctx, log.DebugLevelInfra, "upload ova from", "URI", url, "tmpl", tname)
	cat, err := v.GetCatalog(ctx, v.GetCatalogName(), vcdClient)
	if err != nil {
		return err
	}
	elapse_start := time.Now()
	// 8*1024 MB chunk size for the download.
	task, err := cat.UploadOvf(url, tname, "mex ova base template", uploadChunkSize)
	if err != nil {
		return err
	}
	err = task.WaitTaskCompletion()
	elapsed := time.Since(elapse_start).String()
	log.SpanLog(ctx, log.DebugLevelInfra, "tmpl uploaded ", "template", tmplName, "elapsed time", elapsed)

	return err
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
