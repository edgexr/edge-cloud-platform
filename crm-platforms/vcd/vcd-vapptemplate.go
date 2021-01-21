package vcd

import (
	"context"
	"fmt"

	"github.com/mobiledgex/edge-cloud/log"
	"github.com/vmware/go-vcloud-director/v2/govcd"
)

// vapptemplate related operations

// Return requested vdc template
func (v *VcdPlatform) FindTemplate(ctx context.Context, tmplName string, vcdClient *govcd.VCDClient) (*govcd.VAppTemplate, error) {

	log.SpanLog(ctx, log.DebugLevelInfra, "Find template", "Name", tmplName)
	tmpls, err := v.GetAllVdcTemplates(ctx, vcdClient)
	if err != nil {
		return nil, err
	}

	for _, tmpl := range tmpls {
		if tmpl.VAppTemplate.Name == tmplName {
			log.SpanLog(ctx, log.DebugLevelInfra, "Found template", "Name", tmplName)
			return tmpl, nil
		}
	}

	return nil, fmt.Errorf("template %s not found", tmplName)
}

// Return all templates found as vdc resources from MEX_CATALOG
func (v *VcdPlatform) GetAllVdcTemplates(ctx context.Context, vcdClient *govcd.VCDClient) ([]*govcd.VAppTemplate, error) {

	var tmpls []*govcd.VAppTemplate
	org, err := v.GetOrg(ctx, vcdClient)
	if err != nil {
		return tmpls, err
	}
	vdc, err := v.GetVdc(ctx, vcdClient)
	if err != nil {
		return tmpls, err
	}
	// Get our catalog MEX_CATALOG
	catName := v.GetCatalogName()
	if catName == "" {
		return tmpls, fmt.Errorf("MEX_CATALOG name not found")
	}

	cat, err := org.GetCatalogByName(catName, true)
	if err != nil {
		return tmpls, err
	}

	for _, r := range vdc.Vdc.ResourceEntities {
		for _, res := range r.ResourceEntity {
			if res.Type == "application/vnd.vmware.vcloud.vAppTemplate+xml" {
				if v.Verbose {
					log.SpanLog(ctx, log.DebugLevelInfra, "Found Vdc resource template", "Name", res.Name, "from Catalog", catName)
				}
				tmpl, err := cat.GetVappTemplateByHref(res.HREF)
				if err != nil {
					continue
				} else {
					tmpls = append(tmpls, tmpl)
				}
			}
		}
	}
	return tmpls, nil
}
