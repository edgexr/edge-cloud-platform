package vcd

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vmware/go-vcloud-director/v2/govcd"
	"github.com/vmware/go-vcloud-director/v2/types/v56"
)

func TestCats(t *testing.T) {
	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")
	if live {
		fmt.Printf("TestCats-I-tv init done\n")
		cat, err := tv.GetCatalog(ctx, tv.GetCatalogName())
		if err != nil {
			fmt.Printf("GetCatalog faled: %s\n", err.Error())
			return
		}
		govcd.ShowCatalog(*cat.Catalog)
	}
}

// -tmpl from PrimaryCat
func TestRMTmpl(t *testing.T) {
	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")

	if live {
		fmt.Printf("Test Remove template %s from cat", *tmplName)
		err := tv.DeleteTemplate(ctx, *tmplName)
		if err != nil {
			fmt.Printf("TestRMTmpl delete %s returned %s\n", *tmplName, err.Error())
		}
		return
	}
}

// uses -ova
// If you run this live, use --timeout 0 to disable the default panic after 10 mins
// since this test runs ~ upload complete in 17m20.262586965s
//
func TestUploadOva(t *testing.T) {
	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")
	if live {
		fmt.Printf("Live OVA  upload test\n")
		err = testOvaUpload(t, ctx)
		require.Nil(t, err, "testOVAUpload")
	} else {
		return
	}
}

// -live -href
func TestGetTmplByHref(t *testing.T) {

	live, _, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")
	if live {
		//		fmt.Printf("Get by href org: %s href %s\n",
	}
}

// Or we can access tmpls via our vcd items looking for
// "application/vnd.vmware.vcloud.vAppTemplate+xml"
// In general, many resource Items can be discovered this way
//
func TestGetTemplates(t *testing.T) {

	//	var tmpls []string

	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")
	if live {
		vdc, err := tv.GetVdc(ctx)
		if err != nil {
			fmt.Printf("GetVdc failed: %s\n", err.Error())
			return
		}
		fmt.Printf("TestGetTemplates\n")
		for _, res := range vdc.Vdc.ResourceEntities {
			for N, item := range res.ResourceEntity {
				if item.Type == "application/vnd.vmware.vcloud.vAppTemplate+xml" {
					fmt.Printf("%3d %-40s %s\n", N, item.Name, item.Type)
					//tmpls = append(tmpls, item.Name)

				}
				if item.Type == "application/vnd.vmware.vcloud.vm+xml" {
					fmt.Printf("VM found: %3d %-40s %s\n", N, item.Name, item.Type)
				}
			}
		}
		fmt.Println("")
	}
	return
}

// upload a local .vmdk to our catalog, actually, they prefer an entire .ova file
// uses -ova for what (local) file to upload
func testOvaUpload(t *testing.T, ctx context.Context) error {

	path := os.Getenv("HOME")
	fmt.Printf("Path: %s\n", path)

	url := path + "/vmware-lab/" + *ovaName

	//tname := *ovaName
	tname := "mobiledgex-v4.1.3-vcd"
	fmt.Printf("testMediaUpload-I-attempt uploading: %s naming it %s \n", url, tname)

	cat, err := tv.GetCatalog(ctx, tv.GetCatalogName())
	if err != nil {
		fmt.Printf("GetCatalog faled: %s\n", err.Error())
		return err
	}

	elapse_start := time.Now()
	task, err := cat.UploadOvf(url, tname, "test-import-ova-vcd", (1024 * 100))

	if err != nil {
		fmt.Printf("\nError from UploadOvf: %s\n", err.Error())
	}
	fmt.Printf("Task: %+v\n", task)
	err = task.WaitTaskCompletion()
	fmt.Printf("upload complete in %s\n", time.Since(elapse_start).String())
	return err
}

// Ok, we have a case where qa2-vdc has no vapptemplate as vdc.resources.
// It has a catalog item though that we obtain using

// try getting a list of catalog items, and then the one that is our template, fetch the template.

func TestCatItemTmpl(t *testing.T) {

	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")
	templateName := ""
	if live {
		catname := ""
		vdc, err := tv.GetVdc(ctx)
		if err != nil {
			fmt.Printf("GetVdc failed: %s\n", err.Error())
			return
		}
		cat, err := tv.GetCatalog(ctx, tv.GetCatalogName())
		if err != nil {
			fmt.Printf("GetCatalog faled: %s\n", err.Error())
			return
		}
		catname = cat.Catalog.Name

		fmt.Printf("TestCatItemTmpl addressing vdc %s catalog %s\n", vdc.Vdc.Name, catname)

		// all items in the cat. You can ask vdc.QueryCatalogItemsList for vdc  items I guess Or adminVdc.Query
		fmt.Printf("\n Using cat.QueryCatalogItemList\n")
		catItems, err := cat.QueryCatalogItemList()
		if err != nil {
			fmt.Printf("Error on query cat items list: %s\n", err.Error())
			return
		}
		for _, qr := range catItems {

			fmt.Printf("next QueryResult:\n\tEntName: %s\n\tEntType:%s\n\tiPublished: %t\n\tName: %s\n\tisVdcEnabled: %t\n\tisExpired: %t\n\tHREF: %s\n",
				qr.EntityName,
				qr.EntityType,
				qr.IsPublished,
				qr.Name, // catalog Item Name
				qr.IsVdcEnabled,
				qr.IsExpired,
				qr.HREF,
			)
			if qr.Name == *tmplName {
				templateName = qr.Name
			}

		}

		fmt.Printf("\n Using cat.QueryResultVappTemplateList\n")
		// QueryResultVappTemplateType
		qrvttList, err := cat.QueryVappTemplateList()
		if err != nil {
			fmt.Printf("Error from QueryVappTemplateList: %s\n", err.Error())
			return
		}
		for _, qr := range qrvttList {

			fmt.Printf("next QueryResult:\n\tHREF: %s\n\tType:%s\n\tisPublished: %t\n\tName: %s\n\tisEnabled: %t\n\tisExpired: %t\n\tisDeployed: %t\n\tVdcName:%s\n",
				qr.HREF,
				qr.Type,
				qr.IsPublished,
				qr.Name,
				qr.IsEnabled,
				qr.IsExpired,
				qr.IsDeployed,
				qr.VdcName,
			)

		}
		fmt.Printf("\n Using vdc.QueryResultVappTemplateList vdc: %s\n", vdc.Vdc.Name)
		qrvttList, err = vdc.QueryVappTemplateList()
		if err != nil {
			fmt.Printf("Error from QueryVappTemplateList: %s\n", err.Error())
			return
		}
		for _, qr := range qrvttList {

			fmt.Printf("next QueryResult:\n\tHREF: %s\n\tType:%s\n\tisPublished: %t\n\tName: %s\n\tisEnabled: %t\n\tisExpired: %t\n\tisDeployed: %t\n\tVdcName:%s\n",
				qr.HREF,
				qr.Type,
				qr.IsPublished,
				qr.Name,
				qr.IsEnabled,
				qr.IsExpired,
				qr.IsDeployed,
				qr.VdcName,
			)

		}
		// Ok, so interesting. The second query qr.VdcName seems to show what vdc
		// this template is available from.
		// The 3rd query using the vdc context, for example shows nothing for q2-lab
		// while the 2nd query show vdcName as qe-lab.
		//

		// Next, try and a single CatalogItem object pointing to this template, and
		// retrive it wih:

		fmt.Printf("Asking cat.FindCatalogItem(%s) \n", templateName)

		emptyItem := govcd.CatalogItem{}
		catItem, err := cat.FindCatalogItem(templateName)
		// Now, how to get this item type. catalog.go?
		if err != nil {
			fmt.Printf("FindCatalogItem for %s failed: %s\n", templateName, err.Error())
			return
		}
		if catItem == emptyItem { // empty!

			fmt.Printf("cat.FindCatalogItem didn't fail, but returned nil catItem!\n")

		} else {
			tmpl, err := catItem.GetVAppTemplate()
			if err != nil {
				fmt.Printf("GetVAppTemplate from catItem failed: %s vdc: %s\n", err.Error(), vdc.Vdc.Name)
				return
			}
			fmt.Printf("Have template, is this usable? template: %+v\n", tmpl)
			if tmpl.VAppTemplate.Children == nil {
				fmt.Printf("No it looks like this template has no children\n")
			} else {
				numChildren := len(tmpl.VAppTemplate.Children.VM)
				fmt.Printf("Yes it looks like this template has %d children\n", numChildren)
			}
			dumpVAppTemplate(&tv, ctx, &tmpl, 1)

		}
		fmt.Printf("Try QueryVapVmtemplate, needs catname %s  templateName %s and vmNameInTemplate %s\n",
			catname, *tmplName, *vmName)

		queryResultRec, err := vdc.QueryVappVmTemplate(catname, *tmplName, *vmName)
		if err != nil {
			fmt.Printf("QueryVappVmTemplate err: %s\n", err.Error())
			return
		}
		fmt.Printf("results:\n\tName: %s\n\tType: %s\n\tContainerName: %s\n\tVAppTemplate? %t\n\t Status: %s\n\tDeployed %t\n\tPublished: %t\n",
			queryResultRec.Name,
			queryResultRec.Type,
			queryResultRec.ContainerName,
			queryResultRec.VAppTemplate,
			queryResultRec.Status,
			queryResultRec.Deployed,
			queryResultRec.Published)

		stdTmp := tv.GetTemplateName()
		// now fetch the darn template, and compare contents
		// first look for it as a vdc.resource which if found we know works
		tmpl, err := tv.RetrieveTemplate(ctx) // this might not work now in TestMode

		if err != nil {
			fmt.Printf("Std tmpl %s not found in vdc: %s\n", stdTmp, vdc.Vdc.Name)

		} else {
			// Now try and get it by HREF
			//queryResultRec.HREF
			fmt.Printf("tmpl %s is a vdc resource good to go\n", tmpl.VAppTemplate.Name)
		}
	}
}

// -live -tmpl
func TestImportVMTmpl(t *testing.T) {

	//	var tmpls []string

	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")
	if live {
		fmt.Printf("TestImport tmpl %s\n", *tmplName)
		// we want to take a item (vcloud.vm+xml) and instanciate it to be a vdc.resource full vcloud.vapptemplate+xml type
		vdc, err := tv.GetVdc(ctx)
		if err != nil {
			fmt.Printf("GetVdc failed: %s\n", err.Error())
			return
		}
		cat, err := tv.GetCatalog(ctx, tv.GetCatalogName())
		if err != nil {
			fmt.Printf("GetCatalog faled: %s\n", err.Error())
			return
		}

		templateVmQueryRecs, err := tv.Client.Client.QueryVmList(types.VmQueryFilterOnlyTemplates)

		qr := &types.QueryResultVMRecordType{}
		for _, qr = range templateVmQueryRecs {

			if qr.Name == *tmplName {

				fmt.Printf("Discover found template:\n\tName%s\n\tType: %s\n\tHref:%s\n", qr.Name, qr.Type, qr.HREF)

				tmpl, err := cat.GetVappTemplateByHref(qr.HREF)

				fmt.Printf("template:\n\tName: %s\n\tType: %s\n\tID: %s\n\tHREF: %s\n\t OperKey: %s\n\tStatus: %d\n\tOvfDescriptorUpLoaded: %s\n",
					tmpl.VAppTemplate.Name,
					tmpl.VAppTemplate.Type,
					tmpl.VAppTemplate.ID,
					tmpl.VAppTemplate.HREF,
					tmpl.VAppTemplate.OperationKey,
					tmpl.VAppTemplate.Status,
					tmpl.VAppTemplate.OvfDescriptorUploaded)

				if err != nil {
					fmt.Printf("\n\nDISCOVER: Error GetVappTemplateByHref: tmpl: %s err: %s \n", qr.Name, err.Error())
					return
				}
				fmt.Printf("Have tmpl as: %+v\n", tmpl)
				err = tmpl.Refresh()
				if err != nil {
					fmt.Printf("error refreshing tmpl: %s\n", err.Error())
				}
				break
			}
		}
		vappTmplRef := &types.Reference{
			HREF: qr.HREF,
			ID:   qr.ID,
			Type: qr.Type,
			Name: qr.Name,
		}
		tmplParams := &types.InstantiateVAppTemplateParams{
			Name:             qr.Name,
			PowerOn:          false,
			Source:           vappTmplRef,
			AllEULAsAccepted: true,
		}

		err = vdc.InstantiateVAppTemplate(tmplParams)
		if err != nil {
			fmt.Printf("Instanciate error: %s\n", err.Error())
		}

		// now check our vdc.Resources, is it there now?
		for _, res := range vdc.Vdc.ResourceEntities {
			for N, item := range res.ResourceEntity {
				if item.Type == "application/vnd.vmware.vcloud.vAppTemplate+xml" {
					fmt.Printf("%3d %-40s %s\n", N, item.Name, item.Type)
					//tmpls = append(tmpls, item.Name)

				}
				if item.Type == "application/vnd.vmware.vcloud.vm+xml" {
					fmt.Printf("VM found: %3d %-40s %s\n", N, item.Name, item.Type)
				}
			}
		}
	}
}
