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
	"os"
	"testing"

	"net/url"

	"github.com/edgexr/edge-cloud/log"
	"github.com/stretchr/testify/require"
	"github.com/vmware/go-vcloud-director/v2/govcd"
	"github.com/vmware/go-vcloud-director/v2/types/v56"
)

// This is our object we'll store nacent Vapps in ?
type MexVapp struct {
	Client *govcd.VCDClient
	Org    *govcd.Org
	Vdc    *govcd.Vdc
	Vapp   *govcd.VApp
	Config VcdConfigParams // Config
}

// based on the cloudlet's name, find the auth creds, (vault eventually, env for now)
// we're creating a clusterInst, get all the bits needed to createa a VApp that will be
// an example.
func TestDiscover(t *testing.T) {
	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")
	defer testVcdClient.Disconnect()
	if live {
		org, err := tv.GetOrg(ctx, testVcdClient)
		if err != nil {
			fmt.Printf("Error GetOrg: %s\n", err.Error())
			return
		}
		vcd, err := tv.GetVdc(ctx, testVcdClient)
		fmt.Printf("Org:\n\tName: %s\n\tid: %s\n\tVcd: %s\n\tHref: %s\n", org.Org.Name, org.Org.ID, vcd.Vdc.Name, tv.Creds.VcdApiUrl)
	} else {
		return
	}
}

// expects -vapp
func TestVCD(t *testing.T) {

	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")
	defer testVcdClient.Disconnect()

	if live {
		m_vapp := populateMexVappConfig(t, ctx, "mexcloudname")

		client, err := testOrgAuth(t, m_vapp.Config) // get config/login now have a VDC client
		if err != nil {
			fmt.Printf("TestVCD-E-testOrgAuth return error: %s\n", err.Error())
			return
		}
		org, err := testGetOrg(t, client, m_vapp.Config.Org)
		//	fmt.Printf("TestVCD-I-have org name: %s fullname: %s OpKey: %s Enabled: %t\n", org.Org.Name, org.Org.FullName, org.Org.OperationKey, org.Org.IsEnabled)

		vdc, err := testGetVdc(t, client, org, m_vapp.Config.VDC)
		cats, err := testGetCatalogs(t, client.Client, org)

		for i, catName := range cats {
			// need to get cat by name first
			cat, err := org.GetCatalogByName(catName, false)
			if err != nil {
				fmt.Printf("\nUnable to fetch %s from org %s\n", catName, org.Org.Name)
			}
			fmt.Printf("Org %s vdc: %s  catalog %d = %s has %d items\n", m_vapp.Config.Org, m_vapp.Config.VDC, i, catName, len(cat.Catalog.CatalogItems))

			for j, item := range cat.Catalog.CatalogItems {
				fmt.Printf("\n\titem %d: %+v\n", j, *item)

				for N, deepItem := range item.CatalogItem {

					fmt.Printf("%3d %-40s %s (ID: %s)\n", N, deepItem.Name, deepItem.Type, deepItem.ID)
					if deepItem.Type == "application/vnd.vmware.vcloud.media+xml" {
						fmt.Printf("\n cat %s has media named %s\n", cat.Catalog.Name, deepItem.Name)
					}
				}
			}

			// Find our media image
		}
		m_vapp.Org = org
		m_vapp.Vdc = &vdc

		//	fmt.Printf("vdc %s has VMQuota of %d  nicQuota : %d\n", vdc.Vdc.Name, vdc.Vdc.VMQuota, vdc.Vdc.NicQuota)
		// compute capacity of the vdc
		c_capacity := vdc.Vdc.ComputeCapacity
		fmt.Printf("Resources:\n")
		for num, caps := range c_capacity {
			// here we get CPU: CapacityWithUsage and Memory:CapacityWithUsage
			//		fmt.Printf("%d: CPU : %+v Mem: %+v\n", num, caps.CPU, caps.Memory)
			fmt.Printf("\t%d CPU: Units: %s Allocated %d Limit: %d Reserved: %d Used %d\n", num, caps.CPU.Units, caps.CPU.Allocated, caps.CPU.Limit, caps.CPU.Reserved, caps.CPU.Used)
			fmt.Printf("\t%d Memory: Units: %s Allocated %d Limit: %d Reserved: %d Used %d\n", num, caps.Memory.Units, caps.Memory.Allocated, caps.Memory.Limit, caps.Memory.Reserved, caps.Memory.Used)

		}
		fmt.Printf("\n")
		//res_ents := vdc.Vdc.ResourceEntities
		//for k, res := range res_ents {
		//		fmt.Printf("%d: res: %+v\n", k, res)
		//}

		netws := vdc.Vdc.AvailableNetworks

		for /*netcnt*/ _, net := range netws {
			// AvaliableNetworks is Network []*Reference
			//	fmt.Printf("%d networks from vdc.Vdc: %+v\n", netcnt, net)
			//fmt.Printf("%d net:\n", netcnt)
			for _ /*rcnt*/, ref := range net.Network {
				//fmt.Printf("\t%d ref.HREF: %s type: %s id: %s name %s\n", rcnt, ref.HREF, ref.Type, ref.ID, ref.Name)
				orgvcdnet, err := vdc.GetOrgVdcNetworkByName(ref.Name, false)
				if err != nil {
					fmt.Printf("GetOrgVdcNetworkByName-E-failed: %s\n\n", err.Error())
				}
				vdcnet := orgvcdnet.OrgVDCNetwork
				//	fmt.Printf("vdcnet: %+v\n\n", vdcnet)

				fmt.Printf("OrgVDCNetwork %s :\n", ref.Name)
				//vu.DumpOrgVDCNetwork(vdcnet, 1)
				fmt.Printf("vcdnet: %+v\n", vdcnet)
			}
		}

		// This doesn't seem to allow fetch/manipulation of the catalog object It's link is nil
		catalogs, err := testQueryCatalogList(t, org)
		if err != nil {
			fmt.Printf("testQueryCatalogList-E-%s\n", err.Error())
		}
		for _, cat := range catalogs {
			fmt.Printf("catalog %s of type %s  has %d vapp temlates and %d media with subtype: %s \n", cat.Name, cat.Type, cat.NumberOfVAppTemplates, cat.NumberOfMedia, cat.PublishSubscriptionType)
			// catalogs have a Link, so dump that guy
			fmt.Printf("%s link: %+v\n", cat.Name, cat.Link) // nil? Hm...

		}

		// get the .iso image from cat1 to put into our vapp
		fmt.Printf("TestVCD-I-cats: %+v\n", cats)
		_, err = testGetVAppByName(t, vdc, *vappName)
		require.Nil(t, err, "testGetVappByName")

		testGetAllVAppsForVdc(t, &vdc)
	} else {
		return
	}
}

func populateMexVappConfig(t *testing.T, ctx context.Context, cloudlet string) MexVapp {
	log.SpanLog(ctx, log.DebugLevelInfra, "cloudlet", cloudlet)
	m_vapp := MexVapp{}

	m_vapp.Config = VcdConfigParams{
		User:      os.Getenv("VCD_USER"),
		Password:  os.Getenv("VCD_PASSWD"),
		Org:       os.Getenv("VCD_ORG"),
		VcdApiUrl: fmt.Sprintf("https://%s/api", os.Getenv("VCD_IP")),
		VDC:       os.Getenv("VCD_NAME"),
		Insecure:  true,
	}
	require.NotEqual(t, m_vapp.Config.User, "", "Missing $VDC_USER env var")
	require.NotEqual(t, m_vapp.Config.User, "", "Missing $VDC_PASSWD env var")
	require.NotEqual(t, m_vapp.Config.User, "", "Missing $VDC_ORG env var")
	require.NotEqual(t, m_vapp.Config.User, "", "Missing $VDC_IP env var")
	require.NotEqual(t, m_vapp.Config.User, "", "Missing $VDC_Insecure  env var")

	return m_vapp
}

// Get the org by name
func testGetOrg(t *testing.T, cli *govcd.VCDClient, orgName string) (org *govcd.Org, err error) {

	//org, err := cli.GetOrgByName(m_vapp.config.Org)
	o, e := cli.GetOrgByName(orgName)
	if e != nil {
		fmt.Printf("GetOrgByName-E-%s\n", err.Error())
		return o, e
	}
	require.Nil(t, e, "GetOrgByName")
	fmt.Printf("GetOrgByName returns org org.Org.HREF: %s\n", o.Org.HREF)

	return o, nil

}

// Get vdcs available in this org, manual
func testGetAllVAppsForVdc(t *testing.T, vdc *govcd.Vdc) {
	for _, r := range vdc.Vdc.ResourceEntities {
		for _, res := range r.ResourceEntity {
			if res.Type == VappResourceXmlType {
				vapp, err := vdc.GetVAppByName(res.Name, true)
				if err != nil {
					fmt.Printf("\n Error GetVAppbyName for %s err: %s\n", res.Name, err.Error())
					// spanlog
				} else {
					fmt.Printf("\nGetVdcVAppbyName returns: %s\n", res.Name)
					fmt.Printf("vapp: %+v\n", vapp)
				}
			}
		}
	}

}

// Get the vdc of the org
func testGetVdc(t *testing.T, cli *govcd.VCDClient, org *govcd.Org, vdcName string) (govcd.Vdc, error) {

	vdc, err := org.GetVDCByName(vdcName, false)
	require.Nil(t, err, "GetVDCByName")

	fmt.Printf("vdc.Vdc   HRef: %s type: %s allocation Model: %s\n", vdc.Vdc.HREF, vdc.Vdc.Type, vdc.Vdc.AllocationModel)
	return *vdc, err
}

func testGetCatalogs(t *testing.T, cli govcd.Client, org *govcd.Org) (cats []string, err error) {
	// current cli unused here...
	var catalogs []string
	//	catalogName := ""
	for N, item := range org.Org.Link {
		fmt.Printf("%3d %-40s %s\n", N, item.Name, item.Type)
		// Retrieve the first catalog name for further usage
		// what interesting item.Types are useful?
		if item.Type == "application/vnd.vmware.vcloud.catalog+xml" { // && catalogName == "" {
			catalogs = append(catalogs, item.Name)
			//catalogName = item.Name
		}
	}
	return catalogs, nil
}

// Org offers a QueryCatalogList returning a []*types.CattalogRecord
// rather than running org.Org.Link list, getting the name and lookup by name.
func testQueryCatalogList(t *testing.T, org *govcd.Org) (cats []*types.CatalogRecord, err error) {

	return org.QueryCatalogList()
}

func testGetOrgNetworks(t *testing.T, org *govcd.Org) (nets []string, err error) {

	var catalogs []string
	for _, item := range org.Org.Link {
		// Retrieve the first catalog name for further usage
		// what interesting item.Types are useful?
		if item.Type == "application/vnd.vmware.vcloud.orgNetwork+xml" {
			catalogs = append(catalogs, item.Name)
			//catalogName = item.Name
		}
	}
	return catalogs, nil

}

func testGetOrgTemplates(t *testing.T, org *govcd.Org) (tmps []string, err error) {

	var templates []string
	for _, item := range org.Org.Link {
		if item.Type == "application/vnd.vmware.vcloud.vdcTemplates+xml" {
			templates = append(templates, item.Name)
		}
	}
	return templates, nil

}

func testCreateVAppTemplate(t *testing.T, cli govcd.Client) {

	return
}

func testOrgAuth(t *testing.T, config VcdConfigParams) (*govcd.VCDClient, error) {

	// for this test, we require
	// env vars $VCD_USER, VCD_PASSWD, VCD_ORG, VCD_HREF VCD_NAME VCD_SECURE (T/F)

	u, err := url.ParseRequestURI(config.VcdApiUrl)
	require.Nil(t, err, "ParseRequestURI")
	vcdClient := govcd.NewVCDClient(*u, config.Insecure)
	resp, err := vcdClient.GetAuthResponse(config.User, config.Password, config.Org)
	require.Nil(t, err, "GetAuthResponse")
	fmt.Printf("Token: %s\n", resp.Header[govcd.AuthorizationHeader])
	return vcdClient, nil
}

// GetExternal returns  "functionality requires system administrator privileges"
func testGetIPScopes(t *testing.T, vcdClient *govcd.VCDClient, netid string) (err error) {

	externalNetwork, err := vcdClient.GetExternalNetworkByNameOrId(netid)
	if err != nil {
		fmt.Printf("GetExternalNetworkByNameOrId returns: %s\n", err.Error())
		return nil // "", fmt.Errorf("error fetching external network details %s", err)
	}
	fmt.Printf("testGetIPScopes-I-external network: %+v\n", externalNetwork)
	return nil
}

func testGetVAppByName(t *testing.T, vdc govcd.Vdc, vappName string) (*govcd.VApp, error) {

	vapp, err := vdc.GetVAppByName(vappName, false)
	if err != nil {
		return nil, fmt.Errorf("error finding vApp: %s and err: %s", vappName, err)

	}
	return vapp, nil
}
