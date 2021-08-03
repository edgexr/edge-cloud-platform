package vcd

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vmware/go-vcloud-director/v2/govcd"
	"github.com/vmware/go-vcloud-director/v2/types/v56"
)

// Test what instanciate does, should be the simple creation of a vapp from the template
// So we  use -vdc, -vapp and -tmpl args
func TestInstanciateTmpl(t *testing.T) {

	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")
	defer testVcdClient.Disconnect()

	if live {

		vdc, err := tv.GetVdc(ctx, testVcdClient)
		if err != nil {
			fmt.Printf("GetVdc err: %s\n", err.Error())
			return
		}
		fmt.Printf("TestInstancitate tmplName %s vappName %s\n", *tmplName, *vappName)
		tmpl, err := tv.FindTemplate(ctx, *tmplName, testVcdClient)
		require.Nil(t, err, "FindVappTemplate")

		tmplRef := &types.Reference{
			HREF: tmpl.VAppTemplate.HREF,
			ID:   tmpl.VAppTemplate.ID,
			Type: tmpl.VAppTemplate.Type,
			Name: tmpl.VAppTemplate.Name,
		}
		// create a minimal InstanctiateVAppTemplateParams
		netConfig := popNetConfig(t, ctx)
		netConnect := popNetConnect(t, ctx)

		IParams := &types.InstantiationParams{
			NetworkConfigSection:     netConfig,
			NetworkConnectionSection: netConnect,
		}
		tmplParams := &types.InstantiateVAppTemplateParams{

			Name:                *vappName,
			PowerOn:             false,
			Source:              tmplRef,
			InstantiationParams: IParams,
			// SourcedItem *SourcedCompositionItemParam see if we need this here, probably used in Compose/ReCompose not instanciate
			AllEULAsAccepted: true, // takeBoolPointer(true),
		}

		err = vdc.InstantiateVAppTemplate(tmplParams)
		if err != nil {
			fmt.Printf("InstantiateVApptemplate-E-error: %s\n", err.Error())
			return
		}
		vapp, err := vdc.GetVAppByName(*vappName, true)
		if err != nil {
			fmt.Printf("GetVappByName-E-%s\n", err.Error())
			return
		}
		status, err := vapp.GetStatus()
		fmt.Printf("VApp %s has status : %s\n", *vappName, status)
	} else {
		return
	}
}

func popNetConfig(t *testing.T, ctx context.Context) *types.NetworkConfigSection {

	// This is the guy with the IPScopes /Features
	// *Note SubInterface and DistributedInterface here, they are mutually exclusive
	// When both are nil, the internal (default) interface is  used.
	vdcnet, err := tv.GetExtNetwork(ctx, testVcdClient, tv.vmProperties.GetCloudletExternalNetwork())
	if err != nil {
		return nil
	}
	net := vdcnet.OrgVDCNetwork
	var ipscopes *types.IPScopes = vdcnet.OrgVDCNetwork.Configuration.IPScopes

	//	Ipscope := vdcnet.Configuration.IPScopes.IPScope[0]

	//	ipscopes = append(ipscopes, Ipscope)

	netConfig := &types.NetworkConfiguration{
		IPScopes: ipscopes,
		ParentNetwork: &types.Reference{
			HREF: net.HREF,
			ID:   net.ID,
			Type: net.Type,
			Name: net.Name,
		},
	}
	var vappNetConfigs []types.VAppNetworkConfiguration

	vappNetConfig := types.VAppNetworkConfiguration{
		// create unique name for our new Vapp network
		NetworkName:   "vapp-" + net.Name + "-network",
		Configuration: netConfig, // *types.NetworkConfiguration
	}
	vappNetConfigs = append(vappNetConfigs, vappNetConfig)
	config := &types.NetworkConfigSection{

		NetworkConfig: vappNetConfigs,
	}

	networkNames := config.NetworkNames()

	for _, name := range networkNames {
		fmt.Printf("popNetConfig next network %s\n", name)
	}
	return config
}

func popNetConnect(t *testing.T, ctx context.Context) *types.NetworkConnectionSection {
	vdcnet, err := tv.GetExtNetwork(ctx, testVcdClient, tv.vmProperties.GetCloudletExternalNetwork())
	if err != nil {
		return nil
	}
	net := vdcnet.OrgVDCNetwork
	//		Network: "vapp-"+vdcnet.Name+"-network", // Name of the network to which this NIC is connected

	var netConnections []*types.NetworkConnection
	netConnection := &types.NetworkConnection{
		Network:                "vapp-" + net.Name + "-network",
		NeedsCustomization:     false,
		NetworkConnectionIndex: 0,
		//		IPAddress:
		//	ExternalIPAddress:
		IsConnected:             true,
		MACAddress:              "00.00.00.00.00",
		IPAddressAllocationMode: types.IPAllocationModeDHCP,
		NetworkAdapterType:      "E1000", // VMXNET3
	}
	netConnections = append(netConnections, netConnection)
	connects := &types.NetworkConnectionSection{

		PrimaryNetworkConnectionIndex: 0,
		NetworkConnection:             netConnections,
	}
	return connects
}

/*
   xxxxxx hey, try this, note 'deployed' and "not deployed" templates... scratch that itch...

    Sorta smells like our not found locally template is just a "not deployed" template? how to deploy the darn template?

// QueryVappVmTemplate Finds VM template using catalog name, vApp template name, VN name in template. Returns types.QueryResultVMRecordType
func (vdc *Vdc) QueryVappVmTemplate(catalogName, vappTemplateName, vmNameInTemplate string) (*types.QueryResultVMRecordType, error) {

	queryType := "vm"
	if vdc.client.IsSysAdmin {
		queryType = "adminVM"
	}

	// this allows to query deployed and not deployed templates
	results, err := vdc.QueryWithNotEncodedParams(nil, map[string]string{"type": queryType,
		"filter": "catalogName==" + url.QueryEscape(catalogName) + ";containerName==" + url.QueryEscape(vappTemplateName) + ";name==" + url.QueryEscape(vmNameInTemplate) +
*/

func populateInstantiationParams() *types.InstantiationParams {

	custSec := &types.CustomizationSection{
		GoldMaster:             false,
		CustomizeOnInstantiate: false,
	}

	//GuestCustomizationSection contains settings for VM customization like admin password, SID
	// changes, domain join configuration, etc
	guestCustSec := &types.GuestCustomizationSection{}

	// empty will inherit defaults of our Org, we can only reduce the times
	leaseSettingSec := &types.LeaseSettingsSection{}

	vappNetConfigSec := &types.NetworkConfigSection{}

	netConnectSec := &types.NetworkConnectionSection{}
	prodSec := &types.ProductSection{}
	instParams := &types.InstantiationParams{
		CustomizationSection:      custSec,
		GuestCustomizationSection: guestCustSec,
		LeaseSettingsSection:      leaseSettingSec,
		NetworkConfigSection:      vappNetConfigSec,
		NetworkConnectionSection:  netConnectSec,
		ProductSection:            prodSec,
	}
	return instParams
}

// create and return instantitation params, given a sourced itme, which can itself be
// vApp, VappTemplate, or a Vm.
//
func populateVAppTmplInstatiationParams(t *testing.T, ctx context.Context) *types.InstantiateVAppTemplateParams {

	tmplParams := &types.InstantiateVAppTemplateParams{}
	return tmplParams

}

// Delete the name VAppTemplate from the catalog
// Anything else needs to be done?
// catalogItem.Delete()
// So must frist get the catitem for this templ name.
func testDestroyVAppTmpl(t *testing.T, ctx context.Context, tmplname string) error {
	cat, err := tv.GetCatalog(ctx, tv.GetCatalogName(), testVcdClient)
	if err != nil {
		return err
	}
	catitem, err := cat.GetCatalogItemByName(tmplname, true)
	if err != nil {
		fmt.Printf("testDestroyVAppTmpl-E-error finding %s item in cat: %s\n", tmplname, cat.Catalog.Name)
	}
	err = catitem.Delete()
	if err != nil {
		fmt.Printf("Error catitem.Delete() on %s from %s as: %s \n", tmplname, cat.Catalog.Name, err.Error())
		return err
	}
	return nil
}

// test for bug handle removing networks along with VM if the vm removed is last one using network.
func testRemoveVmFromVApp(t *testing.T, ctx context.Context, vapp govcd.VApp, vmName string) (*govcd.VApp, error) {

	vm, err := vapp.GetVMByName(vmName, false)
	if err != nil {
		fmt.Printf("Error retriving vm name %s from vapp %s err: %s\n", vmName, vapp.VApp.Name, err.Error())
		return nil, err
	}
	err = vapp.RemoveVM(*vm)
	if err != nil {
		fmt.Printf("error removing vm %s\n", err.Error())
	}
	return &vapp, err
	// check if bug #252 is present: https://github.com/vmware/go-vcloud-director/issues/252
}

func testDestroyVapp(t *testing.T, ctx context.Context, vappName string) error {

	return nil
}

func dumpVAppTemplateChildren(tv *VcdPlatform, ctx context.Context, tc *types.VAppTemplateChildren, indent int) {
	fill := strings.Repeat("  ", indent)
	if tc == nil {
		fmt.Printf("%s\n", fill+"None found")
		return
	}

	for _, vmt := range tc.VM {
		vat := govcd.VAppTemplate{
			VAppTemplate: vmt,
		}
		dumpVAppTemplate(tv, ctx, &vat, indent+1)
	}
}

func dumpVAppTemplate(tv *VcdPlatform, ctx context.Context, vt *govcd.VAppTemplate, indent int) {

	fill := strings.Repeat("  ", indent)
	if vt == nil {
		fmt.Printf("%s\n", fill+"None found")
		return
	}
	fmt.Printf("%s %s\n", fill+"Name", vt.VAppTemplate.Name)
	fmt.Printf("%s %s\n", fill+"HREF", vt.VAppTemplate.HREF)
	fmt.Printf("%s %s\n", fill+"Type", vt.VAppTemplate.Type)
	vdc, err := tv.GetVdc(ctx, testVcdClient)
	if err != nil {
		fmt.Printf("GetVdc failed: %s\n", err.Error())
		return
	}
	if vt.VAppTemplate.Type == "application/vnd.vmware.vcloud.vm+xml" {

		// we can fetch it from vCD or from our local cache if we've done things right
		vm, err := tv.FindVMByName(ctx, vt.VAppTemplate.Name, testVcdClient, vdc)
		if err != nil {
			fmt.Printf("Failed to find vm %s locally\n", vt.VAppTemplate.Name)
		} else {
			fmt.Printf("vm: %+v\n", vm)
		}

	}
	fmt.Printf("%s %s\n", fill+"ID", vt.VAppTemplate.ID)
	fmt.Printf("%s %s\n", fill+"Name", vt.VAppTemplate.OperationKey)

	fmt.Printf("%s %d\n", fill+"Status", vt.VAppTemplate.Status)

	fmt.Printf("%s %s\n", fill+"OvfDescriptorUploaded", vt.VAppTemplate.OvfDescriptorUploaded)

	fmt.Printf("%s %t\n", fill+"GoldMaster", vt.VAppTemplate.GoldMaster)
	// Link
	fmt.Printf("%s %s\n", fill+"Description", vt.VAppTemplate.Description)
	fmt.Printf("%s %s\n", fill+"ID", vt.VAppTemplate.ID)
	// Tasks

	fmt.Printf("%s\n", fill+"Files:")
	//vu.DumpFilesList(vt.VAppTemplate.Files, indent+1)
	fmt.Printf("%s\n", fill+"Owner:")
	//vu.DumpOwner(vt.VAppTemplate.Owner, indent+1)

	fmt.Printf("%s\n", fill+"Tmpl Children:") // , vt.VAppTemplate.ID)
	// dumpVAppTemplateChildren(tv, ctx, vt.VAppTemplate.Children, indent+1)

	fmt.Printf("%s %s\n", fill+"VAppScopedLocalID", vt.VAppTemplate.VAppScopedLocalID)
	fmt.Printf("%s %s\n", fill+"DefaultStorageProfile", vt.VAppTemplate.DefaultStorageProfile)
	fmt.Printf("%s %s\n", fill+"Created         ", vt.VAppTemplate.DateCreated)

	fmt.Printf("%s\n", fill+"NetworkConfigSection:")
	//vu.DumpNetworkConfigSection(vt.VAppTemplate.NetworkConfigSection, indent+1)

	fmt.Printf("%s\n", fill+"NetworkConnectionSection:")
	//vu.DumpNetworkConnectionSection(vt.VAppTemplate.NetworkConnectionSection, indent+1)
	fmt.Printf("%s\n", fill+"LeaseSettingsSection:")
	//vu.DumpLeaseSettingSection(vt.VAppTemplate.LeaseSettingsSection, indent+1)

	fmt.Printf("%s\n", fill+"CustomizationSection:")
	//vu.DumpCustomizationSection(vt.VAppTemplate.CustomizationSection, indent+1)
}
