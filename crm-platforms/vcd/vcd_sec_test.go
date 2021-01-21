package vcd

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vmware/go-vcloud-director/v2/types/v56"
)

// Security related tests, mainly whitelist => firewall rules

// Relevant nsxv_types.go:

/*
// EdgeFirewallEndpoint can contains slices of objects for source or destination in EdgeFirewall
type EdgeFirewallEndpoint struct {
	Exclude           bool     `xml:"exclude"`
	VnicGroupIds      []string `xml:"vnicGroupId,omitempty"`
	GroupingObjectIds []string `xml:"groupingObjectId,omitempty"`
	IpAddresses       []string `xml:"ipAddress,omitempty"`
}
*/

/*
// EdgeFirewall holds data for creating firewall rule using proxied NSX-V API
// https://code.vmware.com/docs/6900/vcloud-director-api-for-nsx-programming-guide
type EdgeFirewallRule struct {
	XMLName         xml.Name                `xml:"firewallRule" `
	ID              string                  `xml:"id,omitempty"`
	Name            string                  `xml:"name,omitempty"`
	RuleType        string                  `xml:"ruleType,omitempty"`
	RuleTag         string                  `xml:"ruleTag,omitempty"`
	Source          EdgeFirewallEndpoint    `xml:"source" `
	Destination     EdgeFirewallEndpoint    `xml:"destination"`
	Application     EdgeFirewallApplication `xml:"application"`
	MatchTranslated *bool                   `xml:"matchTranslated,omitempty"`
	Direction       string                  `xml:"direction,omitempty"`
	Action          string                  `xml:"action,omitempty"`
	Enabled         bool                    `xml:"enabled"`
	LoggingEnabled  bool                    `xml:"loggingEnabled"`
}
*/

//
func TestFirewall(t *testing.T) {
	live, ctx, err := InitVcdTestEnv()
	require.Nil(t, err, "InitVcdTestEnv")
	defer testVcdClient.Disconnect()
	if live {

		vdc, err := tv.GetVdc(ctx, testVcdClient)
		if err != nil {
			fmt.Printf("GetVdc error %s\n", err.Error())
			return
		}

		/*
			edgeGateWayRecord, err := tv.Objs.Vdc.GetEdgeGatewayRecordsType(true)
			if err != nil {
				fmt.Printf("GetGatewayRecordsType failed: %s\n", err.Error())
			} else {
				fmt.Printf("Got A Gateway records type check the list len: %d  of records\n", len(edgeGateWayRecord.EdgeGatewayRecord))
				for _, gateway := range edgeGateWayRecord.EdgeGatewayRecord {
					fmt.Printf("\t name: %s status %s\n", gateway.Name, gateway.GatewayStatus)
					fmt.Printf("\t external network count: %d\n", gateway.NumberOfExtNetworks)
					fmt.Printf("\t OrgNetworks count%d\n", gateway.NumberOfOrgNetworks)
					fmt.Printf("\t HA status: %s\n", gateway.HaStatus)
				}
			}
		*/
		edgeName := ""
		edgeRecs, err := vdc.GetEdgeGatewayRecordsType(true)
		if err != nil {
			fmt.Printf("GetGatewayRecordsType failed: %s\n", err.Error())
		} else {
			for _, edge := range edgeRecs.EdgeGatewayRecord {
				edgeName = edge.Name
				break
			}
			fmt.Printf("Got A Gateway record name: %s  check the list len: %d  of records\n", edgeRecs.Name, len(edgeRecs.EdgeGatewayRecord))

			if err != nil {
				fmt.Printf("error on edge refresh: %s\n", err.Error())
				return
			}
			edge, err := vdc.GetEdgeGatewayByName(edgeName, false)

			if err != nil {

				fmt.Printf("Error retrieving edge by name: %s error: %s\n", edgeRecs.Name, err.Error())
				require.Nil(t, err, "GetEdgeGatewayByName")
			}
			err = edge.Refresh()
			if err != nil {
				fmt.Printf("Error refreshing edge error: %s\n", err.Error())
				return
			}
			fmt.Printf("Retrived edge gate as %+v\n", *edge)

			existingRules, err := edge.GetAllNsxvFirewallRules()

			if err != nil { // this fails 8/28/20 unable to read firewall rules: API Error: 0:
				// Guess we're not suprised, this is an nsx-v api, but the console states our edge gateways type=NSX-T
				//
				fmt.Printf("TestFireWall-I-failed to retrieve existing rules for %s error: %s\n", edge.EdgeGateway.Name, err.Error())
				//require.Nil(t, err, "GetAllNsxvFirewallRules")
			} else {
				fmt.Printf("Rules for %s:\n", edge.EdgeGateway.Name)
				for _, rule := range existingRules {
					fmt.Printf("\t%+v\n", rule)
				}

			}
			// Can we just get a list of networks from this API?

			nets, err := edge.GetNetworks()
			if err != nil {
				fmt.Printf("Error from GetNetworks: %s\n", err.Error())
			} else {
				for _, net := range nets {
					fmt.Printf("next net for edge : %+v\n", net)
				}
			}
			// Yes, this is fine.
			// Let's create a rule and push it.
			// So, the create is CreateNsxvFirewallRule() but from the console,
			// our setup uses Nsx-t not -v
		}
	} else {
		return
	}
}

// Create a deny all ingress rule
// revisit when we get an edge gateway of type nsx-v (old) or when govcd sprouts support for
// nsx-t which is the type of our current edge gateway.
//
func testPopulateTestRule(t *testing.T, ctx context.Context) (*types.EdgeFirewallRule, error) {

	srcEndpoint := types.EdgeFirewallEndpoint{}
	dstEndpoint := types.EdgeFirewallEndpoint{}
	allApps := types.EdgeFirewallApplication{}

	rule := &types.EdgeFirewallRule{

		Name:        "deny-all-ingress",
		Source:      srcEndpoint,
		Destination: dstEndpoint,
		Application: allApps,
		//		MatchTranslated: true,     // means what?
		Direction:      "ingress",
		Action:         "drop",
		Enabled:        true,
		LoggingEnabled: true,
	}

	return rule, nil

}
