package vcd

import (
	"fmt"
	"testing"
)

var verbose = true

// Move to sec_test, or move sec_test's firewall stuff here. XXX
// Get a client, vapp, networks, firewall service, make some rules.

/*
result, err := vapp.UpdateNetworkFirewallRules(uuid, []*types.FirewallRule{&types.FirewallRule{Description: "myFirstRule1", IsEnabled: true, Policy: "allow",
		DestinationPortRange: "Any", DestinationIP: "Any", SourcePortRange: "Any", SourceIP: "Any", Protocols: &types.FirewallRuleProtocols{TCP: true}},
                &types.FirewallRule{Description: "myFirstRule2", IsEnabled: false, Policy: "drop", DestinationPortRange: "Any",
                        DestinationIP: "Any", SourcePortRange: "Any", SourceIP: "Any", Protocols: &types.FirewallRuleProtocols{Any: true}}}, true, "drop", true)
*/

/* A rule
type FirewallRule struct {
        ID                   string                 `xml:"Id,omitempty"`                   // Firewall rule identifier.
        IsEnabled            bool                   `xml:"IsEnabled"`                      // Used to enable or disable the firewall rule. Default value is true.
        MatchOnTranslate     bool                   `xml:"MatchOnTranslate"`               // For DNATed traffic, match the firewall rules only after the destination IP is translated.
        Description          string                 `xml:"Description,omitempty"`          // A description of the rule.
        Policy               string                 `xml:"Policy,omitempty"`               // One of: drop (drop packets that match the rule), allow (allow packets that match the rule to pass through the firewall)
        Protocols            *FirewallRuleProtocols `xml:"Protocols,omitempty"`            // Specify the protocols to which the rule should be applied.
        IcmpSubType          string                 `xml:"IcmpSubType,omitempty"`          // ICMP subtype. One of: address-mask-request, address-mask-reply, destination-unreachable, echo-request, echo-reply, parameter-problem, redirect, router-advertisement, router-solicitation, source-quench, \
time-exceeded, timestamp-request, timestamp-reply, any.
        Port                 int                    `xml:"Port,omitempty"`                 // The port to which this rule applies. A value of -1 matches any port.
        DestinationPortRange string                 `xml:"DestinationPortRange,omitempty"` // Destination port range to which this rule applies.
        DestinationIP        string                 `xml:"DestinationIp,omitempty"`        // Destination IP address to which the rule applies. A value of Any matches any IP address.
        DestinationVM        *VMSelection           `xml:"DestinationVm,omitempty"`        // Details of the destination VM
        SourcePort           int                    `xml:"SourcePort,omitempty"`           // Destination port to which this rule applies. A value of -1 matches any port.
        SourcePortRange      string                 `xml:"SourcePortRange,omitempty"`      // Source port range to which this rule applies.
        SourceIP             string                 `xml:"SourceIp,omitempty"`             // Source IP address to which the rule applies. A value of Any matches any IP address.
        SourceVM             *VMSelection           `xml:"SourceVm,omitempty"`             // Details of the source Vm
        Direction            string                 `xml:"Direction,omitempty"`            // Direction of traffic to which rule applies. One of: in (rule applies to incoming traffic. This is the default value), out (rule applies to outgoing traffic).
        EnableLogging        bool                   `xml:"EnableLogging"`                  // Used to enable or disable firewall rule logging. Default value is false.
}
*/

func TestFirewallService(t *testing.T) {

	fmt.Printf("TestFirewallService\n")
	/*
		vappNetworkSettings := &govcd.VappNetworkSettings{
			Name:               vappNetworkName,
			Gateway:            "192.168.0.1",
			NetMask:            "255.255.255.0",
			DNS1:               "8.8.8.8",
			DNS2:               "1.1.1.1",
			DNSSuffix:          "biz.biz",
			StaticIPRanges:     []*types.IPRange{{StartAddress: "192.168.0.10", EndAddress: "192.168.0.20"}},
			DhcpSettings:       &DhcpSettings{IsEnabled: true, MaxLeaseTime: 3500, DefaultLeaseTime: 2400, IPRange: &types.IPRange{StartAddress: "192.168.0.30", EndAddress: "192.168.0.40"}},
			GuestVLANAllowed:   &guestVlanAllowed,
			Description:        description,
			RetainIpMacEnabled: &retainIpMacEnabled,
		}
	*/
	//fmt.Printf("vapp netowrk settings: %+v\n", vappNetworkSettings)

}
