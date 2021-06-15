package chargify

import (
	"strings"
	"time"

	"github.com/mobiledgex/edge-cloud/edgeproto"
)

var dmeApiCode = "dmeapi"

// gets the corresponding compoenent code for the flavor
func getComponentCode(flavor, region string, cloudlet *edgeproto.CloudletKey, start, end time.Time) string {
	// CURRENT FLAVOR HANDLE STRUCTURE: region-cloudletOrg-cloudletName-flavor
	regionName := handleSanitize(region)
	org := handleSanitize(cloudlet.Organization)
	name := handleSanitize(cloudlet.Name)
	flavorName := handleSanitize(flavor)
	return "handle:" + regionName + "-" + org + "-" + name + "-" + flavorName
}

func handleSanitize(name string) string {
	// Handle must start with a letter or number and may only contain lowercase letters, numbers, or the characters ':', '-', or '_'
	// replace .&,!
	r := strings.NewReplacer(
		" ", "",
		"&", "",
		",", "",
		".", "",
		"!", "")
	return r.Replace(name)
}
