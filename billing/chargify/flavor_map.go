package chargify

import (
	"time"

	"github.com/mobiledgex/edge-cloud/edgeproto"
)

var dmeApiCode = "dmeapi"

// gets the corresponding compoenent code for the flavor
// TODO: figure out if we want to embed prices/components into the flavor struct itself(probably not)
func getComponentCode(flavor string, cloudlet *edgeproto.CloudletKey, start, end time.Time) string {
	return "handle:" + "testflavor1"
}
