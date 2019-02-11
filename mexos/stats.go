package mexos

import (
	"encoding/json"
	"fmt"

	sh "github.com/codeskyblue/go-sh"
	"github.com/mobiledgex/edge-cloud/log"
)

//GetLimits is used to retrieve tenant level platform stats
func GetLimits() ([]OSLimit, error) {
	log.DebugLog(log.DebugLevelMexos, "GetLimits")
	//err := sh.Command("openstack", "limits", "show", "--absolute", "-f", "json", sh.Dir("/tmp")).WriteStdout("os-out.txt")
	out, err := sh.Command("openstack", "limits", "show", "--absolute", "-f", "json", sh.Dir("/tmp")).Output()
	if err != nil {
		err = fmt.Errorf("cannot get limits from openstack, %v", err)
		return nil, err
	}
	var limits []OSLimit
	err = json.Unmarshal(out, &limits)
	if err != nil {
		err = fmt.Errorf("cannot unmarshal, %v", err)
		return nil, err
	}
	log.DebugLog(log.DebugLevelMexos, "get limits", "limits", limits)
	return limits, nil
}
