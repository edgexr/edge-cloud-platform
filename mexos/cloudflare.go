package mexos

import (
	"fmt"

	"github.com/mobiledgex/edge-cloud/log"
)

//CheckCredentialsCF checks for Cloudflare
func CheckCredentialsCF(mf *Manifest) error {
	log.DebugLog(log.DebugLevelMexos, "check for cloudflare credentials")
	for _, envname := range []string{"MEX_CF_KEY", "MEX_CF_USER"} {
		if v := mexEnv(mf, envname); v == "" {
			return fmt.Errorf("no env var for %s", envname)
		}
	}
	return nil
}
