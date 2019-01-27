package mexos

import (
	"fmt"
	"os"
	"reflect"
	"strings"

	"github.com/mobiledgex/edge-cloud/log"
)

var validMEXOSEnv = false

func CheckManifest(mf *Manifest) error {
	if mf.APIVersion == "" {
		return fmt.Errorf("mf apiversion not set")
	}
	if mf.APIVersion != APIversion {
		return fmt.Errorf("invalid api version")
	}
	return CheckManifestValues(mf)
}

func CheckManifestValues(mf *Manifest) error {
	log.DebugLog(log.DebugLevelMexos, "checking manifest values")
	return CheckVals(mf.Values)
}

func CheckVals(vals interface{}) error {
	m := reflect.ValueOf(vals)
	if strings.HasPrefix(m.Type().String(), "map[") {
		return nil
	}
	for i := 0; i < m.NumField(); i++ {
		//n := m.Type().Field(i).Name
		t := m.Type().Field(i).Type
		v := m.Field(i).Interface()
		//log.DebugLog(log.DebugLevelMexos, "checkvals", "name", n, "type", m.Type(), "field type", t, "value", v)
		if t.String() == "[]mexos.PortDetail" { // XXX skip ports, TODO check !nil and validate
			continue
		}
		if t.String() == "string" {
			if v == "" {
				//log.DebugLog(log.DebugLevelMexos, "checkvals, warning, empty field", "name", n, "type", m.Type(), "field type", t, "value", v)
			}
			//log.DebugLog(log.DebugLevelMexos, "ok", "name", n, "type", t, "value", v)
		} else {
			if err := CheckVals(m.Field(i).Interface()); err != nil {
				return err
			}
		}
	}
	validMEXOSEnv = true
	return nil
}

func IsValidMEXOSEnv() bool {
	if os.Getenv("MEX_CF_KEY") == "" { // XXX
		return false
	}
	return validMEXOSEnv
}

//ValidateNetSpec parses and validates the netSpec
func ValidateNetSpec(netSpec string) error {
	// TODO if _,err:=ParseNetSpec(netSpec); err!=nil{ return err}
	if netSpec == "" {
		return fmt.Errorf("empty netspec")
	}
	return nil
}

//ValidateTags parses and validates tags
func ValidateTags(tags string) error {
	// TODO a=b,c=d,...
	if tags == "" {
		return fmt.Errorf("empty tags")
	}
	return nil
}

//ValidateTenant parses and validates tenant
func ValidateTenant(tenant string) error {
	// TODO suffix -tenant
	if tenant == "" {
		return fmt.Errorf("emtpy tenant")
	}
	return nil
}

func ValidateClusterKind(kind string) error {
	// TODO list of acceptable cluster kinds to be provided elsewhere
	log.DebugLog(log.DebugLevelMexos, "cluster kind", "kind", kind)
	if kind == "" {
		return fmt.Errorf("empty cluster kind")
	}
	//TODO: add more kinds of clusters
	for _, k := range []string{
		"gcp",
		"azure",
		//"gddt",
	} {
		if kind == k {
			return nil
		}
	}
	// if strings.HasPrefix(kind, "mex-") {
	// 	return nil
	// }
	// log.DebugLog(log.DebugLevelMexos, "warning, cluster kind, operator has no mex- prefix", "kind", kind)
	return nil
}

func ValidateMetadata(mf *Manifest) error {
	//TODO acceptable name patterns to be provided elsewhere
	if mf.Metadata.Name == "" {
		return fmt.Errorf("missing name for the deployment")
	}
	return nil
}

func ValidateKey(mf *Manifest) error {
	// TODO  use of spec key as cluster name may need to change
	if mf.Spec.Key == "" {
		return fmt.Errorf("empty spec key name")
	}
	return nil
}

func ValidateProxyPath(mf *Manifest) error {
	// XXX is it error if this is empty?
	if mf.Spec.ProxyPath == "" {
		return fmt.Errorf("empty proxy path")
	}
	return nil
}

func ValidateImage(mf *Manifest) error {
	// TODO check valid list of images, provided elsewhere
	if mf.Spec.Image == "" {
		return fmt.Errorf("empty image")
	}
	return nil
}

func ValidateDNSZone(mf *Manifest) error {
	// TODO  check against mobiledgex.net and other zones acceptable as listed in DB
	if mf.Metadata.DNSZone == "" {
		return fmt.Errorf("missing DNS zone, metadata %v", mf.Metadata)
	}
	return nil
}

func ValidateCommon(mf *Manifest) error {
	if err := ValidateMetadata(mf); err != nil {
		return err
	}
	if err := ValidateKey(mf); err != nil {
		return err
	}
	if err := ValidateProxyPath(mf); err != nil {
		return err
	}
	if err := ValidateImage(mf); err != nil {
		return err
	}
	if err := ValidateDNSZone(mf); err != nil {
		return err
	}
	return nil
}
