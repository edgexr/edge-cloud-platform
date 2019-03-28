package mexos

import (
	"fmt"
	"strings"

	"github.com/mobiledgex/edge-cloud-infra/openstack-tenant/agent/cloudflare"
	"github.com/mobiledgex/edge-cloud/log"
)

func isDomainName(s string) bool {
	l := len(s)
	if l == 0 || l > 254 || l == 254 && s[l-1] != '.' {
		return false
	}

	last := byte('.')
	ok := false // Ok once we've seen a letter.
	partlen := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		default:
			return false
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '_':
			ok = true
			partlen++
		case '0' <= c && c <= '9':
			// fine
			partlen++
		case c == '-':
			// Byte before dash cannot be dot.
			if last == '.' {
				return false
			}
			partlen++
		case c == '.':
			// Byte before dot cannot be dot, dash.
			if last == '.' || last == '-' {
				return false
			}
			if partlen > 63 || partlen == 0 {
				return false
			}
			partlen = 0
		}
		last = c
	}
	if last == '-' || partlen > 63 {
		return false
	}

	return ok
}

func uri2fqdn(uri string) string {
	fqdn := strings.Replace(uri, "http://", "", 1)
	fqdn = strings.Replace(fqdn, "https://", "", 1)
	//XXX assumes no trailing elements
	return fqdn
}

//ActivateFQDNA updates and ensures FQDN is registered properly
func ActivateFQDNA(fqdn string) error {
	if err := cloudflare.InitAPI(GetCloudletCFUser(), GetCloudletCFKey()); err != nil {
		return fmt.Errorf("cannot init cloudflare api, %v", err)
	}
	log.DebugLog(log.DebugLevelMexos, "getting dns record for zone", "DNSZone", GetCloudletDNSZone())
	dr, err := cloudflare.GetDNSRecords(GetCloudletDNSZone(), fqdn)
	if err != nil {
		return fmt.Errorf("cannot get dns records for %s, %v", fqdn, err)
	}
	addr, err := GetServerIPAddr(GetCloudletExternalNetwork(), fqdn)
	for _, d := range dr {
		if d.Type == "A" && d.Name == fqdn {
			if d.Content == addr {
				log.DebugLog(log.DebugLevelMexos, "existing A record", "FQDN", fqdn, "addr", addr)
				return nil
			}
			log.DebugLog(log.DebugLevelMexos, "cloudflare A record has different address, it will be overwritten", "existing", d, "addr", addr)
			if err = cloudflare.DeleteDNSRecord(GetCloudletDNSZone(), d.ID); err != nil {
				return fmt.Errorf("can't delete DNS record for %s, %v", fqdn, err)
			}
			break
		}
	}
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "error while talking to cloudflare", "error", err)
		return err
	}
	if err := cloudflare.CreateDNSRecord(GetCloudletDNSZone(), fqdn, "A", addr, 1, false); err != nil {
		return fmt.Errorf("can't create DNS record for %s, %v", fqdn, err)
	}
	log.DebugLog(log.DebugLevelMexos, "waiting for cloudflare...")
	//once successfully inserted the A record will take a bit of time, but not too long due to fast cloudflare anycast
	//err = WaitforDNSRegistration(fqdn)
	//if err != nil {
	//	return err
	//}
	return nil
}
