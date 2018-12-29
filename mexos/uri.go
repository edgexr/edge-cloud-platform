package mexos

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	sh "github.com/codeskyblue/go-sh"
	"github.com/mobiledgex/edge-cloud/log"
)

//validateDomain does strange validation, not strictly domain, due to the data passed from controller.
// if it is FQDN it is valid. And if it starts with http:// or https:// and followed by fqdn, it is valid.
func validateDomain(uri string) error {
	if isDomainName(uri) {
		return nil
	}
	fqdn := uri2fqdn(uri)
	if isDomainName(fqdn) {
		return nil
	}
	return fmt.Errorf("URI %s is not a valid domain name", uri)
}

func GetURIFile(mf *Manifest, uri string) ([]byte, error) {
	log.DebugLog(log.DebugLevelMexos, "attempt to get uri file", "uri", uri)
	// if _, err := url.ParseRequestURI(uri); err != nil {
	// 	return nil, err
	// }
	if strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://") {
		res, err := GetHTTPFile(mf, uri)
		if err != nil {
			log.DebugLog(log.DebugLevelMexos, "error getting http uri file", "uri", uri, "error", err)
			return nil, err
		}
		return res, nil
	}
	if strings.HasPrefix(uri, "scp://") {
		res, err := GetSCPFile(mf, uri)
		if err != nil {
			log.DebugLog(log.DebugLevelMexos, "error getting scp uri file", "uri", uri, "error", err)
			return nil, err
		}
		return res, nil
	}
	if strings.HasPrefix(uri, "file:///") {
		uri = strings.Replace(uri, "file:///", "", -1)
	}
	// if err := validateDomain(uri); err != nil {
	// 	return ioutil.ReadFile(uri)
	// }
	log.DebugLog(log.DebugLevelMexos, "attempt to read uri as normal file", "uri", uri)
	res, err := ioutil.ReadFile(uri)
	if err != nil {
		log.DebugLog(log.DebugLevelMexos, "error getting file uri file", "uri", uri, "error", err)
		return nil, err
	}
	return res, nil
}

func GetHTTPFile(mf *Manifest, uri string) ([]byte, error) {
	log.DebugLog(log.DebugLevelMexos, "attempt to get http uri file", "uri", uri)
	resp, err := http.Get(uri)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		res, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		return res, nil
	}
	return nil, fmt.Errorf("http status not OK, %v", resp.StatusCode)
}

func GetSCPFile(mf *Manifest, uri string) ([]byte, error) {
	log.DebugLog(log.DebugLevelMexos, "attempt to get scp uri file", "uri", uri)
	part1 := strings.Replace(uri, "scp://", "mobiledgex@", -1)
	slashindex := strings.Index(part1, "/")
	if slashindex < 0 {
		return nil, fmt.Errorf("malformed uri, missing /")
	}
	addr := part1[:slashindex]
	if len(part1) < (slashindex + 1) {
		return nil, fmt.Errorf("malformed uri, too short")
	}
	fn := part1[slashindex+1:]
	if len(fn) < 1 {
		return nil, fmt.Errorf("malformed uri, fn too short")
	}
	return sh.Command("ssh", "-o", sshOpts[0], "-o", sshOpts[1], "-i", PrivateSSHKey(), addr, "cat", fn).Output()
}

// func CopyURIFile(mf *Manifest, uri string, fn string) error {
// 	res, err := GetURIFile(mf, uri)
// 	if err != nil {
// 		return err
// 	}
// 	err = ioutil.WriteFile(fn, res, 0644)
// 	if err != nil {
// 		return err
// 	}
// 	return nil
// }
