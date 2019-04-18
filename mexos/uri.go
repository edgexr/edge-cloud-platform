package mexos

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	sh "github.com/codeskyblue/go-sh"
	"github.com/mobiledgex/edge-cloud-infra/artifactory"
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

func GetURIFile(uri string) ([]byte, error) {
	log.DebugLog(log.DebugLevelMexos, "attempt to get uri file", "uri", uri)
	// if _, err := url.ParseRequestURI(uri); err != nil {
	// 	return nil, err
	// }
	if strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://") {
		res, err := GetHTTPFile(uri)
		if err != nil {
			log.DebugLog(log.DebugLevelMexos, "error getting http uri file", "uri", uri, "error", err)
			return nil, err
		}
		return res, nil
	}
	if strings.HasPrefix(uri, "scp://") {
		res, err := GetSCPFile(uri)
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

func GetHTTPFile(uri string) ([]byte, error) {
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

func GetSCPFile(uri string) ([]byte, error) {
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

// func CopyURIFile(uri string, fn string) error {
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

func SendHTTPReq(method, fileUrlPath string) (*http.Response, error) {
	fileUrl, err := url.Parse(fileUrlPath)
	if err != nil {
		return nil, err
	}
	var af_user, af_pass string
	if fileUrl.Host == "artifactory.mobiledgex.net" {
		af_user, af_pass, err = artifactory.GetCreds()
		if err != nil {
			return nil, err
		}
	}
	client := &http.Client{}
	req, err := http.NewRequest(method, fileUrlPath, nil)
	if err != nil {
		return nil, fmt.Errorf("failed sending request %v", err)
	}
	if af_user != "" && af_pass != "" {
		req.SetBasicAuth(af_user, af_pass)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed fetching response %v", err)
	}
	// Check server response
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status: %s", resp.Status)
	}
	return resp, err
}

func GetUrlInfo(fileUrlPath string) (time.Time, string, error) {
	log.DebugLog(log.DebugLevelMexos, "get url last-modified time", "file-url", fileUrlPath)
	resp, err := SendHTTPReq("HEAD", fileUrlPath)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("Error fetching last modified time of URL %s, %v", fileUrlPath, err)
	}
	tStr := resp.Header.Get("Last-modified")
	lastMod, err := time.Parse(time.RFC1123, tStr)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("Error parsing last modified time of URL %s, %v", fileUrlPath, err)
	}
	md5Sum := resp.Header.Get("X-Checksum-Md5")
	return lastMod, md5Sum, err
}

func Md5SumFile(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file %s, %v", filePath, err)
	}
	defer f.Close()

	h := md5.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("failed to calculate md5sum of file %s, %v", filePath, err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

func DownloadFile(fileUrlPath string, filePath string) error {
	log.DebugLog(log.DebugLevelMexos, "attempt to download file", "file-url", fileUrlPath)

	// Create the file
	out, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer out.Close()

	resp, err := SendHTTPReq("GET", fileUrlPath)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("failed to download file %v", err)
	}

	return nil
}

func DeleteFile(filePath string) error {
	var err error
	if _, err = os.Stat(filePath); !os.IsNotExist(err) {
		_, err = sh.Command("rm", filePath).Output()
	}
	return err
}
