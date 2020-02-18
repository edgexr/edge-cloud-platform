package mexos

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	sh "github.com/codeskyblue/go-sh"
	"github.com/miekg/dns"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/log"
	"gortc.io/stun"
)

//validateDomain does strange validation, not strictly domain, due to the data passed from controller.
// if it is Fqdn it is valid. And if it starts with http:// or https:// and followed by fqdn, it is valid.
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

func GetHTTPFile(ctx context.Context, uri string) ([]byte, error) {
	log.SpanLog(ctx, log.DebugLevelMexos, "attempt to get http uri file", "uri", uri)
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

func GetUrlInfo(ctx context.Context, fileUrlPath string) (time.Time, string, error) {
	log.SpanLog(ctx, log.DebugLevelMexos, "get url last-modified time", "file-url", fileUrlPath)
	resp, err := cloudcommon.SendHTTPReq(ctx, "HEAD", fileUrlPath, VaultConfig, nil)
	if err != nil {
		return time.Time{}, "", err
	}
	defer resp.Body.Close()
	tStr := resp.Header.Get("Last-modified")
	lastMod, err := time.Parse(time.RFC1123, tStr)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("Error parsing last modified time of URL %s, %v", fileUrlPath, err)
	}
	md5Sum := ""
	urlInfo := strings.Split(fileUrlPath, "#")
	if len(urlInfo) == 2 {
		cSum := strings.Split(urlInfo[1], ":")
		if len(cSum) == 2 && cSum[0] == "md5" {
			md5Sum = cSum[1]
		}
	}
	if md5Sum == "" {
		md5Sum = resp.Header.Get("X-Checksum-Md5")
	}
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

func DownloadFile(ctx context.Context, fileUrlPath string, filePath string) error {
	var reqConfig *cloudcommon.RequestConfig

	log.SpanLog(ctx, log.DebugLevelMexos, "attempt to download file", "file-url", fileUrlPath)

	// Adjust request timeout based on File Size
	//  - Timeout is increased by 10min for every 5GB
	//  - If less than 5GB, then use default timeout
	resp, err := cloudcommon.SendHTTPReq(ctx, "HEAD", fileUrlPath, VaultConfig, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	contentLength := resp.Header.Get("Content-Length")
	cLen, err := strconv.Atoi(contentLength)
	if err == nil && cLen > 0 {
		timeout := GetTimeout(cLen)
		if timeout > 0 {
			reqConfig = &cloudcommon.RequestConfig{
				Timeout: timeout,
			}
			log.SpanLog(ctx, log.DebugLevelMexos, "increased request timeout", "file-url", fileUrlPath, "timeout", timeout.String())
		}
	}

	resp, err = cloudcommon.SendHTTPReq(ctx, "GET", fileUrlPath, VaultConfig, reqConfig)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// Check server response
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	// Create the file
	out, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer out.Close()

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

// Get the externally visible public IP address
func GetExternalPublicAddr(ctx context.Context) (string, error) {
	myip, err := stunGetMyIP(ctx)
	if err == nil {
		return myip, nil
	}
	// Alternatively use dns resolver to fetch external IP
	myip, err = dnsGetMyIP()
	if err == nil {
		return myip, nil
	}
	return "", err
}

func stunGetMyIP(ctx context.Context) (string, error) {
	log.SpanLog(ctx, log.DebugLevelMexos, "get ip from stun server")
	var myip string

	// Creating a "connection" to STUN server.
	c, err := stun.Dial("udp", "stun.mobiledgex.net:19302")
	if err != nil {
		return "", err
	}
	// Building binding request with random transaction id.
	message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	// Sending request to STUN server, waiting for response message.
	if c_err := c.Do(message, func(res stun.Event) {
		if res.Error != nil {
			err = res.Error
		} else {
			// Decoding XOR-MAPPED-ADDRESS attribute from message.
			var xorAddr stun.XORMappedAddress
			if x_err := xorAddr.GetFrom(res.Message); err != nil {
				err = x_err
			}
			myip = xorAddr.IP.String()
		}
	}); c_err != nil {
		return "", c_err
	}
	if err != nil {
		return "", err
	}
	return myip, nil
}

func dnsGetMyIP() (string, error) {
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("myip.opendns.com"), dns.TypeANY)
	m.RecursionDesired = true

	r, _, err := c.Exchange(m, net.JoinHostPort("resolver1.opendns.com", "53"))
	if r == nil {
		return "", err
	}

	if r.Rcode != dns.RcodeSuccess {
		return "", fmt.Errorf("invalid return code %d", r.Rcode)
	}
	// Stuff must be in the answer section
	for _, a := range r.Answer {
		f, ok := a.(*dns.A)
		if ok {
			return f.A.String(), nil
		}
	}
	return "", fmt.Errorf("unable to find external IP")
}
