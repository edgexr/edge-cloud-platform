// Copyright 2022 MobiledgeX, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package infracommon

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/platform"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"gortc.io/stun"
)

type ImageCategoryType string

const ImageCategoryVmApp ImageCategoryType = "vmapp"
const ImageCategoryPlatform ImageCategoryType = "platform"

type ImageInfo struct {
	Md5sum          string
	LocalImageName  string
	SourceImageTime time.Time
	OsType          edgeproto.VmAppOsType
	ImageType       edgeproto.ImageType
	ImagePath       string
	ImageCategory   ImageCategoryType
	Flavor          string
	VmName          string // for use only if the image is to be imported directly into a VM
}

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
	log.SpanLog(ctx, log.DebugLevelInfra, "attempt to get http uri file", "uri", uri)
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

func GetUrlInfo(ctx context.Context, accessApi platform.AccessApi, fileUrlPath string) (time.Time, string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "get url last-modified time", "file-url", fileUrlPath)
	resp, err := cloudcommon.SendHTTPReq(ctx, "HEAD", fileUrlPath, accessApi, cloudcommon.NoCreds, nil, nil)
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

// Get the externally visible public IP address
func GetExternalPublicAddr(ctx context.Context) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "GetExternalPublicAddr")
	myip, err := stunGetMyIP(ctx)
	if err == nil {
		return myip, nil
	}
	log.SpanLog(ctx, log.DebugLevelInfra, "Failed to get IP from STUN, try DNS", "err", err)

	// Alternatively use dns resolver to fetch external IP
	myip, err = dnsGetMyIP()
	if err == nil {
		return myip, nil
	}
	return "", err
}

func stunGetMyIP(ctx context.Context) (string, error) {
	log.SpanLog(ctx, log.DebugLevelInfra, "get ip from stun server")
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
	m.SetQuestion(dns.Fqdn("myip.opendns.com"), dns.TypeA)
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
