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
	"net/http"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/platform"
	goexternalip "github.com/glendc/go-external-ip"
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

var extIPV4Lookup *goexternalip.Consensus
var extIPV6Lookup *goexternalip.Consensus

func init() {
	lookupCfg := &goexternalip.ConsensusConfig{
		Timeout: 3 * time.Second,
	}
	extIPV4Lookup = goexternalip.NewConsensus(lookupCfg, nil)
	extIPV4Lookup.UseIPProtocol(4)
	extIPV6Lookup = goexternalip.NewConsensus(lookupCfg, nil)
	extIPV6Lookup.UseIPProtocol(6)

	for _, lookup := range []*goexternalip.Consensus{extIPV4Lookup, extIPV6Lookup} {
		lookup.AddVoter(goexternalip.NewHTTPSource("https://ident.me"), 3)
		lookup.AddVoter(goexternalip.NewHTTPSource("https://api64.ipify.org"), 3)
		lookup.AddVoter(goexternalip.NewHTTPSource("https://icanhazip.com"), 3)
	}
}

// GetExternalPublicAddr gets the externally visible public IP address
func GetExternalPublicAddr(ctx context.Context, types ...IPVersion) (IPs, error) {
	var pubIPs IPs
	log.SpanLog(ctx, log.DebugLevelInfra, "GetExternalPublicAddr", "types", types)

	for _, typ := range types {
		var lookup *goexternalip.Consensus
		var idx int
		switch typ {
		case IPV4:
			lookup = extIPV4Lookup
			idx = IndexIPV4
		case IPV6:
			lookup = extIPV6Lookup
			idx = IndexIPV6
		}
		if lookup == nil {
			continue
		}
		ip, err := lookup.ExternalIP()
		log.SpanLog(ctx, log.DebugLevelInfra, "lookup external IP", "type", typ, "ip", ip, "err", err)
		if err == nil {
			pubIPs[idx] = ip.String()
		}
	}
	if !pubIPs.IsSet() {
		return pubIPs, fmt.Errorf("external public IPs not found")
	}
	return pubIPs, nil
}
