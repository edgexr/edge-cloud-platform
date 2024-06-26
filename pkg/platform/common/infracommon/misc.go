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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var DefaultConnectTimeout time.Duration = 30 * time.Second
var ClientVersion = "SSH-2.0-mobiledgex-ssh-client-1.0"

var SSHOpts = []string{"StrictHostKeyChecking=no", "UserKnownHostsFile=/dev/null", "LogLevel=ERROR"}
var SSHUser = "ubuntu"

func DefaultKubeconfig() string {
	return os.Getenv("HOME") + "/.kube/config"
}

func CopyFile(src string, dst string) error {
	data, err := ioutil.ReadFile(src)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(dst, data, 0644)
	if err != nil {
		return err
	}
	return nil
}

func WriteTemplateFile(filename string, buf *bytes.Buffer) error {
	outFile, err := os.OpenFile(filename, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("unable to write heat template %s: %s", filename, err.Error())
	}
	_, err = outFile.WriteString(buf.String())

	if err != nil {
		outFile.Close()
		os.Remove(filename)
		return fmt.Errorf("unable to write heat template file %s: %s", filename, err.Error())
	}
	outFile.Sync()
	outFile.Close()
	return nil
}

func IncrIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

type ErrorResp struct {
	Error  string   `json:"error,omitempty"`
	Errors []string `json:"errors,omitempty"`
}

// for reading errors from an http response
func GetReqErr(reqBody io.ReadCloser) error {
	body, err := ioutil.ReadAll(reqBody)
	if err != nil {
		return err
	}
	errorResp := ErrorResp{}
	err = json.Unmarshal(body, &errorResp)
	if err != nil {
		// string error
		return fmt.Errorf("%s", body)
	}
	combineErrors(&errorResp)
	return fmt.Errorf("Errors: %s", strings.Join(errorResp.Errors, ","))
}

func combineErrors(e *ErrorResp) {
	e.Errors = append(e.Errors, e.Error)
}

// round the given field denoted by digIdx, we mostly want seconds
// rounded to two digits
func FormatDuration(dur time.Duration, digIdx int) string {

	var divisors = []time.Duration{
		time.Duration(1),
		time.Duration(10),
		time.Duration(100),
		time.Duration(1000),
	}

	if digIdx < 0 {
		digIdx = 0
	}
	if digIdx >= len(divisors) {
		digIdx = len(divisors) - 1
	}

	switch {
	case dur > time.Second:
		dur = dur.Round(time.Second / divisors[digIdx])
	case dur > time.Millisecond:
		dur = dur.Round(time.Millisecond / divisors[digIdx])
	case dur > time.Microsecond:
		dur = dur.Round(time.Microsecond / divisors[digIdx])
	}
	return dur.String()
}

// ParseIpRanges takes a list of comma-separated IP ranges such as
// 139.178.83.27/29-139.178.83.30/29,139.178.87.10/29-139.178.87.14/29 and returns a slice of all the IP addresses
func ParseIpRanges(ipranges string) ([]string, error) {
	var rc []string
	if ipranges == "" {
		return rc, fmt.Errorf("ip range is empty")
	}
	ipRanges := strings.Split(ipranges, ",")
	for _, ipRange := range ipRanges {
		ranges := strings.Split(ipRange, "-")
		if len(ranges) != 2 {
			return rc, fmt.Errorf("IP range must be in format startcidr-endcidr: %s", ipRange)
		}
		startCidr := ranges[0]
		endCidr := ranges[1]

		ipStart, ipnetStart, err := net.ParseCIDR(startCidr)
		if err != nil {
			return rc, fmt.Errorf("cannot parse start cidr: %v", err)
		}
		ipEnd, ipnetEnd, err := net.ParseCIDR(endCidr)
		if err != nil {
			return rc, fmt.Errorf("cannot parse end cidr: %v", err)
		}
		if ipnetStart.String() != ipnetEnd.String() {
			return rc, fmt.Errorf("start and end network address must match: %s neq %s", ipnetStart, ipnetEnd)
		}
		for ip := ipStart.Mask(ipnetStart.Mask); ipnetStart.Contains(ip); IncrIP(ip) {
			if string(ipStart.To16()) <= string(ip.To16()) && string(ipEnd.To16()) >= string(ip.To16()) {
				rc = append(rc, ip.String())
			}
		}
	}
	return rc, nil
}

func GetDockerCrtFile(crtFilePath string) (string, error) {
	_, crtFile := filepath.Split(crtFilePath)
	ext := filepath.Ext(crtFile)
	if ext == "" {
		return "", fmt.Errorf("invalid tls cert file name: %s", crtFile)
	}
	return "/root/tls/" + crtFile, nil
}
