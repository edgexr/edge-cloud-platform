// Copyright 2025 EdgeXR, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package nodemgr manages nodes which are bare metal
// machines or VMs.
package nodemgr

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	ssh "github.com/edgexr/golang-ssh"
)

const ClientVersion = "SSH-2.0-edgexr-client-1.0.0"

var CheckNodeTimeout = time.Second * 10

var SupportedOSes = map[string]struct{}{
	"Ubuntu": {},
}

type NodeInfo struct {
	OSName    string
	Arch      string
	Resources edgeproto.NodeResources
}

type CPUInfoData struct {
	Field    string        `json:"field"`
	Data     string        `json:"data"`
	Children []CPUInfoData `json:"children"`
}

func GetSSHClient(node *edgeproto.Node, privKey []byte, timeout time.Duration) (ssh.Client, error) {
	auth := ssh.Auth{
		RawKeys: [][]byte{privKey},
	}
	return ssh.NewNativeClient(node.Username, ClientVersion, node.MgmtAddr, int(node.SshPort), &auth, timeout, nil)
}

func CheckNode(node *edgeproto.Node, privKey []byte) (*NodeInfo, error) {
	client, err := GetSSHClient(node, privKey, CheckNodeTimeout)
	if err != nil {
		return nil, err
	}
	nodeInfo := NodeInfo{}

	// get OS info
	lsbdat, err := client.OutputWithTimeout("lsb_release -a", CheckNodeTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to run lsb_release, %s, %s", lsbdat, err)
	}
	for _, line := range strings.Split(lsbdat, "\n") {
		line = strings.TrimSpace(line)
		parts := strings.Fields(line)
		if len(parts) == 3 && parts[0] == "Distributor" && parts[1] == "ID:" {
			nodeInfo.OSName = parts[2]
			break
		}
	}
	if nodeInfo.OSName == "" {
		return nil, errors.New("unable to determine OS")
	}
	if _, found := SupportedOSes[nodeInfo.OSName]; !found {
		return nil, fmt.Errorf("unsupported OS %s", nodeInfo.OSName)
	}

	// get vcpu info
	cpudat, err := client.OutputWithTimeout("lscpu -J", CheckNodeTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to run lscpu, %s, %s", string(cpudat), err)
	}
	cpuInfo := map[string][]CPUInfoData{}
	err = json.Unmarshal([]byte(cpudat), &cpuInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal lscpu JSON output %s, %s", cpudat, err)
	}
	cpuInfoList, ok := cpuInfo["lscpu"]
	if !ok {
		return nil, fmt.Errorf("lscpu info not found in JSON response %s", string(cpudat))
	}
	for _, cpuInfo := range cpuInfoList {
		if cpuInfo.Field == "Architecture:" {
			nodeInfo.Arch = cpuInfo.Data
		} else if cpuInfo.Field == "CPU(s):" {
			cpus, err := strconv.ParseUint(cpuInfo.Data, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("failed to parse lscpu CPUs count %s, %s", cpuInfo.Data, err)
			}
			nodeInfo.Resources.Vcpus = cpus
		}
	}
	if nodeInfo.Arch == "" {
		return nil, errors.New("unable to determine node architecture")
	}
	if nodeInfo.Resources.Vcpus == 0 {
		return nil, errors.New("no vCPUs found")
	}

	// get mem info
	memdat, err := client.OutputWithTimeout("cat /proc/meminfo", CheckNodeTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to run cat /proc/meminfo, %s, %s", memdat, err)
	}
	for _, line := range strings.Split(memdat, "\n") {
		line = strings.TrimSpace(line)
		parts := strings.Fields(line)
		if parts[0] == "MemTotal:" && len(parts) > 1 {
			memKb, err := strconv.ParseUint(parts[1], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("failed to parse MemTotal %s, %s", parts[1], err)
			}
			nodeInfo.Resources.Ram = memKb / 1024
		}
	}
	if nodeInfo.Resources.Ram == 0 {
		return nil, errors.New("no RAM found")
	}

	// get disk info
	diskdat, err := client.OutputWithTimeout("df -lP", CheckNodeTimeout)
	if err != nil {
		return nil, fmt.Errorf("failed to run df -lP, %s, %s", diskdat, err)
	}
	for _, line := range strings.Split(diskdat, "\n") {
		line = strings.TrimSpace(line)
		parts := strings.Fields(line)
		// Filesystem 1024-blocks Used Available Capacity Mounted-on
		if len(parts) < 5 {
			continue
		}
		// only count the root parition
		if parts[5] == "/" {
			// use available instead of full size, since whatever
			// is already used is not free for us to use.
			diskKb, err := strconv.ParseUint(parts[3], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("failed to parse available disk size %s, %s", parts[3], err)
			}
			nodeInfo.Resources.Disk = diskKb / 1024 / 1024
		}
	}
	if nodeInfo.Resources.Disk == 0 {
		return nil, errors.New("no disk space found")
	}

	return &nodeInfo, nil
}
