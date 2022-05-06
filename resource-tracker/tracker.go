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

// This is a utility to get resource utilization of a system
// it uses psutil package to query different subsystems
// This script produces json data for shepherd consumption:
//   {"Cpu":1.2,"Mem":34.379,"Disk":4.93,"NetSent":5622,"NetRecv":7164,"TcpConns":0,"TcpRetrans":0,"UdpSent":0,"UdpRecv":0,"UdpRecvErr":0}
package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/edgexr/edge-cloud-infra/shepherd/shepherd_common"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/mem"
	"github.com/shirou/gopsutil/net"
)

func main() {
	result := shepherd_common.ClusterMetrics{}

	if v, err := mem.VirtualMemory(); err == nil {
		result.Mem = v.UsedPercent
	} else {
		// We should always have memory data - something wrong, so just bail
		fmt.Printf("Unable to get memory information - %s\n", err.Error())
		return
	}

	if c, err := cpu.Percent(300*time.Millisecond, false); err == nil {
		result.Cpu = c[0]
	} else {
		// We should always have cpu data - something wrong, so just bail
		fmt.Printf("Unable to get cpu information - %s\n", err.Error())
		return
	}
	if d, err := disk.Usage("/"); err == nil {
		result.Disk = d.UsedPercent
	} else {
		// We should always have disk data - something wrong, so just bail
		fmt.Printf("Unable to get disk information - %s\n", err.Error())
		return
	}
	// Collect proto-specific metrics
	if proto, err := net.ProtoCounters([]string{"tcp", "udp"}); err == nil {
		for _, s := range proto {
			if s.Protocol == "tcp" {
				conns := s.Stats["ActiveOpens"]
				if conns > 0 {
					result.TcpConns = uint64(conns)
				}
			} else if s.Protocol == "udp" {
				// TODO - parse udp stats
			}
		}
	}
	b, err := json.Marshal(&result)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Printf("%s\n", string(b))
	}
}
