// This is a utility to get resource utilization of a system
// it uses psutil package to query different subsystems
// This script produces json data for shepherd consumption:
//   {"Cpu":1.2,"Mem":34.379,"Disk":4.93,"NetSent":5622,"NetRecv":7164,"TcpConns":0,"TcpRetrans":0,"UdpSent":0,"UdpRecv":0,"UdpRecvErr":0}
package main

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_common"
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
	// We currently aggregate all the nics, but in reality we want to only track external interface
	if n, err := net.IOCounters(false); err == nil {
		result.NetSent = n[0].BytesSent
		result.NetRecv = n[0].BytesRecv
	} else {
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
