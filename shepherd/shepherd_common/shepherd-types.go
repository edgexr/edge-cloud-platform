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

package shepherd_common

import (
	"context"
	"time"

	"github.com/gogo/protobuf/types"
	"github.com/edgexr/edge-cloud/edgeproto"
)

const ShepherdSshConnectTimeout = time.Second * 3

// Prerequisite - install small edge-cloud utility on the VM running this docker containers
var ResTrackerCmd = "resource-tracker"

// Common interface to deal with AppMetrics
// Pending EDGECLOUD-1183 implementation
type AppStats interface {
	// Returns current resource usage for a app instance
	GetAppStats(ctx context.Context) *AppMetrics
}

// Common interface to deal with ClusterMetrics
type ClusterStats interface {
	// Returns current resource usage for a cluster instance
	GetClusterStats(ctx context.Context, ops ...StatsOp) *ClusterMetrics
	GetAppStats(ctx context.Context) map[MetricAppInstKey]*AppMetrics
	GetAlerts(ctx context.Context) []edgeproto.Alert
}

type AppMetrics struct {
	// Cpu is a percentage
	Cpu   float64
	CpuTS *types.Timestamp
	// Mem is bytes used
	Mem   uint64
	MemTS *types.Timestamp
	// Disk is bytes used
	Disk   uint64
	DiskTS *types.Timestamp
}

type ClusterMetrics struct {
	Cpu          float64
	CpuTS        *types.Timestamp
	Mem          float64
	MemTS        *types.Timestamp
	Disk         float64
	DiskTS       *types.Timestamp
	TcpConns     uint64
	TcpConnsTS   *types.Timestamp
	TcpRetrans   uint64
	TcpRetransTS *types.Timestamp
	UdpSent      uint64
	UdpSentTS    *types.Timestamp
	UdpRecv      uint64
	UdpRecvTS    *types.Timestamp
	UdpRecvErr   uint64
	UdpRecvErrTS *types.Timestamp
	AutoScaleCpu float64
	AutoScaleMem float64
}

type ClusterNetMetrics struct {
	NetTS   *types.Timestamp
	NetSent uint64
	NetRecv uint64
}

// This structure represents cloudlet utilization stats
// It tracks the Max Available and currently used set of
// resources
type CloudletMetrics struct {
	CollectTime *types.Timestamp
	// Total number of CPUs
	VCpuMax uint64
	// Current number of CPUs used
	VCpuUsed uint64
	// Total amount of RAM(in MB)
	MemMax uint64
	// Currently used RAM(in MB)
	MemUsed uint64
	// Total amount of Storage(in GB)
	DiskUsed uint64
	// Currently used Storage(in GB)
	DiskMax uint64
	// Total number of Floating IPs available
	FloatingIpsMax uint64
	// Currently used number of Floating IPs
	FloatingIpsUsed uint64
	// Total KBytes received
	NetRecv uint64
	// Total KBytes sent
	NetSent uint64
	// Total available IP addresses
	Ipv4Max uint64
	// Currently used IP addrs
	Ipv4Used uint64
}

type ProxyMetrics struct {
	ActiveConn    uint64
	Accepts       uint64
	HandledConn   uint64
	Requests      uint64
	Reading       uint64
	Writing       uint64
	Waiting       uint64
	Nginx         bool
	EnvoyTcpStats map[int32]TcpConnectionsMetric
	EnvoyUdpStats map[int32]UdpConnectionsMetric
	Ts            *types.Timestamp
}

type UdpConnectionsMetric struct {
	RecvBytes     uint64
	SentBytes     uint64
	RecvDatagrams uint64
	SentDatagrams uint64
	RecvErrs      uint64
	SentErrs      uint64
	Overflow      uint64
	Missed        uint64
}

type TcpConnectionsMetric struct {
	ActiveConn  uint64
	Accepts     uint64
	HandledConn uint64
	// histogram of sessions times (in ms)
	SessionTime map[string]float64
	BytesSent   uint64
	BytesRecvd  uint64
}

// We keep the name of the pod+ClusterInstKey rather than AppInstKey
// The reason is that we do not have a way to differentiate between different pods in a k8s cluster
// See EDGECLOUD-1183
type MetricAppInstKey struct {
	ClusterInstKey edgeproto.ClusterInstKey
	Pod            string
	App            string
	Version        string
}

type StatsOptions struct {
	GetAutoScaleStats bool
}

func GetStatsOptions(ops []StatsOp) *StatsOptions {
	s := &StatsOptions{}
	for _, op := range ops {
		op(s)
	}
	return s
}

type StatsOp func(opts *StatsOptions)

func WithAutoScaleStats() StatsOp {
	return func(opts *StatsOptions) { opts.GetAutoScaleStats = true }
}

var ShepherdPlatformActive bool
