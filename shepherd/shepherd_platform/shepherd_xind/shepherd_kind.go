package shepherd_xind

import (
	"context"
	"fmt"
	"time"

	"github.com/gogo/protobuf/types"
	"github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_common"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/common/xind"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	ssh "github.com/mobiledgex/golang-ssh"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/mem"
	"github.com/shirou/gopsutil/net"
)

type Platform struct {
	pf           xind.Xind
	SharedClient ssh.Client
}

func (s *Platform) Init(ctx context.Context, pc *platform.PlatformConfig, caches *platform.Caches) error {
	var err error
	s.SharedClient, err = s.pf.GetNodePlatformClient(ctx, nil)
	return err
}

func (s *Platform) SetVMPool(ctx context.Context, vmPool *edgeproto.VMPool) {
}

func (s *Platform) GetClusterIP(ctx context.Context, clusterInst *edgeproto.ClusterInst) (string, error) {
	if clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
		return clusterInst.AllocatedIp, nil
	}
	return "localhost", nil
}

func (s *Platform) GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst, clientType string) (ssh.Client, error) {
	return s.SharedClient, nil
}

func (s *Platform) GetVmAppRootLbClient(ctx context.Context, app *edgeproto.AppInstKey) (ssh.Client, error) {
	return nil, fmt.Errorf("No dedicated lbs for xind")
}

func (s *Platform) GetMetricsCollectInterval() time.Duration {
	return 0
}

func (s *Platform) GetPlatformStats(ctx context.Context) (shepherd_common.CloudletMetrics, error) {
	cloudletMetric := shepherd_common.CloudletMetrics{}
	cloudletMetric.CollectTime, _ = types.TimestampProto(time.Now())

	cpu, err := cpu.CountsWithContext(ctx, true)
	if err != nil {
		return cloudletMetric, err
	}
	cloudletMetric.VCpuMax = uint64(cpu)
	// for local we are using all VCpus
	cloudletMetric.VCpuUsed = uint64(cpu)
	m, err := mem.VirtualMemoryWithContext(ctx)
	if err != nil {
		return cloudletMetric, err
	}
	// Limits for Mem is in MBs
	cloudletMetric.MemUsed = uint64(m.Used >> 20)
	cloudletMetric.MemMax = uint64(m.Total >> 20)
	d, err := disk.Usage("/")
	if err != nil {
		return cloudletMetric, err
	}
	// Limits for Disk is in GBs
	cloudletMetric.DiskMax = d.Total >> 30
	cloudletMetric.DiskUsed = d.Used >> 30

	n, err := net.IOCounters(false)
	if err != nil {
		return cloudletMetric, err
	}
	cloudletMetric.NetRecv = n[0].BytesRecv >> 10
	cloudletMetric.NetSent = n[0].BytesSent >> 10
	return cloudletMetric, nil
}

func (s *Platform) GetVmStats(ctx context.Context, key *edgeproto.AppInstKey) (shepherd_common.AppMetrics, error) {
	return shepherd_common.AppMetrics{}, fmt.Errorf("VM on XIND is unsupported")
}

func (s *Platform) VmAppChangedCallback(ctx context.Context) {
}

func (s *Platform) IsPlatformLocal(ctx context.Context) bool {
	return true
}
