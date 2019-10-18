package shepherd_openstack

import (
	"context"
	"fmt"
	"time"

	"github.com/gogo/protobuf/types"
	"github.com/mobiledgex/edge-cloud-infra/crm-platforms/openstack"
	"github.com/mobiledgex/edge-cloud-infra/mexos"
	"github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_common"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform/pc"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

// Default Ceilometer granularity is 300 secs(5 mins)
var VmScrapeInterval = time.Minute * 5

type Platform struct {
	rootLbName      string
	SharedClient    pc.PlatformClient
	pf              openstack.Platform
	collectInterval time.Duration
}

func (s *Platform) GetType() string {
	return "openstack"
}

func (s *Platform) Init(ctx context.Context, key *edgeproto.CloudletKey, physicalName, vaultAddr string) error {
	//get the platform client so we can ssh in to make curl commands to the prometheus apps
	var err error
	if err = mexos.InitOpenstackProps(ctx, key.OperatorKey.Name, physicalName, vaultAddr); err != nil {
		return err
	}
	//need to have a separate one for dedicated rootlbs, see openstack.go line 111,
	s.rootLbName = cloudcommon.GetRootLBFQDN(key)
	s.SharedClient, err = s.pf.GetPlatformClientRootLB(ctx, s.rootLbName)
	if err != nil {
		return err
	}
	s.collectInterval = VmScrapeInterval
	log.SpanLog(ctx, log.DebugLevelMexos, "init openstack", "rootLB", s.rootLbName,
		"physicalName", physicalName, "vaultAddr", vaultAddr)
	return nil
}

func (s *Platform) GetMetricsCollectInterval() time.Duration {
	return s.collectInterval
}

func (s *Platform) GetClusterIP(ctx context.Context, clusterInst *edgeproto.ClusterInst) (string, error) {
	_, ip, err := mexos.GetMasterNameAndIP(ctx, clusterInst)
	return ip, err
}

func (s *Platform) GetPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst) (pc.PlatformClient, error) {
	if clusterInst != nil && clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
		rootLb := cloudcommon.GetDedicatedLBFQDN(&clusterInst.Key.CloudletKey, &clusterInst.Key.ClusterKey)
		pc, err := s.pf.GetPlatformClientRootLB(ctx, rootLb)
		return pc, err
	} else {
		return s.SharedClient, nil
	}
}

func (s *Platform) GetPlatformStats(ctx context.Context) (shepherd_common.CloudletMetrics, error) {
	cloudletMetric := shepherd_common.CloudletMetrics{}
	limits, err := mexos.OSGetAllLimits(ctx)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelMetrics, "openstack limits", "error", err)
		return cloudletMetric, err
	}

	cloudletMetric.ComputeTS, _ = types.TimestampProto(time.Now())
	// Openstack limits for RAM in MB and Disk is in GBs
	for _, l := range limits {

		if l.Name == "maxTotalRAMSize" {
			cloudletMetric.MemMax = uint64(l.Value)
		} else if l.Name == "totalRAMUsed" {
			cloudletMetric.MemUsed = uint64(l.Value)
		} else if l.Name == "maxTotalCores" {
			cloudletMetric.VCpuMax = uint64(l.Value)
		} else if l.Name == "totalCoresUsed" {
			cloudletMetric.VCpuUsed = uint64(l.Value)
		} else if l.Name == "maxTotalVolumeGigabytes" {
			cloudletMetric.DiskMax = uint64(l.Value)
		} else if l.Name == "totalGigabytesUsed" {
			cloudletMetric.DiskUsed = uint64(l.Value)
		}
	}
	// TODO - collect network data for all the VM instances

	return cloudletMetric, nil
}

// Helper function to asynchronously get the metric from openstack
func (s *Platform) goGetMetricforId(ctx context.Context, id string, measurement string, osMetric *mexos.OSMetricMeasurement) chan string {
	waitChan := make(chan string)
	go func() {
		// We don't want to have a bunch of data, just get from last 2*interval
		startTime := time.Now().Add(-s.collectInterval * 2)
		metrics, err := mexos.OSGetMetricsRangeForId(ctx, id, measurement, startTime)
		if err == nil && len(metrics) > 0 {
			*osMetric = metrics[len(metrics)-1]
			waitChan <- ""
		} else {
			log.SpanLog(ctx, log.DebugLevelMexos, "Error getting metric", "id", id,
				"measurement", measurement, "error", err)
			waitChan <- err.Error()
		}
	}()
	return waitChan
}

func (s *Platform) GetVmStats(ctx context.Context, key *edgeproto.AppInstKey) (shepherd_common.AppMetrics, error) {
	var Cpu, Mem, Disk, NetSent, NetRecv mexos.OSMetricMeasurement
	netSentChan := make(chan string)
	netRecvChan := make(chan string)
	appMetrics := shepherd_common.AppMetrics{}

	if key == nil {
		return appMetrics, fmt.Errorf("Nil App passed")
	}

	server, err := mexos.GetServerDetails(ctx, key.AppKey.Name)
	if err != nil {
		return appMetrics, err
	}

	// Get a bunch of the results in parallel as it might take a bit of time
	cpuChan := s.goGetMetricforId(ctx, server.ID, "cpu_util", &Cpu)
	memChan := s.goGetMetricforId(ctx, server.ID, "memory.usage", &Mem)
	diskChan := s.goGetMetricforId(ctx, server.ID, "disk.usage", &Disk)

	// For network we try to get the id of the instance_network_interface for an instance
	netIf, err := mexos.OSFindResourceByInstId(ctx, "instance_network_interface", server.ID)
	if err == nil {
		netSentChan = s.goGetMetricforId(ctx, netIf.Id, "network.outgoing.bytes.rate", &NetSent)
		netRecvChan = s.goGetMetricforId(ctx, netIf.Id, "network.incoming.bytes.rate", &NetRecv)
	} else {
		netRecvChan <- "Unavailable"
		netSentChan <- "Unavailable"
	}
	cpuErr := <-cpuChan
	memErr := <-memChan
	diskErr := <-diskChan
	netInErr := <-netRecvChan
	netOutErr := <-netSentChan

	// Now fill the metrics that we actually got
	if cpuErr == "" {
		time, err := time.Parse(time.RFC3339, Cpu.Timestamp)
		if err == nil {
			appMetrics.Cpu = Cpu.Value
			appMetrics.CpuTS, _ = types.TimestampProto(time)
		}
	}
	if memErr == "" {
		time, err := time.Parse(time.RFC3339, Mem.Timestamp)
		if err == nil {
			// Openstack gives it to us in MB
			appMetrics.Mem = uint64(Mem.Value * 1024 * 1024)
			appMetrics.MemTS, _ = types.TimestampProto(time)
		}
	}
	if diskErr == "" {
		time, err := time.Parse(time.RFC3339, Disk.Timestamp)
		if err == nil {
			appMetrics.Disk = uint64(Disk.Value)
			appMetrics.DiskTS, _ = types.TimestampProto(time)
		}
	}
	if netInErr == "" {
		time, err := time.Parse(time.RFC3339, NetRecv.Timestamp)
		if err == nil {
			appMetrics.NetRecv = uint64(NetRecv.Value)
			appMetrics.NetRecvTS, _ = types.TimestampProto(time)
		}
	}
	if netOutErr == "" {
		time, err := time.Parse(time.RFC3339, NetSent.Timestamp)
		if err == nil {
			appMetrics.NetSent = uint64(NetSent.Value)
			appMetrics.NetSentTS, _ = types.TimestampProto(time)
		}
	}
	log.SpanLog(ctx, log.DebugLevelMetrics, "Finished openstack vm metrics", "metrics", appMetrics)
	return appMetrics, nil
}
