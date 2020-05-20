package shepherd_openstack

import (
	"context"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/gogo/protobuf/types"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"

	"github.com/mobiledgex/edge-cloud-infra/crm-platforms/openstack"
	"github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_common"
	"github.com/mobiledgex/edge-cloud-infra/vmlayer"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/vault"
	ssh "github.com/mobiledgex/golang-ssh"
)

// Default Ceilometer granularity is 300 secs(5 mins)
var VmScrapeInterval = time.Minute * 5

// TODO: ShepherdPlatform should not have references
// to both vmlayer and openstack platforms, this is an interim step.
// We need some refactor of this file to split things out into vmlayer
type ShepherdPlatform struct {
	rootLbName      string
	SharedClient    ssh.Client
	opf             *openstack.OpenstackPlatform
	vmpf            *vmlayer.VMPlatform
	collectInterval time.Duration
	vaultConfig     *vault.Config
}

func (s *ShepherdPlatform) GetType() string {
	return "openstack"
}

func (s *ShepherdPlatform) Init(ctx context.Context, key *edgeproto.CloudletKey, region, physicalName, vaultAddr string, vars map[string]string) error {
	vaultConfig, err := vault.BestConfig(vaultAddr)
	if err != nil {
		return err
	}
	s.vaultConfig = vaultConfig

	// For now we will have a reference to both the VM Platform and the contained Provider, which is openstack.  TODO: all openstack
	// specific stuff needs to be separated out to have a shepherd that will work for any VM platform.
	openstackProvider := &openstack.OpenstackPlatform{}
	s.vmpf = &vmlayer.VMPlatform{
		Type:       vmlayer.VMProviderOpenstack,
		VMProvider: openstackProvider,
	}
	s.opf = openstackProvider
	if err = s.vmpf.InitProps(ctx, &platform.PlatformConfig{}, vaultConfig); err != nil {
		return err
	}
	if err = s.opf.InitApiAccessProperties(ctx, key, region, physicalName, vaultConfig, vars); err != nil {
		return err
	}

	//need to have a separate one for dedicated rootlbs, see openstack.go line 111,
	s.rootLbName = cloudcommon.GetRootLBFQDN(key)
	s.SharedClient, err = s.vmpf.GetNodePlatformClient(ctx, &edgeproto.CloudletMgmtNode{Name: s.rootLbName})
	if err != nil {
		return err
	}
	// Reuse the same ssh connection whever possible
	err = s.SharedClient.StartPersistentConn(shepherd_common.ShepherdSshConnectTimeout)
	if err != nil {
		return err
	}

	s.collectInterval = VmScrapeInterval
	log.SpanLog(ctx, log.DebugLevelInfra, "init openstack", "rootLB", s.rootLbName,
		"physicalName", physicalName, "vaultAddr", vaultAddr)
	return nil
}

func (s *ShepherdPlatform) GetMetricsCollectInterval() time.Duration {
	return s.collectInterval
}

func (s *ShepherdPlatform) GetClusterIP(ctx context.Context, clusterInst *edgeproto.ClusterInst) (string, error) {
	sd, err := s.opf.GetServerDetail(ctx, vmlayer.GetClusterMasterName(ctx, clusterInst))
	if err != nil {
		return "", err
	}
	mexNet := s.opf.VMProperties.GetCloudletMexNetwork()
	subnetName := vmlayer.GetClusterSubnetName(ctx, clusterInst)
	sip, err := vmlayer.GetIPFromServerDetails(ctx, mexNet, subnetName, sd)
	if err != nil {
		return "", err
	}
	return sip.ExternalAddr, nil
}

func (s *ShepherdPlatform) GetClusterPlatformClient(ctx context.Context, clusterInst *edgeproto.ClusterInst) (ssh.Client, error) {
	if clusterInst != nil && clusterInst.IpAccess == edgeproto.IpAccess_IP_ACCESS_DEDICATED {
		rootLb := cloudcommon.GetDedicatedLBFQDN(&clusterInst.Key.CloudletKey, &clusterInst.Key.ClusterKey)
		pc, err := s.vmpf.GetNodePlatformClient(ctx, &edgeproto.CloudletMgmtNode{Name: rootLb})
		if err != nil {
			return nil, err
		}
		err = pc.StartPersistentConn(shepherd_common.ShepherdSshConnectTimeout)
		if err != nil {
			return nil, err
		}
		return pc, err
	} else {
		return s.SharedClient, nil
	}
}

// Given pool ranges return total number of available ip addresses
// Example: 10.10.10.1-10.10.10.20,10.10.10.30-10.10.10.40
//  Returns 20+11 = 31
func getIpCountFromPools(ipPools string) (uint64, error) {
	var total uint64
	total = 0
	pools := strings.Split(ipPools, ",")
	for _, p := range pools {
		ipRange := strings.Split(p, "-")
		if len(ipRange) != 2 {
			return 0, fmt.Errorf("invalid ip pool format")
		}
		ipStart := net.ParseIP(ipRange[0])
		ipEnd := net.ParseIP(ipRange[1])
		if ipStart == nil || ipEnd == nil {
			return 0, fmt.Errorf("Could not parse ip pool limits")
		}
		numStart := new(big.Int)
		numEnd := new(big.Int)
		diff := new(big.Int)
		numStart = numStart.SetBytes(ipStart)
		numEnd = numEnd.SetBytes(ipEnd)
		if numStart == nil || numEnd == nil {
			return 0, fmt.Errorf("cannot convert bytes to bigInt")
		}
		diff = diff.Sub(numEnd, numStart)
		total += diff.Uint64()
		// add extra 1 for the start of pool
		total += 1
	}
	return total, nil
}

func (s *ShepherdPlatform) addIpUsageDetails(ctx context.Context, metric *shepherd_common.CloudletMetrics) error {
	externalNet, err := s.opf.GetNetworkDetail(ctx, s.vmpf.VMProperties.GetCloudletExternalNetwork())
	if err != nil {
		return err
	}
	if externalNet == nil {
		return fmt.Errorf("No external network")
	}
	subnets := strings.Split(externalNet.Subnets, ",")
	if len(subnets) < 1 {
		return nil
	}
	// Assume first subnet for now - see similar note in GetExternalGateway()
	sd, err := s.opf.GetSubnetDetail(ctx, subnets[0])
	if metric.Ipv4Max, err = getIpCountFromPools(sd.AllocationPools); err != nil {
		return err
	}
	// Get current usage
	srvs, err := s.opf.ListServers(ctx)
	if err != nil {
		return err
	}
	metric.Ipv4Used = 0
	for _, srv := range srvs {
		if strings.Contains(srv.Networks, s.vmpf.VMProperties.GetCloudletExternalNetwork()) {
			metric.Ipv4Used++
		}
	}
	return nil
}

func (s *ShepherdPlatform) GetPlatformStats(ctx context.Context) (shepherd_common.CloudletMetrics, error) {
	cloudletMetric := shepherd_common.CloudletMetrics{}
	limits, err := s.opf.OSGetAllLimits(ctx)
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
		} else if l.Name == "maxTotalFloatingIps" {
			cloudletMetric.FloatingIpsMax = uint64(l.Value)
		} else if l.Name == "totalFloatingIpsUsed" {
			cloudletMetric.FloatingIpsUsed = uint64(l.Value)
		}
	}
	// TODO - collect network data for all the VM instances

	// Get Ip pool usage
	if s.addIpUsageDetails(ctx, &cloudletMetric) != nil {
		log.SpanLog(ctx, log.DebugLevelMetrics, "get ip pool information", "error", err)
	} else {
		cloudletMetric.IpUsageTS, _ = types.TimestampProto(time.Now())
	}
	return cloudletMetric, nil
}

// Helper function to asynchronously get the metric from openstack
func (s *ShepherdPlatform) goGetMetricforId(ctx context.Context, id string, measurement string, osMetric *openstack.OSMetricMeasurement) chan string {
	waitChan := make(chan string)
	go func() {
		// We don't want to have a bunch of data, just get from last 2*interval
		startTime := time.Now().Add(-s.collectInterval * 2)
		metrics, err := s.opf.OSGetMetricsRangeForId(ctx, id, measurement, startTime)
		if err == nil && len(metrics) > 0 {
			*osMetric = metrics[len(metrics)-1]
			waitChan <- ""
		} else if len(metrics) == 0 {
			waitChan <- "no metric"
		} else {
			log.SpanLog(ctx, log.DebugLevelMetrics, "Error getting metric", "id", id,
				"measurement", measurement, "error", err)
			waitChan <- err.Error()
		}
	}()
	return waitChan
}

func (s *ShepherdPlatform) GetVmStats(ctx context.Context, key *edgeproto.AppInstKey) (shepherd_common.AppMetrics, error) {
	var Cpu, Mem, Disk, NetSent, NetRecv openstack.OSMetricMeasurement
	netSentChan := make(chan string)
	netRecvChan := make(chan string)
	appMetrics := shepherd_common.AppMetrics{}

	if key == nil {
		return appMetrics, fmt.Errorf("Nil App passed")
	}

	server, err := s.opf.GetActiveServerDetails(ctx, cloudcommon.GetAppFQN(&key.AppKey))
	if err != nil {
		return appMetrics, err
	}

	// Get a bunch of the results in parallel as it might take a bit of time
	cpuChan := s.goGetMetricforId(ctx, server.ID, "cpu_util", &Cpu)
	memChan := s.goGetMetricforId(ctx, server.ID, "memory.usage", &Mem)
	diskChan := s.goGetMetricforId(ctx, server.ID, "disk.usage", &Disk)

	// For network we try to get the id of the instance_network_interface for an instance
	netIf, err := s.opf.OSFindResourceByInstId(ctx, "instance_network_interface", server.ID)
	if err == nil {
		netSentChan = s.goGetMetricforId(ctx, netIf.Id, "network.outgoing.bytes.rate", &NetSent)
		netRecvChan = s.goGetMetricforId(ctx, netIf.Id, "network.incoming.bytes.rate", &NetRecv)
	} else {
		go func() {
			netRecvChan <- "Unavailable"
			netSentChan <- "Unavailable"
		}()
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
