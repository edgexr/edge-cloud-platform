package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/gogo/protobuf/types"
	"github.com/mobiledgex/edge-cloud-infra/shepherd/shepherd_common"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/util"
	ssh "github.com/mobiledgex/golang-ssh"
)

var dockerStatsFormat = `"{\"container\":\"{{.Name}}\",\"id\":\"{{.ID}}\",\"memory\":{\"raw\":\"{{.MemUsage}}\",\"percent\":\"{{.MemPerc}}\"},\"cpu\":\"{{.CPUPerc}}\",\"io\":{\"network\":\"{{.NetIO}}\",\"block\":\"{{.BlockIO}}\"}}"`
var dockerStatsCmd = "docker stats --no-stream --format " + dockerStatsFormat

var dockerPsFormat = `"{\"container\":\"{{.Names}}\",\"id\":\"{{.ID}}\",\"disk\":\"{{.Size}}\"}"`
var dockerPsSizeCmd = "docker ps -s --format " + dockerPsFormat

type ContainerMem struct {
	Raw     string
	Percent string
}
type ContainerIO struct {
	Network string
	Block   string
}
type ContainerStats struct {
	App       string `json:"app,omitempty"`
	Id        string `json:"id,omitempty"`
	Version   string `json:"version,omitempty"`
	Container string
	Memory    ContainerMem
	Cpu       string
	IO        ContainerIO
}

type DockerStats struct {
	Containers []ContainerStats
}

type ContainerSize struct {
	Container string `json:"container,omitempty"`
	Id        string `json:"id,omitempty"`
	Disk      string `json:"disk,omitempty"`
}

// Docker Cluster
type DockerClusterStats struct {
	key           edgeproto.ClusterInstKey
	client        ssh.Client
	clusterClient ssh.Client
	shepherd_common.ClusterMetrics
}

func (c *DockerClusterStats) GetClusterStats(ctx context.Context) *shepherd_common.ClusterMetrics {
	if err := collectDockerClusterMetrics(ctx, c); err != nil {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Could not collect cluster metrics", "Docker cluster", c)
		return nil
	}
	return &c.ClusterMetrics
}

// Currently we are collecting stats for all apps in the cluster in one shot
// Implementing  EDGECLOUD-1183 would allow us to query by label and we can have each app be an individual metric
func (c *DockerClusterStats) GetAppStats(ctx context.Context) map[shepherd_common.MetricAppInstKey]*shepherd_common.AppMetrics {
	metrics := c.collectDockerAppMetrics(ctx, c)
	if metrics == nil {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Could not collect app metrics", "Docker Container", c)
	}
	return metrics
}

// Get the output of the container stats on the platform and format them properly
// Container stats give a list of all AppInst containers
// Walk the appInst cache for a given clusterInst and match to the container_ids
func (c *DockerClusterStats) GetContainerStats(ctx context.Context) (*DockerStats, error) {
	containers := make(map[string]*ContainerStats)
	respLB, err := c.client.Output(dockerStatsCmd)
	if err != nil {
		errstr := fmt.Sprintf("Failed to run <%s> on LB VM", dockerStatsCmd)
		log.SpanLog(ctx, log.DebugLevelMetrics, errstr, "err", err.Error())
		return nil, err
	}
	respVM, err := c.clusterClient.Output(dockerStatsCmd) // check the VM for LoadBalancer docker apps
	if err != nil {
		errstr := fmt.Sprintf("Failed to run <%s> on ClusterVM", dockerStatsCmd)
		log.SpanLog(ctx, log.DebugLevelMetrics, errstr, "err", err.Error())
		return nil, err
	}
	dockerResp := &DockerStats{}
	stats := strings.Split(respLB, "\n")
	statsVM := strings.Split(respVM, "\n")
	stats = append(stats, statsVM...)
	for _, stat := range stats {
		if stat == "" {
			// last string is an empty string
			continue
		}
		containerStat := ContainerStats{}
		if err = json.Unmarshal([]byte(stat), &containerStat); err != nil {
			log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to marshal stats", "stats", c, "err", err.Error())
			continue
		}
		// save results in a hash based on the container name
		containers[containerStat.Container] = &containerStat
	}

	// find apps on this cluster and add appName
	AppInstCache.GetForRealClusterInstKey(&c.key, func(obj *edgeproto.AppInst) {
		var cData *ContainerStats
		var found bool

		for _, cID := range obj.RuntimeInfo.ContainerIds {
			cData, found = containers[cID]

			if found {
				cData.App = util.DNSSanitize(obj.Key.AppKey.Name)
				cData.Version = util.DNSSanitize(obj.Key.AppKey.Version)
				dockerResp.Containers = append(dockerResp.Containers, *cData)

			}
		}
	})
	// Keep track of those containers not associated with any App, just in case
	for _, container := range containers {
		if container.App == "" {
			// container and app are the same here
			container.App = util.DNSSanitize(container.Container)
			dockerResp.Containers = append(dockerResp.Containers, *container)
		}
	}
	return dockerResp, nil
}

func parsePercentStr(pStr string) (float64, error) {
	i := strings.Index(pStr, "%")
	if i < 0 {
		return 0, fmt.Errorf("Invalid percentage string")
	}
	return strconv.ParseFloat(pStr[:i], 64)
}

// This looks like this:
// $ cat /proc/$CONTAINER_PID/net/dev | grep ens
//Inter-|   Receive                                                |  Transmit
//  ens3: 448842077 3084030    0    0    0     0          0         0 514882026 2675536    0    0    0     0       0          0
func parseNetData(dataStr string) ([]uint64, error) {
	var items []uint64
	details := strings.Fields(dataStr)
	// second element is recv and 9th element is tx
	if len(details) < 10 {
		return nil, fmt.Errorf("Improperly formatted output - %s", dataStr)
	}
	if t, err := strconv.ParseUint(details[1], 10, 64); err == nil {
		items = append(items, t)
	} else {
		return nil, fmt.Errorf("Could not parse recv bytes - %s", details[1])
	}
	if t, err := strconv.ParseUint(details[9], 10, 64); err == nil {
		items = append(items, t)
	} else {
		return nil, fmt.Errorf("Could not parse send bytes - %s", details[9])
	}
	return items, nil
}

// parse data in the format "1.629MiB / 1.952GiB / 12KB / 12B" into [1.629* 1000000, 1.952 * 1000000000, 12*1000 , 12]
func parseComputeUnitsDelim(ctx context.Context, dataStr string) ([]uint64, error) {
	var items []uint64
	var scale uint64
	// token function to find first letter(K/M/G)
	tokenFunc := func(c rune) bool {
		return unicode.IsLetter(c)
	}

	vals := strings.Split(dataStr, " / ")
	for _, v := range vals {

		i := strings.IndexFunc(v, tokenFunc)
		if i == -1 {
			//if just a number add to array
			if t, err := strconv.ParseUint(v, 10, 64); err == nil {
				items = append(items, t)
			} else {
				log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to parse data", "val", v, "err", err)
			}
			continue
		}
		// deal with KiB, MiB, GiB
		switch v[i] {
		case 'B':
			scale = 1
		case 'k':
			fallthrough
		case 'K':
			scale = 1024
		case 'm':
			fallthrough
		case 'M':
			scale = 1024 * 1024
		case 'g':
			fallthrough
		case 'G':
			scale = 1024 * 1024 * 1024
		default:
			log.SpanLog(ctx, log.DebugLevelMetrics, "Unknown Unit string", "units", v[i])
			continue
		}

		if t, err := strconv.ParseFloat(v[0:i], 64); err == nil {
			t *= float64(scale)
			items = append(items, uint64(t))
		} else {
			log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to parse data", "val", v[0:i], "err", err)
		}
	}
	return items, nil
}

// Example format: "0B (virtual 332.1GB)"
func parseContainerDiskUsage(ctx context.Context, diskStr string) (uint64, error) {
	var writeDisk, virtDisk string
	// getting just a virtual disk size for the grand total
	n, err := fmt.Sscanf(diskStr, "%s (virtual %s", &writeDisk, &virtDisk)
	if err != nil || n < 2 {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to parse disk usage",
			"diskStr", diskStr, "err", err.Error())
		return 0, fmt.Errorf("Failed to parse disk usage - %v", err)
	}
	// remove trailing )
	virtDisk = strings.TrimSuffix(virtDisk, ")")
	diskBytes, err := parseComputeUnitsDelim(ctx, virtDisk)
	if err != nil || len(diskBytes) != 1 {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to parse disk bytes", "virtDisk", virtDisk,
			"diskStr", diskStr, "err", err.Error())
		return 0, fmt.Errorf("Failed to parse disk Units - %v", err)
	}
	return diskBytes[0], nil
}

// get disk stats from containers and convert them into a readable format
func (c *DockerClusterStats) GetContainerDiskUsage(ctx context.Context) (map[string]uint64, error) {
	containers := make(map[string]uint64)
	respLB, err := c.client.Output(dockerPsSizeCmd)
	if err != nil {
		errstr := fmt.Sprintf("Failed to run <%s> on LB VM", dockerPsSizeCmd)
		log.SpanLog(ctx, log.DebugLevelMetrics, errstr, "err", err.Error())
		return nil, err
	}
	respVM, err := c.clusterClient.Output(dockerPsSizeCmd) // check the VM for LoadBalancer docker apps
	if err != nil {
		errstr := fmt.Sprintf("Failed to run <%s> on ClusterVM", dockerPsSizeCmd)
		log.SpanLog(ctx, log.DebugLevelMetrics, errstr, "err", err.Error())
		return nil, err
	}

	stats := strings.Split(respLB, "\n")
	statsVM := strings.Split(respVM, "\n")
	stats = append(stats, statsVM...)
	for _, stat := range stats {
		if stat == "" {
			// last string is an empty string
			continue
		}
		containerDisk := ContainerSize{}
		if err = json.Unmarshal([]byte(stat), &containerDisk); err != nil {
			log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to marshal disk usage", "stats", stat, "err", err.Error())
			continue
		}
		// Convert the Disk string into uint64 and
		// save results in a hash keyed on the container id
		if diskSize, err := parseContainerDiskUsage(ctx, containerDisk.Disk); err == nil {
			containers[containerDisk.Id] = diskSize
		} else {
			log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to parse disk bytes",
				"diskStr", containerDisk.Disk, "err", err)
		}
	}
	return containers, nil
}

// This is a helper function to get docker container statistics.
// Currently it runs "docker stats" on rootLB and gets coarse stats from the resource utilization
// If a more detailed resource usage is needed /containers/(id)/stats API endpoint should be used
// To get to the API endpoint on a rootLB netcat can be used:
//   $ echo -e "GET /containers/mobiledgexsdkdemo/stats?stream=0 HTTP/1.0\r\n" | nc -q -1 -U /var/run/docker.sock | grep "^{" | jq
func (c *DockerClusterStats) collectDockerAppMetrics(ctx context.Context, p *DockerClusterStats) map[shepherd_common.MetricAppInstKey]*shepherd_common.AppMetrics {
	var diskUsageMap map[string]uint64 // map of container id to virtual disk used
	appStatsMap := make(map[shepherd_common.MetricAppInstKey]*shepherd_common.AppMetrics)

	stats, err := p.GetContainerStats(ctx)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to collect App stats for docker cluster", "err", err)
		return nil
	}
	diskUsageMap, err = p.GetContainerDiskUsage(ctx)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to collect Disk usage stats for docker containers", "err", err)
		// we can still collect other metrics, so just init this to an empty map
		diskUsageMap = make(map[string]uint64)
	}

	log.SpanLog(ctx, log.DebugLevelMetrics, "Docker stats", "stats", stats)
	appKey := shepherd_common.MetricAppInstKey{
		ClusterInstKey: p.key,
	}

	// We scraped it at the same time, so same timestamp for everything
	ts, _ := types.TimestampProto(time.Now())
	for _, containerStats := range stats.Containers {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Docker stats - container", "container", containerStats)
		// TODO EDGECLOUD-1316 - set pod to the container
		// appKey.Pod = containerStats.Container
		appKey.Pod = containerStats.App
		appKey.App = containerStats.App
		appKey.Version = containerStats.Version
		stat, found := appStatsMap[appKey]
		if !found {
			stat = &shepherd_common.AppMetrics{}
			appStatsMap[appKey] = stat
		}
		// TODO EDGECLOUD-1316 - if found that means there are several containers with this app
		// Add the stats from all
		stat.CpuTS, stat.MemTS, stat.DiskTS, stat.NetSentTS, stat.NetRecvTS = ts, ts, ts, ts, ts
		// cpu is in the form "0.00%" - remove the % at the end and cast to float
		cpu, err := parsePercentStr(containerStats.Cpu)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to parse CPU usage", "App", appKey, "stats", containerStats, "err", err)
		}
		// TODO EDGECLOUD-1316 - add stats for all containers together
		stat.Cpu += cpu

		memData, err := parseComputeUnitsDelim(ctx, containerStats.Memory.Raw)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to parse Mem usage", "App", appKey, "stats", containerStats, "err", err)
		} else {
			// TODO EDGECLOUD-1316 - add stats for all containers together
			stat.Mem += memData[0]
		}
		// Add disk usage from the usage map
		if disk, found := diskUsageMap[containerStats.Id]; found {
			stat.Disk += disk
		}

		// NET data in docker stats only counts docker0 interface,
		// so for host networking it's always going to be zero - use proc data instead
		pid, err := c.clusterClient.Output("docker inspect -f '{{ .State.Pid }}' " + containerStats.Id)
		if err != nil {
			errstr := fmt.Sprintf("Failed to get pid for cid <%s> on LB VM", containerStats.Id)
			log.SpanLog(ctx, log.DebugLevelMetrics, errstr, "err", err.Error(), "output", pid)
		} else {
			netdata, err := c.clusterClient.Output("cat /proc/" + pid + "/net/dev | grep ens")
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to get net stats", "err", err.Error(),
					"pid", pid, "cid", containerStats.Id, "output", netdata)
			} else {
				netIO, err := parseNetData(netdata)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to parse Network usage", "App", appKey,
						"stats", containerStats, "err", err, "netdata", netdata)
				} else {
					if len(netIO) > 1 {
						// TODO EDGECLOUD-1316 - add stats for all containers together
						stat.NetRecv += netIO[0]
						stat.NetSent += netIO[1]
					} else {
						log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to parse network data", "netio", netIO)
					}
				}
			}
		}
	}

	return appStatsMap
}

func collectDockerClusterMetrics(ctx context.Context, p *DockerClusterStats) error {
	// VM stats from Openstack might be a better idea going forward, but for now use a simple script to scrape metrics from the cluster node
	resp, err := p.clusterClient.Output(shepherd_common.ResTrackerCmd)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to run", "cmd", shepherd_common.ResTrackerCmd, "err", err.Error())
		return err
	}
	if err = json.Unmarshal([]byte(resp), &p.ClusterMetrics); err != nil {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to marshal machine metrics", "stats", resp, "err", err.Error())
		return err
	}
	// set timestamps to current time
	p.CpuTS, _ = types.TimestampProto(time.Now())
	p.MemTS, p.DiskTS, p.NetSentTS, p.NetRecvTS, p.TcpConnsTS, p.TcpRetransTS, p.UdpSentTS, p.UdpRecvTS, p.UdpRecvErrTS = p.CpuTS, p.CpuTS, p.CpuTS, p.CpuTS, p.CpuTS, p.CpuTS, p.CpuTS, p.CpuTS, p.CpuTS
	return nil
}

func (c *DockerClusterStats) GetAlerts(ctx context.Context) []edgeproto.Alert {
	// no docker alerts yet
	return nil
}
