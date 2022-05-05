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
	"github.com/edgexr/edge-cloud-infra/shepherd/shepherd_common"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/util"
	ssh "github.com/mobiledgex/golang-ssh"
)

var dockerStatsFormat = `"{\"container\":\"{{.Name}}\",\"id\":\"{{.ID}}\",\"memory\":{\"raw\":\"{{.MemUsage}}\",\"percent\":\"{{.MemPerc}}\"},\"cpu\":\"{{.CPUPerc}}\",\"io\":{\"network\":\"{{.NetIO}}\",\"block\":\"{{.BlockIO}}\"}}"`
var dockerStatsCmd = "docker stats --no-stream --format " + dockerStatsFormat

var dockerPsFormat = `"{\"container\":\"{{.Names}}\",\"id\":\"{{.ID}}\",\"disk\":\"{{.Size}}\",\"labels\":\"{{.Labels}}\"}"`
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

type ContainerDiskAndLabels struct {
	Disk    uint64
	AppName string
	AppVer  string
}

type ContainerSize struct {
	Container string `json:"container,omitempty"`
	Id        string `json:"id,omitempty"`
	Disk      string `json:"disk,omitempty"`
	Labels    string `json:"labels,omitempty"`
}

// Docker Cluster
type DockerClusterStats struct {
	vCPUs         int
	key           edgeproto.ClusterInstKey
	client        ssh.Client
	clusterClient ssh.Client
	shepherd_common.ClusterMetrics
}

func (c *DockerClusterStats) GetClusterStats(ctx context.Context, ops ...shepherd_common.StatsOp) *shepherd_common.ClusterMetrics {
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
	// Also avg out the cpu based on how many cores, since docker stats just returns a sum %
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
			"diskStr", diskStr, "err", err)
		return 0, fmt.Errorf("Failed to parse disk Units - %v", err)
	}
	return diskBytes[0], nil
}

// Example format: "cluster=DevOrg-AppCluster,edge-cloud=,mexAppName=devorgsdkdemo,mexAppVersion=10,cloudlet=localtest"
func getAppVerLabels(ctx context.Context, labelStr string) (string, string, error) {
	var app, ver string
	labels := strings.Split(labelStr, ",")
	for _, label := range labels {
		keyVal := strings.SplitN(label, "=", 2)
		if len(keyVal) != 2 {
			continue
		}
		if keyVal[0] == cloudcommon.MexAppNameLabel {
			app = keyVal[1]
		}
		if keyVal[0] == cloudcommon.MexAppVersionLabel {
			ver = keyVal[1]
		}
		if app != "" && ver != "" {
			return app, ver, nil
		}
	}
	return "", "", fmt.Errorf("Unable to find App name and version")
}

// get disk stats from containers and convert them into a readable format
func (c *DockerClusterStats) GetContainerDiskUsage(ctx context.Context) (map[string]ContainerDiskAndLabels, error) {
	containers := make(map[string]ContainerDiskAndLabels)
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

		diskAndLabels := ContainerDiskAndLabels{}
		if app, ver, err := getAppVerLabels(ctx, containerDisk.Labels); err == nil {
			diskAndLabels.AppName = app
			diskAndLabels.AppVer = ver
		} else {
			// no point in processing disk if we don't know what app it's for
			log.SpanLog(ctx, log.DebugLevelMetrics, "Could not extract app name and version", "labels", containerDisk.Labels, "err", err)
			continue
		}

		// Convert the Disk string into uint64 and
		// save results in a hash keyed on the container id
		if diskSize, err := parseContainerDiskUsage(ctx, containerDisk.Disk); err == nil {
			diskAndLabels.Disk = diskSize
		} else {
			log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to parse disk bytes",
				"diskStr", containerDisk.Disk, "err", err)
		}
		containers[containerDisk.Id] = diskAndLabels
	}
	return containers, nil
}

// This is a helper function to get docker container statistics.
// Currently it runs "docker stats" on rootLB and gets coarse stats from the resource utilization
// If a more detailed resource usage is needed /containers/(id)/stats API endpoint should be used
// To get to the API endpoint on a rootLB netcat can be used:
//   $ echo -e "GET /containers/mobiledgexsdkdemo/stats?stream=0 HTTP/1.0\r\n" | nc -q -1 -U /var/run/docker.sock | grep "^{" | jq
func (c *DockerClusterStats) collectDockerAppMetrics(ctx context.Context, p *DockerClusterStats) map[shepherd_common.MetricAppInstKey]*shepherd_common.AppMetrics {
	var diskUsageMap map[string]ContainerDiskAndLabels // map of container id to virtual disk used and app labels
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
		diskUsageMap = make(map[string]ContainerDiskAndLabels)
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
		containerDiskAndLabels, diskAndLabelsFound := diskUsageMap[containerStats.Id]
		if diskAndLabelsFound {
			// if we have disk stats also use labels to identify app/version
			appKey.App = containerDiskAndLabels.AppName
			appKey.Version = containerDiskAndLabels.AppVer

		}
		stat, found := appStatsMap[appKey]
		if !found {
			stat = &shepherd_common.AppMetrics{}
			appStatsMap[appKey] = stat
		}
		// TODO EDGECLOUD-1316 - if found that means there are several containers with this app
		// Add the stats from all
		stat.CpuTS, stat.MemTS, stat.DiskTS = ts, ts, ts
		// cpu is in the form "0.00%" - remove the % at the end and cast to float
		cpu, err := parsePercentStr(containerStats.Cpu)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to parse CPU usage", "App", appKey, "stats", containerStats, "err", err)
		} else {
			cpu = cpu / float64(c.vCPUs)
		}
		// TODO EDGECLOUD-1316 - add stats for all containers together
		// since cpu is a percentage it needs to be averaged
		stat.Cpu += cpu

		memData, err := parseComputeUnitsDelim(ctx, containerStats.Memory.Raw)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelMetrics, "Failed to parse Mem usage", "App", appKey, "stats", containerStats, "err", err)
		} else {
			// TODO EDGECLOUD-1316 - add stats for all containers together
			stat.Mem += memData[0]
		}
		// Add disk usage
		if diskAndLabelsFound {
			stat.Disk += containerDiskAndLabels.Disk
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
	p.MemTS, p.DiskTS, p.TcpConnsTS, p.TcpRetransTS, p.UdpSentTS, p.UdpRecvTS, p.UdpRecvErrTS = p.CpuTS, p.CpuTS, p.CpuTS, p.CpuTS, p.CpuTS, p.CpuTS, p.CpuTS
	return nil
}

func (c *DockerClusterStats) GetAlerts(ctx context.Context) []edgeproto.Alert {
	// no docker alerts yet
	return nil
}
