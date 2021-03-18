package dmecommon

import (
	"sync"

	dme "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	grpcstats "github.com/mobiledgex/edge-cloud/metrics/grpc"
)

// Filled in by DME. Added to EdgeEventStatCall to update stats
type CustomStatInfo struct {
	Samples            []*dme.Sample
	FirstLatencyUpdate bool // Used to update NumSessions count. Set true in LatencyInfo from FindCloudlet when providing initial DeviceInfo for stats. Additional LatencyInfo from StreamEdgeEvents (which must come after FindCloudlet) would double count NumSessions
}

// Used to find corresponding CustomStat
// Created using CustomStatInfo
type CustomStatKey struct {
	AppInstKey edgeproto.AppInstKey
	Name       string
}

func GetCustomStatKey(appInstKey edgeproto.AppInstKey, statName string) CustomStatKey {
	return CustomStatKey{
		AppInstKey: appInstKey,
		Name:       statName,
	}
}

type CustomStat struct {
	Count             uint64 // number of times this custom stat has been updated
	RollingStatistics *grpcstats.RollingStatistics
	NumSessions       uint64 // number of sessions that send stats
	Mux               sync.Mutex
	Changed           bool
}

func NewCustomStat() *CustomStat {
	c := new(CustomStat)
	c.RollingStatistics = grpcstats.NewRollingStatistics()
	return c
}

func (c *CustomStat) Update(info *CustomStatInfo) {
	c.Count++
	if info.FirstLatencyUpdate {
		c.NumSessions++
	}
	if info.Samples != nil {
		for _, sample := range info.Samples {
			c.RollingStatistics.UpdateRollingStatistics(sample.Value)
		}
	}
}
