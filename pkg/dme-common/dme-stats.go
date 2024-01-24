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

package dmecommon

import (
	"flag"
	"strings"
	"sync"
	"time"

	dme "github.com/edgexr/edge-cloud-platform/api/distributed_match_engine"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	grpcstats "github.com/edgexr/edge-cloud-platform/pkg/metrics/grpc"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
	"github.com/gogo/protobuf/types"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

// MyCloudlet is the information for the cloudlet in which the DME is instantiated.
// The key for MyCloudlet is provided as a configuration - either command line or
// from a file.
var MyCloudletKey edgeproto.CloudletKey

var PlatformClientsCache edgeproto.DeviceCache

var ScaleID = flag.String("scaleID", "", "ID to distinguish multiple DMEs in the same cloudlet. Defaults to hostname if unspecified.")
var monitorUuidType = flag.String("monitorUuidType", "MobiledgeXMonitorProbe", "AppInstClient UUID Type used for monitoring purposes")

var Stats *DmeStats

var LatencyTimes = []time.Duration{
	0 * time.Millisecond,
	5 * time.Millisecond,
	10 * time.Millisecond,
	25 * time.Millisecond,
	50 * time.Millisecond,
	100 * time.Millisecond,
}

type ApiStatCall struct {
	Key     StatKey
	Fail    bool
	Latency time.Duration
}

type ApiStat struct {
	reqs    uint64
	errs    uint64
	latency grpcstats.LatencyMetric
	mux     sync.Mutex
	changed bool
}

type MapShard struct {
	apiStatMap map[StatKey]*ApiStat
	notify     bool
	mux        sync.Mutex
}

type DmeStats struct {
	shards    []MapShard
	numShards uint
	mux       sync.Mutex
	interval  time.Duration
	send      func(ctx context.Context, metric *edgeproto.Metric) bool
	waitGroup sync.WaitGroup
	stop      chan struct{}
}

func init() {
	*ScaleID = cloudcommon.Hostname()
}

func NewDmeStats(interval time.Duration, numShards uint, send func(ctx context.Context, metric *edgeproto.Metric) bool) *DmeStats {
	s := DmeStats{}
	s.shards = make([]MapShard, numShards, numShards)
	s.numShards = numShards
	for ii, _ := range s.shards {
		s.shards[ii].apiStatMap = make(map[StatKey]*ApiStat)
	}
	s.interval = interval
	s.send = send
	return &s
}

func (s *DmeStats) Start() {
	s.mux.Lock()
	defer s.mux.Unlock()
	if s.stop != nil {
		return
	}
	s.stop = make(chan struct{})
	s.waitGroup.Add(1)
	go s.RunNotify()
}

func (s *DmeStats) Stop() {
	s.mux.Lock()
	close(s.stop)
	s.mux.Unlock()
	s.waitGroup.Wait()
	s.mux.Lock()
	s.stop = nil
	s.mux.Unlock()
}

func (s *DmeStats) UpdateSettings(interval time.Duration) {
	if s.interval == interval {
		return
	}
	restart := false
	if s.stop != nil {
		s.Stop()
		restart = true
	}
	s.mux.Lock()
	s.interval = interval
	s.mux.Unlock()
	if restart {
		s.Start()
	}
}

func (s *DmeStats) RecordApiStatCall(call *ApiStatCall) {
	idx := util.GetShardIndex(call.Key.Method+call.Key.AppKey.Organization+call.Key.AppKey.Name, s.numShards)

	shard := &s.shards[idx]
	shard.mux.Lock()
	stat, found := shard.apiStatMap[call.Key]
	if !found {
		stat = &ApiStat{}
		grpcstats.InitLatencyMetric(&stat.latency, LatencyTimes)
		shard.apiStatMap[call.Key] = stat
	}
	stat.reqs++
	if call.Fail {
		stat.errs++
	}
	stat.latency.AddLatency(call.Latency)
	stat.changed = true
	shard.mux.Unlock()
}

// RunNotify walks the stats periodically, and uploads the current
// stats to the controller.
func (s *DmeStats) RunNotify() {
	done := false
	// for now, no tracing of stats
	ctx := context.Background()
	for !done {
		select {
		case <-time.After(s.interval):
			ts, _ := types.TimestampProto(time.Now())
			for ii, _ := range s.shards {
				s.shards[ii].mux.Lock()
				for key, stat := range s.shards[ii].apiStatMap {
					if stat.changed {
						s.send(ctx, ApiStatToMetric(ts, &key, stat))
						stat.changed = false
					}
				}
				s.shards[ii].mux.Unlock()
			}
		case <-s.stop:
			done = true
		}
	}
	s.waitGroup.Done()
}

func ApiStatToMetric(ts *types.Timestamp, key *StatKey, stat *ApiStat) *edgeproto.Metric {
	metric := edgeproto.Metric{}
	metric.Timestamp = *ts
	metric.Name = cloudcommon.DmeApiMeasurement
	metric.AddKeyTags(&key.AppKey)
	metric.AddKeyTags(&MyCloudletKey)
	metric.AddTag(cloudcommon.MetricTagDmeId, *ScaleID)
	metric.AddTag(cloudcommon.MetricTagMethod, key.Method)
	metric.AddIntVal("reqs", stat.reqs)
	metric.AddIntVal("errs", stat.errs)
	metric.AddStringVal("foundCloudlet", key.CloudletFound.Name)
	metric.AddStringVal("foundOperator", key.CloudletFound.Organization)
	stat.latency.AddToMetric(&metric)
	return &metric
}

func MetricToStat(metric *edgeproto.Metric) (*StatKey, *ApiStat) {
	key := &StatKey{}
	stat := &ApiStat{}
	for _, tag := range metric.Tags {
		switch tag.Name {
		case edgeproto.AppKeyTagOrganization:
			key.AppKey.Organization = tag.Val
		case edgeproto.AppKeyTagName:
			key.AppKey.Name = tag.Val
		case edgeproto.AppKeyTagVersion:
			key.AppKey.Version = tag.Val
		case cloudcommon.MetricTagMethod:
			key.Method = tag.Val
		}
	}
	for _, val := range metric.Vals {
		switch val.Name {
		case "reqs":
			stat.reqs = val.GetIval()
		case "errs":
			stat.errs = val.GetIval()
		}
	}
	stat.latency.FromMetric(metric)
	return key, stat
}

func getResultFromFindCloudletReply(mreq *dme.FindCloudletReply) dme.FindCloudletReply_FindStatus {
	return mreq.Status
}

// Helper function to keep track of the registered devices
func RecordDevice(ctx context.Context, req *dme.RegisterClientRequest) {
	devKey := edgeproto.DeviceKey{
		UniqueId:     req.UniqueId,
		UniqueIdType: req.UniqueIdType,
	}
	if PlatformClientsCache.HasKey(&devKey) {
		return
	}
	ts, err := types.TimestampProto(time.Now())
	if err != nil {
		return
	}
	dev := edgeproto.Device{
		Key:       devKey,
		FirstSeen: ts,
	}
	// Update local cache, which will trigger a send to controller
	PlatformClientsCache.Update(ctx, &dev, 0)
}

func (s *DmeStats) UnaryStatsInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	start := time.Now()

	call := ApiStatCall{}
	ctx = context.WithValue(ctx, StatKeyContextKey, &call.Key)

	// call the handler
	resp, err := handler(ctx, req)

	_, call.Key.Method = cloudcommon.ParseGrpcMethod(info.FullMethod)

	updateClient := false
	var loc *dme.Loc

	switch typ := req.(type) {
	case *dme.RegisterClientRequest:
		call.Key.AppKey.Organization = typ.OrgName
		call.Key.AppKey.Name = typ.AppName
		call.Key.AppKey.Version = typ.AppVers
		// For platform App clients we need to do accounting of devices
		if err == nil {
			// We want to count app registrations, not MEL platform registers
			if strings.Contains(strings.ToLower(typ.UniqueIdType), strings.ToLower(edgeproto.OrganizationPlatos)) &&
				!cloudcommon.IsPlatformApp(typ.OrgName, typ.AppName) {
				go RecordDevice(ctx, typ)
			}
		}

	case *dme.PlatformFindCloudletRequest:
		token := req.(*dme.PlatformFindCloudletRequest).ClientToken
		// cannot collect any stats without a token
		if token != "" {
			tokdata, tokerr := GetClientDataFromToken(token)
			if tokerr != nil {
				if err != nil {
					// err and tokerr will have the same cause, because GetClientDataFromToken is also called from PlatformFindCloudlet
					// err has the correct status code
					tokerr = err
				}
				return resp, tokerr
			}
			call.Key.AppKey = tokdata.AppKey
			loc = &tokdata.Location
			updateClient = true
		}

	case *dme.FindCloudletRequest:

		ckey, ok := CookieFromContext(ctx)
		if !ok {
			return resp, err
		}
		call.Key.AppKey.Organization = ckey.OrgName
		call.Key.AppKey.Name = ckey.AppName
		call.Key.AppKey.Version = ckey.AppVers
		loc = req.(*dme.FindCloudletRequest).GpsLocation
		updateClient = true
	default:
		// All other API calls besides RegisterClient
		// have the app info in the session cookie key.
		ckey, ok := CookieFromContext(ctx)
		if !ok {
			return resp, err
		}
		call.Key.AppKey.Organization = ckey.OrgName
		call.Key.AppKey.Name = ckey.AppName
		call.Key.AppKey.Version = ckey.AppVers
	}
	if err != nil {
		call.Fail = true
	}
	call.Latency = time.Since(start)

	if updateClient {
		ckey, ok := CookieFromContext(ctx)
		if !ok {
			return resp, err
		}
		// skip platform monitoring FindCloudletCalls, or if we didn't find the cloudlet
		createClient := true
		fcResp := resp.(*dme.FindCloudletReply)
		if err != nil ||
			ckey.UniqueIdType == *monitorUuidType ||
			getResultFromFindCloudletReply(fcResp) != dme.FindCloudletReply_FIND_FOUND {
			createClient = false
		}

		// Update clients cache if we found the cloudlet
		if createClient {
			client := &edgeproto.AppInstClient{}
			client.ClientKey.AppInstKey = edgeproto.AppInstKey{
				Name:         fcResp.Tags[edgeproto.AppInstKeyTagName],
				Organization: fcResp.Tags[edgeproto.AppInstKeyTagOrganization],
				CloudletKey:  call.Key.CloudletFound,
			}
			client.ClientKey.AppKey = call.Key.AppKey
			client.Location = *loc
			client.ClientKey.UniqueId = ckey.UniqueId
			client.ClientKey.UniqueIdType = ckey.UniqueIdType
			// GpsLocation timestamp can carry an arbitrary system time instead of a timestamp
			client.Location.Timestamp = &dme.Timestamp{}
			ts := time.Now()
			client.Location.Timestamp.Seconds = ts.Unix()
			client.Location.Timestamp.Nanos = int32(ts.Nanosecond())
			// Update list of clients on the side and if there is a listener, send it
			go UpdateClientsBuffer(ctx, client)
		}
	}

	s.RecordApiStatCall(&call)

	return resp, err
}
