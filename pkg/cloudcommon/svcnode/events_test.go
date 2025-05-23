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

package svcnode

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/Shopify/sarama"
	"github.com/Shopify/sarama/mocks"
	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/process"
	"github.com/mobiledgex/yaml/v2"
	"github.com/stretchr/testify/require"
)

func TestEvents(t *testing.T) {
	log.SetDebugLevel(log.DebugLevelEtcd | log.DebugLevelApi | log.DebugLevelEvents | log.DebugLevelInfo)

	dockNet := process.DockerNetwork{}
	dockNet.Common.Name = "unit-test-logging"
	err := dockNet.Create()
	require.Nil(t, err)
	defer dockNet.Delete()

	// opensearch docker takes a while to start up (~20s),
	// so make sure to include all unit-testing against it here.
	esProc := process.ElasticSearch{}
	esProc.Common.Name = "opensearch-unit-test"
	esProc.DockerNetwork = dockNet.Common.Name
	err = esProc.StartLocal("")
	require.Nil(t, err)
	defer esProc.StopLocal()

	// start Jaeger to test searching spans in opensearch
	jaegerProc := process.Jaeger{}
	jaegerProc.Common.Name = "jaeger-unit-test"
	jaegerProc.DockerNetwork = dockNet.Common.Name
	jaegerProc.DockerEnvVars = make(map[string]string)
	jaegerProc.DockerEnvVars["ES_SERVER_URLS"] = "http://opensearch:9200"
	jaegerProc.DockerEnvVars["SPAN_STORAGE_TYPE"] = "elasticsearch"
	jaegerProc.Links = []string{"opensearch-unit-test:opensearch"}
	err = jaegerProc.StartLocalNoTraefik("")
	require.Nil(t, err)
	defer jaegerProc.StopLocal()

	// set true otherwise logger will not log spans for unit-tests
	log.JaegerUnitTest = true

	// events rely on nodeMgr
	nodeMgr := SvcNodeMgr{}
	region := "unit-test"
	ctx, _, err := nodeMgr.Init(SvcNodeTypeController, "", WithRegion(region),
		WithESUrls("http://localhost:9200"))
	require.Nil(t, err)
	defer nodeMgr.Finish()
	nodeMgr.unitTestMode = true

	starttime := time.Date(2020, time.August, 1, 0, 0, 0, 0, time.UTC)
	ts := starttime

	org := "devOrg"
	operOrg := "operOrg"
	cloudlet1Name := "cloudlet1"
	keyTags := map[string]string{
		edgeproto.AppKeyTagName:                       "myapp",
		edgeproto.AppKeyTagOrganization:               org,
		edgeproto.AppKeyTagVersion:                    "1.0",
		edgeproto.CloudletKeyTagName:                  cloudlet1Name,
		edgeproto.CloudletKeyTagOrganization:          operOrg,
		edgeproto.CloudletKeyTagFederatedOrganization: operOrg,
		edgeproto.ClusterKeyTagName:                   "testclust",
		edgeproto.ClusterKeyTagOrganization:           "testorg",
	}
	keyTags2 := map[string]string{
		edgeproto.CloudletKeyTagName:                  cloudlet1Name,
		edgeproto.CloudletKeyTagOrganization:          operOrg,
		edgeproto.CloudletKeyTagFederatedOrganization: operOrg,
	}

	// add a mock kafka producer so we can capture kafka events
	// note this only captures events for cloudlet1, not cloudlet2,
	// and not appinsts except when the cloudlet is a private cloudlet.
	producerConfig := sarama.NewConfig()
	producerConfig.Producer.Return.Successes = true
	producerConfig.Producer.Return.Errors = true
	kafkaProducer := mocks.NewAsyncProducer(t, producerConfig)
	prod := producer{
		producer: kafkaProducer,
		address:  "fake-address",
	}
	cloudletKey := edgeproto.CloudletKey{
		Organization: operOrg,
		Name:         cloudlet1Name,
	}
	producerLock.Lock()
	producers[cloudletKey] = prod
	producerLock.Unlock()
	defer kafkaProducer.Close()
	// kafka msg checks
	kmsgs := []*EventData{}
	getKmsg := func(val []byte) error {
		event := EventData{}
		err := yaml.Unmarshal(val, &event)
		if err != nil {
			return err
		}
		// delete tags that are non-deterministic
		delete(event.Mtags, "traceid")
		delete(event.Mtags, "spanid")
		delete(event.Mtags, "lineno")
		delete(event.Mtags, "hostname")
		kmsgs = append(kmsgs, &event)
		return nil
	}

	// create events
	ts = ts.Add(time.Minute)
	nodeMgr.EventAtTime(ctx, "test start", NoOrg, "event", nil, nil, ts)

	ts = ts.Add(time.Minute)
	kafkaProducer.ExpectInputWithCheckerFunctionAndSucceed(getKmsg) // operator event
	nodeMgr.EventAtTime(ctx, "cloudlet online", operOrg, "event", keyTags2, nil, ts)
	expKmsg1 := &EventData{
		Name:      "cloudlet online",
		Org:       []string{operOrg},
		Type:      EventType,
		Region:    region,
		Timestamp: ts,
		Mtags:     keyTags2,
	}

	ts = ts.Add(time.Minute)
	nodeMgr.EventAtTime(ctx, "create AppInst", org, "event", keyTags, nil, ts)

	ts = ts.Add(time.Minute)
	keyTags[edgeproto.CloudletKeyTagName] = "cloudlet2"
	nodeMgr.EventAtTime(ctx, "create AppInst", org, "event", keyTags, fmt.Errorf("failed, unknown failure"), ts, "the reason", "AutoProv")

	ts = ts.Add(time.Minute)
	nodeMgr.EventAtTime(ctx, "delete AppInst", org, "event", keyTags, fmt.Errorf("failed, random failure"), ts, "the reason", "just because")

	// add cloudlet to zone pool
	cloudlet := edgeproto.Cloudlet{
		Key:          cloudletKey,
		Zone:         "zone1",
		KafkaCluster: prod.address,
	}
	nodeMgr.CloudletLookup.GetCloudletCache(NoRegion).Update(ctx, &cloudlet, 0)
	pool := edgeproto.ZonePool{
		Key: edgeproto.ZonePoolKey{
			Organization: operOrg,
			Name:         "pool1",
		},
		Zones: []*edgeproto.ZoneKey{cloudlet.GetZone()},
	}
	nodeMgr.ZonePoolLookup.GetZonePoolCache(NoRegion).Update(ctx, &pool, 0)
	cpc, ok := nodeMgr.ZonePoolLookup.(*ZonePoolCache)
	require.True(t, ok)
	require.True(t, cpc.PoolsByZone.HasRef(*cloudlet.GetZone()))

	// event with two allowed orgs, developer and operator due to ZonePool
	ts = ts.Add(time.Minute)
	keyTags[edgeproto.CloudletKeyTagName] = cloudlet1Name
	kafkaProducer.ExpectInputWithCheckerFunctionAndSucceed(getKmsg) // private cloudlet event
	nodeMgr.EventAtTime(ctx, "update AppInst", org, "event", keyTags, nil, ts)
	expKmsg2 := &EventData{
		Name:      "update AppInst",
		Org:       []string{org, operOrg},
		Type:      EventType,
		Region:    region,
		Timestamp: ts,
		Mtags:     keyTags,
	}

	//
	// ---------------------------------------------------
	// Span logs test data
	// ---------------------------------------------------
	//
	span := log.StartSpan(log.DebugLevelInfo, "span1")
	sctx := log.ContextWithSpan(context.Background(), span)
	log.SpanLog(sctx, log.DebugLevelInfo, "span1-msg1", "key1", "somevalue")
	log.SpanLog(sctx, log.DebugLevelInfo, "msg2")
	span.Finish()

	span = log.StartSpan(log.DebugLevelInfo, "span2")
	sctx = log.ContextWithSpan(context.Background(), span)
	log.SpanLog(sctx, log.DebugLevelInfo, "span2-msg1", "key2", "foooobar")
	log.SpanLog(sctx, log.DebugLevelInfo, "msg2")
	span.Finish()

	span = log.StartSpan(log.DebugLevelInfo, "span3")
	sctx = log.ContextWithSpan(context.Background(), span)
	log.SpanLog(sctx, log.DebugLevelInfo, "msg3")
	log.SpanLog(sctx, log.DebugLevelInfo, "msg3", "key2", "foooobar")
	span.Finish()

	span = log.StartSpan(log.DebugLevelInfo, "span4")
	sctx = log.ContextWithSpan(context.Background(), span)
	log.SpanLog(sctx, log.DebugLevelInfo, "span4-msg1", "anotherkey", "anothervalue")
	log.SpanLog(sctx, log.DebugLevelInfo, "msg3")
	span.Finish()

	// wait for queued events to be written to ES
	waitEvents(t, &nodeMgr, 7)
	// wait for queued spans to be written
	waitSpans(t, 5) // one extra because nodeMgr creates one

	endtime := time.Now()

	// for some reason ES is not ready immediately for searching
	time.Sleep(3 * time.Second)

	//
	// ---------------------------------------------------
	// Tests for term aggregations
	// ---------------------------------------------------
	//

	aggr := func(name string, count int) AggrVal {
		return AggrVal{
			Key:      name,
			DocCount: count,
		}
	}

	// check terms aggregations over all events
	search := EventSearch{
		TimeRange: edgeproto.TimeRange{
			StartTime: starttime,
			EndTime:   endtime,
		},
		Limit: 100,
	}
	terms, err := nodeMgr.EventTerms(ctx, &search)
	require.Nil(t, err)
	expectedTerms := EventTerms{
		Names: []AggrVal{
			aggr("create AppInst", 2),
			aggr("cloudlet online", 1),
			aggr("controller start", 1),
			aggr("delete AppInst", 1),
			aggr("test start", 1),
			aggr("update AppInst", 1),
		},
		Orgs: []AggrVal{
			aggr(org, 4),
			aggr(NoOrg, 2),
			aggr(operOrg, 2),
		},
		Types:   []AggrVal{aggr("event", 7)},
		Regions: []AggrVal{aggr(region, 7)},
		TagKeys: []AggrVal{
			aggr("hostname", 7),
			aggr("lineno", 7),
			aggr("spanid", 7),
			aggr("traceid", 7),
			aggr(edgeproto.CloudletKeyTagName, 6),
			aggr(edgeproto.CloudletKeyTagFederatedOrganization, 6),
			aggr(edgeproto.CloudletKeyTagOrganization, 6),
			aggr(edgeproto.AppKeyTagName, 4),
			aggr(edgeproto.AppKeyTagOrganization, 4),
			aggr(edgeproto.AppKeyTagVersion, 4),
			aggr(edgeproto.ClusterKeyTagName, 4),
			aggr(edgeproto.ClusterKeyTagOrganization, 4),
			aggr("the reason", 2),
			aggr("node", 1),
			aggr("noderegion", 1),
			aggr("nodetype", 1),
		},
	}
	require.Equal(t, expectedTerms, *terms)

	// check terms aggregations filtered by allowed org
	es := search
	es.AllowedOrgs = []string{org}
	terms, err = nodeMgr.EventTerms(ctx, &es)
	require.Nil(t, err)
	expectedTerms = EventTerms{
		Names: []AggrVal{
			aggr("create AppInst", 2),
			aggr("delete AppInst", 1),
			aggr("update AppInst", 1),
		},
		Orgs: []AggrVal{
			aggr(org, 4),
			aggr(operOrg, 1),
		},
		Types:   []AggrVal{aggr("event", 4)},
		Regions: []AggrVal{aggr(region, 4)},
		TagKeys: []AggrVal{
			aggr(edgeproto.AppKeyTagName, 4),
			aggr(edgeproto.AppKeyTagOrganization, 4),
			aggr(edgeproto.AppKeyTagVersion, 4),
			aggr(edgeproto.CloudletKeyTagName, 4),
			aggr(edgeproto.CloudletKeyTagFederatedOrganization, 4),
			aggr(edgeproto.CloudletKeyTagOrganization, 4),
			aggr(edgeproto.ClusterKeyTagName, 4),
			aggr(edgeproto.ClusterKeyTagOrganization, 4),
			aggr("hostname", 4),
			aggr("lineno", 4),
			aggr("spanid", 4),
			aggr("traceid", 4),
			aggr("the reason", 2),
		},
	}
	require.Equal(t, expectedTerms, *terms)

	// check terms aggregations filtered by allowed org
	es = search
	es.AllowedOrgs = []string{operOrg}
	terms, err = nodeMgr.EventTerms(ctx, &es)
	require.Nil(t, err)
	expectedTerms = EventTerms{
		Names: []AggrVal{
			aggr("cloudlet online", 1),
			aggr("update AppInst", 1),
		},
		Orgs: []AggrVal{
			aggr(operOrg, 2),
			aggr(org, 1),
		},
		Types:   []AggrVal{aggr("event", 2)},
		Regions: []AggrVal{aggr(region, 2)},
		TagKeys: []AggrVal{
			aggr(edgeproto.CloudletKeyTagName, 2),
			aggr(edgeproto.CloudletKeyTagFederatedOrganization, 2),
			aggr(edgeproto.CloudletKeyTagOrganization, 2),
			aggr("hostname", 2),
			aggr("lineno", 2),
			aggr("spanid", 2),
			aggr("traceid", 2),
			aggr(edgeproto.AppKeyTagName, 1),
			aggr(edgeproto.AppKeyTagOrganization, 1),
			aggr(edgeproto.AppKeyTagVersion, 1),
			aggr(edgeproto.ClusterKeyTagName, 1),
			aggr(edgeproto.ClusterKeyTagOrganization, 1),
		},
	}
	require.Equal(t, expectedTerms, *terms)

	//
	// ---------------------------------------------------
	// Tests for span term aggregations
	// ---------------------------------------------------
	//
	spansearch := SpanSearch{
		TimeRange: edgeproto.TimeRange{
			StartTime: starttime,
			EndTime:   endtime,
		},
		Limit: 100,
	}
	sterms, err := nodeMgr.SpanTerms(ctx, &spansearch)
	require.Nil(t, err)
	expectedSpanTerms := &SpanTerms{
		Operations: []AggrVal{
			aggr("init-es-events", 1),
			aggr("span1", 1),
			aggr("span2", 1),
			aggr("span3", 1),
			aggr("span4", 1),
		},
		Services: []AggrVal{
			aggr("svcnode.test", 5),
		},
		Msgs: []AggrVal{
			aggr("msg3", 3),
			aggr("msg2", 2),
			aggr("queued event", 1),
			aggr("span1-msg1", 1),
			aggr("span2-msg1", 1),
			aggr("span4-msg1", 1),
			aggr("write event-log index template", 1),
		},
	}
	// ignore tags and hostnames
	sterms.Tags = nil
	sterms.Hostnames = nil
	require.Equal(t, expectedSpanTerms, sterms)

	//
	// ---------------------------------------------------
	// Tests for filter searches
	// ---------------------------------------------------
	//

	// limit time range to just our test events.
	// this avoids the startup event added by nodeMgr.Init().
	search = EventSearch{
		TimeRange: edgeproto.TimeRange{
			StartTime: starttime,
			EndTime:   starttime.Add(time.Hour),
		},
		Limit: 100,
	}

	// find all events
	events, err := nodeMgr.ShowEvents(ctx, &search)
	require.Nil(t, err)
	require.Equal(t, 6, len(events))
	require.Equal(t, "update AppInst", events[0].Name)
	require.Equal(t, "delete AppInst", events[1].Name)
	require.Equal(t, "create AppInst", events[2].Name)
	require.Equal(t, "create AppInst", events[3].Name)
	require.Equal(t, "cloudlet online", events[4].Name)
	require.Equal(t, "test start", events[5].Name)

	// find all events (wildcard)
	es = search
	es.Match.Names = []string{"*"}
	events, err = nodeMgr.ShowEvents(ctx, &es)
	require.Nil(t, err)
	require.Equal(t, 6, len(events))
	require.Equal(t, "update AppInst", events[0].Name)
	require.Equal(t, "delete AppInst", events[1].Name)
	require.Equal(t, "create AppInst", events[2].Name)
	require.Equal(t, "create AppInst", events[3].Name)
	require.Equal(t, "cloudlet online", events[4].Name)
	require.Equal(t, "test start", events[5].Name)

	// find all create AppInst events
	es = search
	es.Match.Names = []string{"create AppInst"}
	events, err = nodeMgr.ShowEvents(ctx, &es)
	require.Nil(t, err)
	require.Equal(t, 2, len(events))
	require.Equal(t, "create AppInst", events[0].Name)
	require.Equal(t, "create AppInst", events[1].Name)

	// find by multiple names
	es = search
	es.Match.Names = []string{"create AppInst", "delete AppInst"}
	events, err = nodeMgr.ShowEvents(ctx, &es)
	require.Nil(t, err)
	require.Equal(t, 3, len(events))
	require.Equal(t, "delete AppInst", events[0].Name)
	require.Equal(t, "create AppInst", events[1].Name)
	require.Equal(t, "create AppInst", events[2].Name)

	// find all create events
	es = search
	es.Match.Names = []string{"create*"}
	events, err = nodeMgr.ShowEvents(ctx, &es)
	require.Nil(t, err)
	require.Equal(t, 2, len(events))
	require.Equal(t, "create AppInst", events[0].Name)
	require.Equal(t, "create AppInst", events[1].Name)

	// search text by words - name is a keyword so must be exact or wildcard
	es = search
	es.Match.Names = []string{"create"}
	events, err = nodeMgr.ShowEvents(ctx, &es)
	require.Nil(t, err)
	require.Equal(t, 0, len(events))

	// support wildcard matching
	es = search
	es.Match.Names = []string{"*App*"}
	events, err = nodeMgr.ShowEvents(ctx, &es)
	require.Nil(t, err)
	require.Equal(t, 4, len(events))
	require.Equal(t, "update AppInst", events[0].Name)
	require.Equal(t, "delete AppInst", events[1].Name)
	require.Equal(t, "create AppInst", events[2].Name)
	require.Equal(t, "create AppInst", events[3].Name)

	// support wildcard matching
	es = search
	es.Match.Names = []string{"create App*", "delete App*"}
	events, err = nodeMgr.ShowEvents(ctx, &es)
	require.Nil(t, err)
	require.Equal(t, 3, len(events))
	require.Equal(t, "delete AppInst", events[0].Name)
	require.Equal(t, "create AppInst", events[1].Name)
	require.Equal(t, "create AppInst", events[2].Name)

	// search for all that failed, regardless of error
	es = search
	es.Match.Failed = true
	events, err = nodeMgr.ShowEvents(ctx, &es)
	require.Nil(t, err)
	require.Equal(t, 2, len(events))
	require.Equal(t, "delete AppInst", events[0].Name)
	require.Equal(t, "create AppInst", events[1].Name)

	// search for particular error message
	es = search
	es.Match.Error = "random failure"
	events, err = nodeMgr.ShowEvents(ctx, &es)
	require.Nil(t, err)
	require.Equal(t, 1, len(events))
	require.Equal(t, "delete AppInst", events[0].Name)
	// note that order of words doesn't matter, nor does capitalization
	es = search
	es.Match.Error = "Failure Random"
	events, err = nodeMgr.ShowEvents(ctx, &es)
	require.Nil(t, err)
	require.Equal(t, 1, len(events))
	require.Equal(t, "delete AppInst", events[0].Name)

	// search by org
	// for security, org is a keyword so requires an exact string match
	es = search
	es.Match.Orgs = []string{org}
	events, err = nodeMgr.ShowEvents(ctx, &es)
	require.Nil(t, err)
	require.Equal(t, 4, len(events))
	require.Equal(t, "update AppInst", events[0].Name)
	require.Equal(t, "delete AppInst", events[1].Name)
	require.Equal(t, "create AppInst", events[2].Name)
	require.Equal(t, "create AppInst", events[3].Name)
	// search by org does not allow partial match
	es = search
	es.Match.Orgs = []string{"dev"}
	events, err = nodeMgr.ShowEvents(ctx, &es)
	require.Nil(t, err)
	require.Equal(t, 0, len(events))
	// search by org does not allow case insensitivity
	es = search
	es.Match.Orgs = []string{"devorg"}
	events, err = nodeMgr.ShowEvents(ctx, &es)
	require.Nil(t, err)
	require.Equal(t, 0, len(events))
	// search by org supports wildcard, but should probably be filtered
	// by MC for RBAC.
	es = search
	es.Match.Orgs = []string{"dev*"}
	events, err = nodeMgr.ShowEvents(ctx, &es)
	require.Nil(t, err)
	require.Equal(t, 4, len(events))
	require.Equal(t, "update AppInst", events[0].Name)
	require.Equal(t, "delete AppInst", events[1].Name)
	require.Equal(t, "create AppInst", events[2].Name)
	require.Equal(t, "create AppInst", events[3].Name)

	out, err := yaml.Marshal(events[0])
	require.Nil(t, err)
	fmt.Printf("%s\n", string(out))

	// search by operator org for ZonePool-based Cloudlet events
	es = search
	es.Match.Orgs = []string{operOrg}
	events, err = nodeMgr.ShowEvents(ctx, &es)
	require.Nil(t, err)
	require.Equal(t, 2, len(events))
	require.Equal(t, "update AppInst", events[0].Name)
	require.Equal(t, "cloudlet online", events[1].Name)

	// search by tag
	es = search
	es.Match.Tags = map[string]string{
		edgeproto.AppKeyTagName: "myapp",
	}
	events, err = nodeMgr.ShowEvents(ctx, &es)
	require.Nil(t, err)
	require.Equal(t, 4, len(events))
	require.Equal(t, "update AppInst", events[0].Name)
	require.Equal(t, "delete AppInst", events[1].Name)
	require.Equal(t, "create AppInst", events[2].Name)
	require.Equal(t, "create AppInst", events[3].Name)
	// search by tag key must be exact match
	es = search
	es.Match.Tags = map[string]string{
		"reason": "AutoProv",
	}
	events, err = nodeMgr.ShowEvents(ctx, &es)
	require.Nil(t, err)
	require.Equal(t, 0, len(events))
	// search by tag key must be exact match
	es = search
	es.Match.Tags = map[string]string{
		"the reason": "AutoProv",
	}
	events, err = nodeMgr.ShowEvents(ctx, &es)
	require.Nil(t, err)
	require.Equal(t, 1, len(events))
	require.Equal(t, "create AppInst", events[0].Name)
	// search by multiple tags must include all
	es = search
	es.Match.Tags = map[string]string{
		edgeproto.AppKeyTagName:      "myapp",
		edgeproto.CloudletKeyTagName: cloudlet1Name,
	}
	events, err = nodeMgr.ShowEvents(ctx, &es)
	require.Nil(t, err)
	require.Equal(t, 2, len(events))
	require.Equal(t, "update AppInst", events[0].Name)
	require.Equal(t, "create AppInst", events[1].Name)
	// search by multiple tags must include all
	es = search
	es.Match.Tags = map[string]string{
		edgeproto.AppKeyTagName:      "myapp",
		edgeproto.CloudletKeyTagName: "cloudlet2",
	}
	events, err = nodeMgr.ShowEvents(ctx, &es)
	require.Nil(t, err)
	require.Equal(t, 2, len(events))
	require.Equal(t, "delete AppInst", events[0].Name)
	require.Equal(t, "create AppInst", events[1].Name)
	// search by tag value can be wildcard
	es = search
	es.Match.Tags = map[string]string{
		edgeproto.AppKeyTagName:      "myapp",
		edgeproto.CloudletKeyTagName: "cloudlet*",
	}
	events, err = nodeMgr.ShowEvents(ctx, &es)
	require.Nil(t, err)
	require.Equal(t, 4, len(events))
	require.Equal(t, "update AppInst", events[0].Name)
	require.Equal(t, "delete AppInst", events[1].Name)
	require.Equal(t, "create AppInst", events[2].Name)
	require.Equal(t, "create AppInst", events[3].Name)
	// verify lineno tag is set correctly
	es = search
	es.Match.Tags = map[string]string{
		"lineno": "*events_test.go*",
	}
	events, err = nodeMgr.ShowEvents(ctx, &es)
	require.Nil(t, err)
	require.Equal(t, 6, len(events))
	require.Equal(t, "update AppInst", events[0].Name)
	require.Equal(t, "delete AppInst", events[1].Name)
	require.Equal(t, "create AppInst", events[2].Name)
	require.Equal(t, "create AppInst", events[3].Name)
	require.Equal(t, "cloudlet online", events[4].Name)
	require.Equal(t, "test start", events[5].Name)

	// verify allowedOrgs enforcement
	es = search
	es.AllowedOrgs = []string{"otherOrg"}
	events, err = nodeMgr.ShowEvents(ctx, &es)
	require.Nil(t, err)
	require.Equal(t, 0, len(events))
	es = search
	es.Match.Orgs = []string{org}
	es.AllowedOrgs = []string{"otherOrg"}
	events, err = nodeMgr.ShowEvents(ctx, &es)
	require.Nil(t, err)
	require.Equal(t, 0, len(events))

	// find all events for multiple allowed orgs
	es = search
	es.AllowedOrgs = []string{org, operOrg}
	events, err = nodeMgr.ShowEvents(ctx, &es)
	require.Nil(t, err)
	require.Equal(t, 5, len(events))
	require.Equal(t, "update AppInst", events[0].Name)
	require.Equal(t, "delete AppInst", events[1].Name)
	require.Equal(t, "create AppInst", events[2].Name)
	require.Equal(t, "create AppInst", events[3].Name)
	require.Equal(t, "cloudlet online", events[4].Name)

	// search by time range
	es = search
	es.StartTime = starttime
	es.EndTime = starttime.Add(2*time.Minute + 200*time.Millisecond)
	events, err = nodeMgr.ShowEvents(ctx, &es)
	require.Nil(t, err)
	require.Equal(t, 2, len(events))
	require.Equal(t, "cloudlet online", events[0].Name)
	require.Equal(t, "test start", events[1].Name)

	//
	// ---------------------------------------------------
	// Tests for relevance searches
	// ---------------------------------------------------
	//

	// search looking for error message
	es = search
	es.Match.Orgs = []string{org, operOrg}
	es.Match.Error = "failed"
	es.Match.Tags = map[string]string{
		edgeproto.AppKeyTagName: "myapp",
		"the reason":            "because",
	}
	es.Match.Names = []string{"*create*"}
	events, err = nodeMgr.FindEvents(ctx, &es)
	require.Nil(t, err)
	require.Equal(t, 6, len(events))
	require.Equal(t, "delete AppInst", events[0].Name)
	require.Equal(t, "create AppInst", events[1].Name)
	require.Equal(t, "update AppInst", events[2].Name)
	require.Equal(t, "create AppInst", events[3].Name)
	require.Equal(t, "", events[3].Error) // should be empty
	require.Equal(t, "cloudlet online", events[4].Name)
	require.Equal(t, "test start", events[5].Name)

	// search looking for failed autoprov
	es = search
	es.Match.Orgs = []string{org, operOrg}
	es.Match.Failed = true
	es.Match.Tags = map[string]string{
		edgeproto.AppKeyTagName: "myapp",
		"the reason":            "autoprov",
	}
	es.Match.Names = []string{"*update*"}
	events, err = nodeMgr.FindEvents(ctx, &es)
	require.Nil(t, err)
	require.Equal(t, 6, len(events))
	require.Equal(t, "create AppInst", events[0].Name)
	require.Equal(t, "delete AppInst", events[1].Name)
	require.Equal(t, "update AppInst", events[2].Name)
	require.Equal(t, "create AppInst", events[3].Name)
	require.Equal(t, "", events[3].Error) // should be empty
	require.Equal(t, "cloudlet online", events[4].Name)
	require.Equal(t, "test start", events[5].Name)

	// search for autoprov creates
	es = search
	es.Match.Orgs = []string{org, operOrg}
	es.Match.Names = []string{"*create*"}
	es.Match.Tags = map[string]string{
		edgeproto.AppKeyTagName:      "myapp",
		edgeproto.CloudletKeyTagName: cloudlet1Name,
	}
	events, err = nodeMgr.FindEvents(ctx, &es)
	require.Nil(t, err)
	require.Equal(t, 6, len(events))
	require.Equal(t, "update AppInst", events[0].Name)
	require.Equal(t, "create AppInst", events[1].Name)
	require.Equal(t, "", events[1].Error) // should be empty
	require.Equal(t, "create AppInst", events[2].Name)
	require.Equal(t, "delete AppInst", events[3].Name)
	require.Equal(t, "cloudlet online", events[4].Name)
	require.Equal(t, "test start", events[5].Name)

	// verify allowedOrgs enforcement
	es = search
	es.AllowedOrgs = []string{"otherOrg"}
	events, err = nodeMgr.FindEvents(ctx, &es)
	require.Nil(t, err)
	require.Equal(t, 0, len(events))
	es = search
	es.Match.Orgs = []string{org}
	es.AllowedOrgs = []string{"otherOrg"}
	events, err = nodeMgr.FindEvents(ctx, &es)
	require.Nil(t, err)
	require.Equal(t, 0, len(events))

	//
	// ---------------------------------------------------
	// Test not matching searches
	// ---------------------------------------------------
	//

	// not names
	es = search
	es.NotMatch.Names = []string{"create AppInst"}
	events, err = nodeMgr.ShowEvents(ctx, &es)
	require.Nil(t, err)
	require.Equal(t, 4, len(events))
	require.Equal(t, "update AppInst", events[0].Name)
	require.Equal(t, "delete AppInst", events[1].Name)
	require.Equal(t, "cloudlet online", events[2].Name)
	require.Equal(t, "test start", events[3].Name)

	// tags plus not failed
	es = search
	es.Match.Tags = map[string]string{
		edgeproto.AppKeyTagName: "myapp",
	}
	es.NotMatch.Failed = true
	events, err = nodeMgr.ShowEvents(ctx, &es)
	require.Nil(t, err)
	require.Equal(t, 2, len(events))
	require.Equal(t, "update AppInst", events[0].Name)
	require.Equal(t, "create AppInst", events[1].Name)

	// not tags
	es = search
	es.NotMatch.Tags = map[string]string{
		edgeproto.CloudletKeyTagName: "cloudlet2",
	}
	events, err = nodeMgr.ShowEvents(ctx, &es)
	require.Nil(t, err)
	require.Equal(t, 4, len(events))
	require.Equal(t, "update AppInst", events[0].Name)
	require.Equal(t, "create AppInst", events[1].Name)
	require.Equal(t, "cloudlet online", events[2].Name)
	require.Equal(t, "test start", events[3].Name)

	es = search
	es.NotMatch.Names = []string{"create App*", "delete App*"}
	events, err = nodeMgr.ShowEvents(ctx, &es)
	require.Nil(t, err)
	require.Equal(t, 3, len(events))
	require.Equal(t, "update AppInst", events[0].Name)
	require.Equal(t, "cloudlet online", events[1].Name)
	require.Equal(t, "test start", events[2].Name)

	//
	// ---------------------------------------------------
	// Test failures
	// ---------------------------------------------------
	//

	// test error check for -, should be ok for keywords
	es = search
	es.Match.Names = []string{"create-App*", "delete App*"}
	events, err = nodeMgr.ShowEvents(ctx, &es)
	require.Nil(t, err)
	require.Equal(t, 1, len(events))
	require.Equal(t, "delete AppInst", events[0].Name)
	// test error check for - in text
	es = search
	es.Match.Tags = map[string]string{
		"somekey": "bad-wildcard*",
	}
	_, err = nodeMgr.ShowEvents(ctx, &es)
	require.NotNil(t, err)

	//
	// ---------------------------------------------------
	// Check kafka events
	// ---------------------------------------------------
	//

	require.Equal(t, 2, len(kmsgs))
	// async producer may produce messages in either order
	if kmsgs[0].Name == expKmsg1.Name {
		require.Equal(t, expKmsg1, kmsgs[0])
		require.Equal(t, expKmsg2, kmsgs[1])
	} else {
		require.Equal(t, expKmsg1, kmsgs[1])
		require.Equal(t, expKmsg2, kmsgs[0])
	}
}

func waitEvents(t *testing.T, nm *SvcNodeMgr, num uint64) {
	for ii := 0; ii < 20; ii++ {
		fmt.Printf("waitEvents %d: %d\n", ii, nm.ESWroteEvents)
		if nm.ESWroteEvents == num {
			break
		}
		time.Sleep(1000 * time.Millisecond)
	}
	require.Equal(t, num, nm.ESWroteEvents)
}

func waitSpans(t *testing.T, num int64) {
	name := "jaeger.tracer.reporter_spans|result=ok"
	counters := map[string]int64{}
	for ii := 0; ii < 20; ii++ {
		counters, _ = log.ReporterMetrics.Snapshot()
		fmt.Printf("waitSpans %d: %v\n", ii, counters)
		if counters[name] == num {
			break
		}
		time.Sleep(time.Second)
	}
	require.Equal(t, num, counters[name])
}
