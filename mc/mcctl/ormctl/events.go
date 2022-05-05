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

package ormctl

import (
	fmt "fmt"
	"strings"

	"github.com/edgexr/edge-cloud/cloudcommon/node"
	edgeproto "github.com/edgexr/edge-cloud/edgeproto"
	"github.com/mobiledgex/jaeger/plugin/storage/es/spanstore/dbmodel"
)

const (
	EventsGroup = "Events"
	SpansGroup  = "Spans"
)

func init() {
	cmds := []*ApiCommand{&ApiCommand{
		Name:         "ShowEvents",
		Use:          "show",
		Short:        "Show events and audit events",
		OptionalArgs: strings.Join(EventsOptionalArgs, " "),
		AliasArgs:    strings.Join(EventsAliasArgs, " "),
		Comments:     addRegionComment(EventsComments),
		SpecialArgs:  &EventsSpecialArgs,
		ReqData:      &node.EventSearch{},
		ReplyData:    &[]node.EventData{},
		Path:         "/auth/events/show",
	}, &ApiCommand{
		Name:         "ShowOldEvents",
		Use:          "showold",
		Short:        "Show events and audit events (for old events format)",
		OptionalArgs: strings.Join(EventsOptionalArgs, " "),
		AliasArgs:    strings.Join(EventsAliasArgs, " "),
		Comments:     addRegionComment(EventsComments),
		SpecialArgs:  &EventsSpecialArgs,
		ReqData:      &node.EventSearch{},
		ReplyData:    &[]node.EventDataOld{},
		Path:         "/auth/events/show",
	}, &ApiCommand{
		Name:         "FindEvents",
		Use:          "find",
		Short:        "Find events and audit events, results sorted by relevance",
		OptionalArgs: strings.Join(EventsOptionalArgs, " "),
		AliasArgs:    strings.Join(EventsAliasArgs, " "),
		Comments:     addRegionComment(EventsComments),
		SpecialArgs:  &EventsSpecialArgs,
		ReqData:      &node.EventSearch{},
		ReplyData:    &[]node.EventData{},
		Path:         "/auth/events/find",
	}, &ApiCommand{
		Name:         "EventTerms",
		Use:          "terms",
		Short:        "Show aggregated events terms",
		OptionalArgs: strings.Join(EventsOptionalArgs, " "),
		AliasArgs:    strings.Join(EventsAliasArgs, " "),
		Comments:     addRegionComment(EventsComments),
		SpecialArgs:  &EventsSpecialArgs,
		ReqData:      &node.EventSearch{},
		ReplyData:    &node.EventTerms{},
		Path:         "/auth/events/terms",
	}}
	AllApis.AddGroup(EventsGroup, "Search events and audit events", cmds)

	cmds = []*ApiCommand{&ApiCommand{
		Name:         "SpanTerms",
		Use:          "terms",
		Short:        "Show aggregated spans terms",
		OptionalArgs: strings.Join(ShowSpansOptionalArgs, " "),
		AliasArgs:    strings.Join(ShowSpansAliasArgs, " "),
		Comments:     addRegionComment(ShowSpansComments),
		SpecialArgs:  &ShowSpansSpecialArgs,
		ReqData:      &node.SpanSearch{},
		ReplyData:    &node.SpanTerms{},
		Path:         "/auth/spans/terms",
	}, &ApiCommand{
		Name:         "ShowSpans",
		Use:          "show",
		Short:        "Search spans",
		OptionalArgs: strings.Join(ShowSpansOptionalArgs, " "),
		AliasArgs:    strings.Join(ShowSpansAliasArgs, " "),
		Comments:     addRegionComment(ShowSpansComments),
		SpecialArgs:  &ShowSpansSpecialArgs,
		ReqData:      &node.SpanSearch{},
		ReplyData:    &[]node.SpanOutCondensed{},
		Path:         "/auth/spans/show",
	}, &ApiCommand{
		Name:         "ShowSpansVerbose",
		Use:          "showverbose",
		Short:        "Search spans, output raw format",
		OptionalArgs: strings.Join(ShowSpansOptionalArgs, " "),
		AliasArgs:    strings.Join(ShowSpansAliasArgs, " "),
		Comments:     addRegionComment(ShowSpansComments),
		SpecialArgs:  &ShowSpansSpecialArgs,
		ReqData:      &node.SpanSearch{},
		ReplyData:    &[]dbmodel.Span{},
		Path:         "/auth/spans/showverbose",
	}}
	AllApis.AddGroup(SpansGroup, "Search spans", cmds)
}

var tagsComment = fmt.Sprintf("key=value tag, may be specified multiple times, key may include %s", strings.Join(edgeproto.AllKeyTags, ", "))

var EventsOptionalArgs = []string{
	"name",
	"org",
	"type",
	"region",
	"error",
	"tags",
	"failed",
	"notname",
	"notorg",
	"nottype",
	"notregion",
	"noterror",
	"nottags",
	"notfailed",
	"starttime",
	"endtime",
	"startage",
	"endage",
	"from",
	"limit",
}

var EventsAliasArgs = []string{
	"name=match.names",
	"org=match.orgs",
	"type=match.types",
	"region=match.regions",
	"error=match.error",
	"tags=match.tags",
	"failed=match.failed",
	"notname=notmatch.names",
	"notorg=notmatch.orgs",
	"nottype=notmatch.types",
	"notregion=notmatch.regions",
	"noterror=notmatch.error",
	"nottags=notmatch.tags",
	"notfailed=notmatch.failed",
	"starttime=timerange.starttime",
	"endtime=timerange.endtime",
	"startage=timerange.startage",
	"endage=timerange.endage",
}

var EventsComments = map[string]string{
	"name":      "name of the event, may be specified multiple times",
	"org":       "organization associated with the event, may be specified multiple times",
	"type":      `type of event, either "event" or "audit", may be specified multiple times`,
	"region":    "region for the event, may be specified multiple times",
	"error":     "any words in an error message",
	"tags":      tagsComment,
	"starttime": "absolute time of search range start (RFC3339)",
	"endtime":   "absolute time of search range end (RFC3339)",
	"startage":  "relative age from now of search range start (default 48h)",
	"endage":    "relative age from now of search range end (default 0)",
	"failed":    "specify true to find events with an error",
	"from":      "start offset if paging through results",
	"limit":     "number of results to return, either to limit or for paging results",
	"notname":   "name of the event to exclude, may be specified multiple times",
	"notorg":    "organization associated with the event to exclude, may be specified multiple times",
	"nottype":   `type of event, either "event" or "audit" to exclude, may be specified multiple times`,
	"notregion": "region for the event to exclude, may be specified multiple times",
	"noterror":  "any words in an error message to exclude",
	"nottags":   "any tags to exclude, see tags option",
	"notfailed": "specify true to find events without any error",
}

var EventsSpecialArgs = map[string]string{
	"match.names":      "StringArray",
	"match.orgs":       "StringArray",
	"match.types":      "StringArray",
	"match.regions":    "StringArray",
	"match.tags":       "StringToString",
	"notmatch.names":   "StringArray",
	"notmatch.orgs":    "StringArray",
	"notmatch.types":   "StringArray",
	"notmatch.regions": "StringArray",
	"notmatch.tags":    "StringToString",
}

var ShowSpansOptionalArgs = []string{
	"service",
	"operation",
	"hostname",
	"tagvalue",
	"tagkeyvalue",
	"logmsg",
	"logvalue",
	"logkeyvalue",
	"starttime",
	"endtime",
	"startage",
	"endage",
	"from",
	"limit",
	"searchbyrelevance",
}

var ShowSpansAliasArgs = []string{
	"service=match.services",
	"operation=match.operations",
	"hostname=match.hostnames",
	"tagvalue=match.tagvalues",
	"tagkeyvalue=match.tagkeyvalues",
	"logmsg=match.logmsgs",
	"logvalue=match.logvalues",
	"logkeyvalue=match.logkeyvalues",
	"notservice=notmatch.services",
	"notoperation=notmatch.operations",
	"nothostname=notmatch.hostnames",
	"nottagvalue=match.nottagvalues",
	"nottagkeyvalue=match.nottagkeyvalues",
	"notlogmsg=notmatch.logmsgs",
	"notlogvalue=notmatch.logvalues",
	"notlogkeyvalue=notmatch.logkeyvalues",
	"starttime=timerange.starttime",
	"endtime=timerange.endtime",
	"startage=timerange.startage",
	"endage=timerange.endage",
}

var ShowSpansComments = map[string]string{
	"service":           "name of the service: mc, controller, dme, etc., may be specified multiple times",
	"operation":         "name of the span operation, i.e. FindCloudlet, may be specified multiple times",
	"hostname":          "hostname of the container/VM running the service, may be specified multiple times",
	"tagvalue":          "tag value of any key, may be specified multiple times",
	"tagkeyvalue":       "tag key=value, may be specified multiple times",
	"logmsg":            "log message (first string arg to log.SpanLog), may be specified multiple times",
	"logvalue":          "log value of any key, may be specified multiple times, values longer than 256 chars cannot be searched",
	"logkeyvalue":       "log key=value, may be specified multiple times, values longer than 256 chars cannot be searched",
	"starttime":         "absolute time of search range start (RFC3339)",
	"endtime":           "absolute time of search range end (RFC3339)",
	"startage":          "relative age from now of search range start (default 48h)",
	"endage":            "relative age from now of search range end (default 0)",
	"from":              "start offset if paging through results",
	"limit":             "number of results to return, either to limit or for paging results",
	"searchbyrelevance": "search results by relevance instead of time",
}

var ShowSpansSpecialArgs = map[string]string{
	"match.services":        "StringArray",
	"match.operations":      "StringArray",
	"match.hostnames":       "StringArray",
	"match.tagvalues":       "StringArray",
	"match.tagkeyvalues":    "StringToString",
	"match.logmsgs":         "StringArray",
	"match.logvalues":       "StringArray",
	"match.logkeyvalues":    "StringToString",
	"notmatch.services":     "StringArray",
	"notmatch.operations":   "StringArray",
	"notmatch.hostnames":    "StringArray",
	"notmatch.tagvalues":    "StringArray",
	"notmatch.tagkeyvalues": "StringToString",
	"notmatch.logmsgs":      "StringArray",
	"notmatch.logvalues":    "StringArray",
	"notmatch.logkeyvalues": "StringToString",
}
