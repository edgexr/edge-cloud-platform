package ormctl

import (
	"strings"

	"github.com/mobiledgex/edge-cloud/cli"
	"github.com/mobiledgex/edge-cloud/cloudcommon/node"
	"github.com/mobiledgex/jaeger/plugin/storage/es/spanstore/dbmodel"
	"github.com/spf13/cobra"
)

func GetEventsCommand() *cobra.Command {
	cmds := []*cli.Command{&cli.Command{
		Use:          "show",
		OptionalArgs: strings.Join(EventsOptionalArgs, " "),
		AliasArgs:    strings.Join(EventsAliasArgs, " "),
		Comments:     addRegionComment(EventsComments),
		SpecialArgs:  &EventsSpecialArgs,
		ReqData:      &node.EventSearch{},
		ReplyData:    &[]node.EventData{},
		Run:          runRest("/auth/events/show"),
	}, &cli.Command{
		Use:          "showold",
		OptionalArgs: strings.Join(EventsOptionalArgs, " "),
		AliasArgs:    strings.Join(EventsAliasArgs, " "),
		Comments:     addRegionComment(EventsComments),
		SpecialArgs:  &EventsSpecialArgs,
		ReqData:      &node.EventSearch{},
		ReplyData:    &[]node.EventDataOld{},
		Run:          runRest("/auth/events/show"),
	}, &cli.Command{
		Use:          "find",
		OptionalArgs: strings.Join(EventsOptionalArgs, " "),
		AliasArgs:    strings.Join(EventsAliasArgs, " "),
		Comments:     addRegionComment(EventsComments),
		SpecialArgs:  &EventsSpecialArgs,
		ReqData:      &node.EventSearch{},
		ReplyData:    &[]node.EventData{},
		Run:          runRest("/auth/events/find"),
	}, &cli.Command{
		Use:          "terms",
		OptionalArgs: strings.Join(EventsOptionalArgs, " "),
		AliasArgs:    strings.Join(EventsAliasArgs, " "),
		Comments:     addRegionComment(EventsComments),
		SpecialArgs:  &EventsSpecialArgs,
		ReqData:      &node.EventSearch{},
		ReplyData:    &node.EventTerms{},
		Run:          runRest("/auth/events/terms"),
	}, &cli.Command{
		Use:          "spanterms",
		OptionalArgs: strings.Join(ShowSpansOptionalArgs, " "),
		AliasArgs:    strings.Join(ShowSpansAliasArgs, " "),
		Comments:     addRegionComment(ShowSpansComments),
		SpecialArgs:  &ShowSpansSpecialArgs,
		ReqData:      &node.SpanSearch{},
		ReplyData:    &node.SpanTerms{},
		Run:          runRest("/auth/spans/terms"),
	}, &cli.Command{
		Use:          "showspans",
		OptionalArgs: strings.Join(ShowSpansOptionalArgs, " "),
		AliasArgs:    strings.Join(ShowSpansAliasArgs, " "),
		Comments:     addRegionComment(ShowSpansComments),
		SpecialArgs:  &ShowSpansSpecialArgs,
		ReqData:      &node.SpanSearch{},
		ReplyData:    &[]node.SpanOutCondensed{},
		Run:          runRest("/auth/spans/show"),
	}, &cli.Command{
		Use:          "showspansverbose",
		OptionalArgs: strings.Join(ShowSpansOptionalArgs, " "),
		AliasArgs:    strings.Join(ShowSpansAliasArgs, " "),
		Comments:     addRegionComment(ShowSpansComments),
		SpecialArgs:  &ShowSpansSpecialArgs,
		ReqData:      &node.SpanSearch{},
		ReplyData:    &[]dbmodel.Span{},
		Run:          runRest("/auth/spans/showverbose"),
	}}
	return cli.GenGroup("events", "view or find events", cmds)
}

var EventsOptionalArgs = []string{
	"name",
	"org",
	"type",
	"region",
	"error",
	"tags",
	"starttime",
	"endtime",
	"startage",
	"endage",
	"failed",
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
