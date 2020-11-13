package ormctl

import (
	"strings"

	"github.com/mobiledgex/edge-cloud/cli"
	"github.com/mobiledgex/edge-cloud/cloudcommon/node"
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
