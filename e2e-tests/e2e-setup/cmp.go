package e2esetup

import (
	"log"
	"sort"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cloudcommon/node"
	dmeproto "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/setup-env/util"
	ecutil "github.com/mobiledgex/edge-cloud/util"
)

// go-cmp Options
var IgnoreAdminRole = cmpopts.AcyclicTransformer("removeAdminRole", func(roles []ormapi.Role) []ormapi.Role {
	// remove automatically created admin role
	newroles := make([]ormapi.Role, 0)
	for _, role := range roles {
		if role.Username == "mexadmin" {
			continue
		}
		newroles = append(newroles, role)
	}
	sort.Slice(newroles, func(i, j int) bool {
		if newroles[i].Org < newroles[j].Org {
			return true
		}
		if newroles[i].Org > newroles[j].Org {
			return false
		}
		if newroles[i].Username < newroles[j].Username {
			return true
		}
		if newroles[i].Username > newroles[j].Username {
			return false
		}
		return newroles[i].Role < newroles[j].Role
	})
	return newroles
})

var IgnoreAdminUser = cmpopts.AcyclicTransformer("removeAdminUser", func(users []ormapi.User) []ormapi.User {
	// remove automatically created super user
	newusers := make([]ormapi.User, 0)
	for _, user := range users {
		if user.Name == "mexadmin" {
			continue
		}
		newusers = append(newusers, user)
	}
	return newusers
})

func CmpSortOrgs(a ormapi.Organization, b ormapi.Organization) bool {
	return a.Name < b.Name
}

//compares two yaml files for equivalence
//TODO need to handle different types of interfaces besides appdata, currently using
//that to sort
func CompareYamlFiles(firstYamlFile string, secondYamlFile string, fileType string) bool {
	var err1 error
	var err2 error
	var y1 interface{}
	var y2 interface{}
	copts := []cmp.Option{}

	if fileType == "mcdata" {
		var a1 ormapi.AllData
		var a2 ormapi.AllData

		err1 = util.ReadYamlFile(firstYamlFile, &a1)
		err2 = util.ReadYamlFile(secondYamlFile, &a2)
		copts = []cmp.Option{
			cmpopts.IgnoreTypes(time.Time{}, dmeproto.Timestamp{}),
			IgnoreAdminRole,
		}
		copts = append(copts, edgeproto.IgnoreTaggedFields("nocmp")...)
		copts = append(copts, edgeproto.CmpSortSlices()...)
		copts = append(copts, cmpopts.SortSlices(CmpSortOrgs))

		y1 = a1
		y2 = a2
	} else if fileType == "mcusers" {
		// remove roles
		var a1 []ormapi.User
		var a2 []ormapi.User

		err1 = util.ReadYamlFile(firstYamlFile, &a1)
		err2 = util.ReadYamlFile(secondYamlFile, &a2)

		copts = []cmp.Option{
			cmpopts.IgnoreTypes(time.Time{}),
			IgnoreAdminUser,
		}
		y1 = a1
		y2 = a2
	} else if fileType == "mcalerts" {
		// sort alerts
		var a1 []edgeproto.Alert
		var a2 []edgeproto.Alert

		err1 = util.ReadYamlFile(firstYamlFile, &a1)
		// If this is an empty file, treat it as an empty list
		if a1 == nil {
			a1 = []edgeproto.Alert{}
		}
		err2 = util.ReadYamlFile(secondYamlFile, &a2)
		// If this is an empty file, treat it as an empty list
		if a2 == nil {
			a2 = []edgeproto.Alert{}
		}

		copts = []cmp.Option{
			cmpopts.IgnoreTypes(time.Time{}, dmeproto.Timestamp{}),
			cmpopts.SortSlices(func(a edgeproto.Alert, b edgeproto.Alert) bool {
				return a.GetKey().GetKeyString() < b.GetKey().GetKeyString()
			}),
		}
		copts = append(copts, edgeproto.IgnoreAlertFields("nocmp"))
		y1 = a1
		y2 = a2
	} else if fileType == "mcaudit" {
		var a1 []ormapi.AuditResponse
		var a2 []ormapi.AuditResponse

		err1 = util.ReadYamlFile(firstYamlFile, &a1)
		err2 = util.ReadYamlFile(secondYamlFile, &a2)

		copts = []cmp.Option{
			cmpopts.IgnoreFields(ormapi.AuditResponse{}, "StartTime", "Duration", "TraceID"),
		}
		y1 = a1
		y2 = a2
	} else if fileType == "mcevents" {
		var a1 []EventSearch
		var a2 []EventSearch

		err1 = util.ReadYamlFile(firstYamlFile, &a1)
		err2 = util.ReadYamlFile(secondYamlFile, &a2)

		copts = []cmp.Option{
			cmpopts.IgnoreFields(node.EventData{}, "Timestamp", "Error"),
			cmpopts.IgnoreFields(ecutil.TimeRange{}, "StartTime", "EndTime", "StartAge", "EndAge"),
		}
		cmpFilterEventData(a1)
		cmpFilterEventData(a2)

		y1 = a1
		y2 = a2
	} else if fileType == "mceventterms" {
		var a1 []EventTerms
		var a2 []EventTerms

		err1 = util.ReadYamlFile(firstYamlFile, &a1)
		err2 = util.ReadYamlFile(secondYamlFile, &a2)

		cmpFilterEventTerms(a1)
		cmpFilterEventTerms(a2)

		copts = []cmp.Option{
			cmpopts.IgnoreFields(ecutil.TimeRange{}, "StartTime", "EndTime", "StartAge", "EndAge"),
			cmpopts.IgnoreFields(node.AggrVal{}, "DocCount"),
			cmpopts.IgnoreSliceElements(func(aggr node.AggrVal) bool {
				// no websocket equivalent so leads to
				// different results for EventTerms for cli vs api
				return aggr.Key == "/api/v1/auth/ctrl/AccessCloudlet"
			}),
		}
		y1 = a1
		y2 = a2
	} else if fileType == "mcspanterms" {
		var a1 []SpanTerms
		var a2 []SpanTerms

		err1 = util.ReadYamlFile(firstYamlFile, &a1)
		err2 = util.ReadYamlFile(secondYamlFile, &a2)

		cmpFilterSpanTerms(a1)
		cmpFilterSpanTerms(a2)

		copts = []cmp.Option{
			cmpopts.IgnoreFields(ecutil.TimeRange{}, "StartTime", "EndTime", "StartAge", "EndAge"),
			cmpopts.IgnoreFields(node.AggrVal{}, "DocCount"),
			// Ignore messages and tags because they will change often.
			// Hostnames will depend on local machine name so have to
			// ignore those too.
			cmpopts.IgnoreFields(node.SpanTerms{}, "Msgs", "Tags", "Hostnames"),
		}
		y1 = a1
		y2 = a2
	} else if fileType == "mcspans" {
		var a1 []SpanSearch
		var a2 []SpanSearch

		err1 = util.ReadYamlFile(firstYamlFile, &a1)
		err2 = util.ReadYamlFile(secondYamlFile, &a2)

		cmpFilterSpans(a1)
		cmpFilterSpans(a2)

		copts = []cmp.Option{
			cmpopts.IgnoreFields(node.SpanOutCondensed{}, "StartTime", "Duration", "TraceID", "SpanID", "Hostname"),
			cmpopts.IgnoreFields(ecutil.TimeRange{}, "StartTime", "EndTime", "StartAge", "EndAge"),
			cmpopts.IgnoreFields(node.SpanLogOut{}, "Timestamp", "Lineno"),
		}

		y1 = a1
		y2 = a2
	} else if fileType == "mcmetrics" {
		var a1 []MetricsCompare
		var a2 []MetricsCompare

		err1 = util.ReadYamlFile(firstYamlFile, &a1)
		err2 = util.ReadYamlFile(secondYamlFile, &a2)

		sort.Slice(a1, func(i, j int) bool {
			return a1[i].Name < a1[j].Name
		})
		sort.Slice(a2, func(i, j int) bool {
			return a2[i].Name < a2[j].Name
		})

		y1 = a1
		y2 = a2
	} else if fileType == "mcapimetrics" {
		var a1 []MetricsCompare
		var a2 []MetricsCompare

		err1 = util.ReadYamlFile(firstYamlFile, &a1)
		err2 = util.ReadYamlFile(secondYamlFile, &a2)

		sort.Slice(a1, func(i, j int) bool {
			return a1[i].Name < a1[j].Name
		})
		sort.Slice(a2, func(i, j int) bool {
			return a2[i].Name < a2[j].Name
		})

		cmpFilterApiMetricData(a1)
		cmpFilterApiMetricData(a2)

		y1 = a1
		y2 = a2
	} else if fileType == "emaildata" {
		// sort email headers
		var a1 []MailDevEmail
		var a2 []MailDevEmail

		err1 = util.ReadYamlFile(firstYamlFile, &a1)
		// If this is an empty file, treat it as an empty list
		if a1 == nil {
			a1 = []MailDevEmail{}
		}
		err2 = util.ReadYamlFile(secondYamlFile, &a2)
		// If this is an empty file, treat it as an empty list
		if a2 == nil {
			a2 = []MailDevEmail{}
		}
		sort.Slice(a1, func(i, j int) bool {
			if a1[i].Text == a1[j].Text {
				return a1[i].Headers.Subject < a1[j].Headers.Subject
			}
			return a1[i].Text < a1[j].Text
		})
		sort.Slice(a2, func(i, j int) bool {
			if a2[i].Text == a2[j].Text {
				return a2[i].Headers.Subject < a2[j].Headers.Subject
			}
			return a2[i].Text < a2[j].Text
		})

		y1 = a1
		y2 = a2
	} else if fileType == "slackdata" {
		// sort email headers
		var a1 []TestSlackMsg
		var a2 []TestSlackMsg

		err1 = util.ReadYamlFile(firstYamlFile, &a1)
		// If this is an empty file, treat it as an empty list
		if a1 == nil {
			a1 = []TestSlackMsg{}
		}
		err2 = util.ReadYamlFile(secondYamlFile, &a2)
		// If this is an empty file, treat it as an empty list
		if a2 == nil {
			a2 = []TestSlackMsg{}
		}
		sort.Slice(a1, func(i, j int) bool {
			if len(a1[i].Attachments) < 1 {
				return false
			}
			if len(a1[j].Attachments) < 1 {
				return true
			}
			return a1[i].Attachments[0].Title < a1[j].Attachments[0].Title
		})
		sort.Slice(a2, func(i, j int) bool {
			if len(a2[i].Attachments) < 1 {
				return false
			}
			if len(a2[j].Attachments) < 1 {
				return true
			}
			return a2[i].Attachments[0].Title < a2[j].Attachments[0].Title
		})

		y1 = a1
		y2 = a2
	} else if fileType == "pagerdutydata" {
		// sort email headers
		var a1 []TestPagerDutyEvent
		var a2 []TestPagerDutyEvent

		err1 = util.ReadYamlFile(firstYamlFile, &a1)
		// If this is an empty file, treat it as an empty list
		if a1 == nil {
			a1 = []TestPagerDutyEvent{}
		}
		err2 = util.ReadYamlFile(secondYamlFile, &a2)
		// If this is an empty file, treat it as an empty list
		if a2 == nil {
			a2 = []TestPagerDutyEvent{}
		}
		sort.Slice(a1, func(i, j int) bool {
			return a1[i].Payload.Summary < a1[j].Payload.Summary
		})
		sort.Slice(a2, func(i, j int) bool {
			return a2[i].Payload.Summary < a2[j].Payload.Summary
		})

		y1 = a1
		y2 = a2
	} else if fileType == "mcstream" {
		var a1 AllStreamOutData
		var a2 AllStreamOutData

		err1 = util.ReadYamlFile(firstYamlFile, &a1)
		err2 = util.ReadYamlFile(secondYamlFile, &a2)
		copts = []cmp.Option{
			cmpopts.IgnoreTypes(time.Time{}, dmeproto.Timestamp{}),
			IgnoreAdminRole,
		}
		copts = append(copts, edgeproto.IgnoreTaggedFields("nocmp")...)
		copts = append(copts, edgeproto.CmpSortSlices()...)
		copts = append(copts, cmpopts.SortSlices(CmpSortOrgs))

		y1 = a1
		y2 = a2
	} else {
		return util.CompareYamlFiles(firstYamlFile,
			secondYamlFile, fileType)
	}

	util.PrintStepBanner("running compareYamlFiles")
	log.Printf("Comparing yamls: %v  %v\n", firstYamlFile, secondYamlFile)

	if err1 != nil {
		log.Printf("Error in reading yaml file %v -- %v\n", firstYamlFile, err1)
		return false
	}
	if err2 != nil {
		log.Printf("Error in reading yaml file %v -- %v\n", secondYamlFile, err2)
		return false
	}

	if !cmp.Equal(y1, y2, copts...) {
		log.Println("Comparison fail")
		log.Printf(cmp.Diff(y1, y2, copts...))
		return false
	}
	log.Println("Comparison success")
	return true
}

func cmpFilterEventData(data []EventSearch) {
	for ii := 0; ii < len(data); ii++ {
		for jj := 0; jj < len(data[ii].Results); jj++ {
			event := &data[ii].Results[jj]
			// Delete incomparable data from tags/data.
			// Unfortunately request cannot be compared
			// because the json generated from cli comes
			// from a map, and from api comes from a struct,
			// and end up being formatted differently.
			ignoreMapStringVal(event.Mtags, "duration")
			ignoreMapStringVal(event.Mtags, "traceid")
			ignoreMapStringVal(event.Mtags, "spanid")
			ignoreMapStringVal(event.Mtags, "hostname")
			ignoreMapStringVal(event.Mtags, "lineno")
			ignoreMapStringVal(event.Mtags, "request")
			ignoreMapStringVal(event.Mtags, "response")
		}
	}
}

func cmpFilterSpans(data []SpanSearch) {
	for ii := 0; ii < len(data); ii++ {
		for jj := 0; jj < len(data[ii].Results); jj++ {
			out := data[ii].Results[jj]
			ignoreMapVal(out.Tags, "client")
			ignoreMapVal(out.Tags, "lineno")
			ignoreMapVal(out.Tags, "peer")
			for _, log := range out.Logs {
				// remove values that change each run
				ignoreMapVal(log.KeyValues, "modRev")
				ignoreMapVal(log.KeyValues, "peer")
				ignoreMapVal(log.KeyValues, "peerAddr")
				ignoreMapVal(log.KeyValues, "cookie")
				ignoreMapVal(log.KeyValues, "expires")
				ignoreMapVal(log.KeyValues, "resp")
				ignoreMapVal(log.KeyValues, "rev")
				ignoreMapVal(log.KeyValues, "autoProvStats")
				ignoreMapVal(log.KeyValues, "stats count")
				ignoreMapVal(log.KeyValues, "stats last count")
			}
		}
	}
}

func cmpFilterApiMetricData(data []MetricsCompare) {
	for ii := 0; ii < len(data); ii++ {
		vals := data[ii].Values
		ignoreMapFloatVal(vals, "0s")
		ignoreMapFloatVal(vals, "5ms")
		ignoreMapFloatVal(vals, "10ms")
		ignoreMapFloatVal(vals, "25ms")
		ignoreMapFloatVal(vals, "50ms")
		ignoreMapFloatVal(vals, "100ms")
		ignoreMapFloatVal(vals, "errs")
		ignoreMapFloatVal(vals, "reqs")
	}
}

// This nils out map value so we can check that keys match
// between expected and actual, but ignore the actual values
// since the values may change or be inconsistent.
func ignoreMapVal(m map[string]interface{}, key string) {
	if _, found := m[key]; found {
		m[key] = nil
	}
}
func ignoreMapStringVal(m map[string]string, key string) {
	if _, found := m[key]; found {
		m[key] = ""
	}
}
func ignoreMapFloatVal(m map[string]float64, key string) {
	if _, found := m[key]; found {
		m[key] = 0
	}
}

type sortAggrVals []node.AggrVal

func (s sortAggrVals) Len() int           { return len(s) }
func (s sortAggrVals) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
func (s sortAggrVals) Less(i, j int) bool { return s[i].Key < s[j].Key }

func cmpFilterEventTerms(data []EventTerms) {
	for ii := 0; ii < len(data); ii++ {
		terms := data[ii].Terms
		if terms == nil {
			continue
		}
		for jj := 0; jj < len(terms.Names); jj++ {
			// cli runs /ws version of RunCommand which makes
			// it impossible to get the same results from both
			// api and cli EventTerms, so map ws one to normal one.
			if terms.Names[jj].Key == "/ws/api/v1/auth/ctrl/RunCommand" {
				terms.Names[jj].Key = "/api/v1/auth/ctrl/RunCommand"
			}
			if terms.Names[jj].Key == "/ws/api/v1/auth/ctrl/ShowLogs" {
				terms.Names[jj].Key = "/api/v1/auth/ctrl/ShowLogs"
			}
		}
		// output order depends on counts, which may
		// change over time or due to retries.
		// Since we're ignoring counts, change order to alphabetical.
		sort.Sort(sortAggrVals(terms.Names))
		sort.Sort(sortAggrVals(terms.Orgs))
		sort.Sort(sortAggrVals(terms.Types))
		sort.Sort(sortAggrVals(terms.Regions))
		sort.Sort(sortAggrVals(terms.TagKeys))
	}
}

func cmpFilterSpanTerms(data []SpanTerms) {
	for ii := 0; ii < len(data); ii++ {
		terms := data[ii].Terms
		if terms == nil {
			continue
		}
		sort.Sort(sortAggrVals(terms.Operations))
		sort.Sort(sortAggrVals(terms.Services))
		sort.Sort(sortAggrVals(terms.Hostnames))
		sort.Sort(sortAggrVals(terms.Msgs))
		sort.Sort(sortAggrVals(terms.Tags))
	}
}
