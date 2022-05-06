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

package e2esetup

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud/cloudcommon/node"
	dmeproto "github.com/edgexr/edge-cloud/d-match-engine/dme-proto"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/setup-env/util"
	edgetestutil "github.com/edgexr/edge-cloud/testutil"
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
func CompareYamlFiles(name string, actions []string, compare *util.CompareYaml) bool {
	return util.CompareYamlFiles(name, actions, compare)
}

func cmpFilterAllData(data *ormapi.AllData) {
	tx := util.NewTransformer()
	tx.AddSetZeroType(time.Time{}, dmeproto.Timestamp{})
	tx.AddSetZeroTypeField(ormapi.Federator{}, "Revision")
	tx.AddSetZeroTypeField(ormapi.Federation{}, "Revision")
	tx.AddSetZeroTypeField(ormapi.FederatorZone{}, "Revision")
	tx.AddSetZeroTypeField(ormapi.FederatedSelfZone{}, "Revision")
	tx.AddSetZeroTypeField(ormapi.FederatedPartnerZone{}, "Revision")
	tx.Apply(data)

	clearTags := map[string]struct{}{
		"nocmp":     struct{}{},
		"timestamp": struct{}{},
	}
	for ii := range data.RegionData {
		data.RegionData[ii].AppData.ClearTagged(clearTags)
	}
	data.Sort()
}

func cmpFilterAllDataNoIgnore(data *ormapi.AllData) {
	tx := util.NewTransformer()
	tx.AddSetZeroType(time.Time{}, dmeproto.Timestamp{})
	tx.AddSetZeroTypeField(edgeproto.AppInstRuntime{}, "ContainerIds")
	tx.AddSetZeroTypeField(edgeproto.CloudletInfo{}, "Controller")
	tx.Apply(data)
	data.Sort()
}

func cmpFilterUsers(data []ormapi.User) {
	tx := util.NewTransformer()
	tx.AddSetZeroType(time.Time{})
	tx.Apply(data)
}

func cmpFilterMetrics(data []MetricsCompare) {
	sort.Slice(data, func(i, j int) bool {
		return data[i].Name < data[j].Name
	})
}

type errReplace struct {
	re   *regexp.Regexp
	repl string
}

func cmpFilterErrs(data []edgetestutil.Err) {
	// remove random data from errors
	replacers := []errReplace{{
		re:   regexp.MustCompile("(, retry again in )([0-9.]+s)"),
		repl: "$1",
	}}
	for ii := range data {
		for ee := range replacers {
			data[ii].Msg = replacers[ee].re.ReplaceAllString(data[ii].Msg, replacers[ee].repl)
		}
	}
}

func cmpFilterErrsData(errActual []edgetestutil.Err, errExpected []edgetestutil.Err) error {
	if len(errExpected) != len(errActual) {
		return fmt.Errorf("The number of expected errors %d is not equal to the number of actual errors %d", len(errExpected), len(errActual))
	}
	for ii := 0; ii < len(errActual); ii++ {
		if !strings.Contains(errActual[ii].Msg, errExpected[ii].Msg) {
			return fmt.Errorf("Expected error \"%s\" is not a substring of actual error \"%s\"", errExpected[ii].Msg, errActual[ii].Msg)
		}
		errExpected[ii].Msg = ""
		errActual[ii].Msg = ""
	}
	return nil
}

func cmpFilterEventData(data []EventSearch) {
	tx := util.NewTransformer()
	tx.AddSetZeroTypeField(node.EventData{}, "Timestamp", "Error")
	tx.AddSetZeroTypeField(edgeproto.TimeRange{}, "StartTime", "EndTime", "StartAge", "EndAge")
	tx.Apply(data)
	for ii := 0; ii < len(data); ii++ {
		for jj := 0; jj < len(data[ii].Results); jj++ {
			event := &data[ii].Results[jj]
			// Delete incomparable data from tags/data.
			ignoreMapStringVal(event.Mtags, "duration")
			ignoreMapStringVal(event.Mtags, "traceid")
			ignoreMapStringVal(event.Mtags, "spanid")
			ignoreMapStringVal(event.Mtags, "hostname")
			ignoreMapStringVal(event.Mtags, "lineno")
			// The request json data needs to be sorted,
			// because the json in the api comes from the struct,
			// and the json from the cli comes from a map,
			// so fields appear in different order.
			if req, ok := event.Mtags["request"]; ok && req != "" {
				m := map[string]interface{}{}
				err := json.Unmarshal([]byte(req), &m)
				if err == nil {
					// Some empty fields show up when
					// marshaling from structs, but not
					// when building json map from cli args,
					// so remove any empty fields.
					omitEmptyJson(m)
					reqSorted, err := json.Marshal(m)
					if err == nil {
						event.Mtags["request"] = string(reqSorted)
					}
				}
			}
		}
	}
}

func omitEmptyJson(val interface{}) interface{} {
	if val == nil {
		return nil
	} else if m, ok := val.(map[string]interface{}); ok {
		for k, v := range m {
			newV := omitEmptyJson(v)
			if newV == nil {
				delete(m, k)
				continue
			}
			m[k] = newV
		}
		if len(m) == 0 {
			return nil
		}
		return m
	} else if arr, ok := val.([]interface{}); ok {
		newArr := make([]interface{}, 0)
		for _, sub := range arr {
			newSub := omitEmptyJson(sub)
			if newSub == nil {
				continue
			}
			newArr = append(newArr, newSub)
		}
		return newArr
	} else if str, ok := val.(string); ok {
		if str == "" {
			return nil
		}
		// check if it's time string at 0
		if t, err := time.Parse(time.RFC3339, str); err == nil && t.IsZero() {
			return nil
		}
		return str
	} else {
		if reflect.ValueOf(val).IsZero() {
			return nil
		}
		return val
	}
}

func cmpFilterSpans(data []SpanSearch) {
	tx := util.NewTransformer()
	tx.AddSetZeroTypeField(node.SpanOutCondensed{}, "StartTime", "Duration", "TraceID", "SpanID", "Hostname")
	tx.AddSetZeroTypeField(edgeproto.TimeRange{}, "StartTime", "EndTime", "StartAge", "EndAge")
	tx.AddSetZeroTypeField(node.SpanLogOut{}, "Timestamp", "Lineno")
	tx.Apply(data)
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

// filter out number of requests and errors as it changes with every loop
func cmpFilterApiMetricData(data []OptimizedMetricsCompare) {
	sort.Slice(data, func(i, j int) bool {
		return data[i].Name < data[j].Name
	})
	for ii := 0; ii < len(data); ii++ {
		for i := range data[ii].Values {
			if len(data[ii].Columns) < i+1 || data[ii].Columns[i] == "reqs" || data[ii].Columns[i] == "errs" {
				for j := range data[ii].Values[i] {
					data[ii].Values[i][j] = ""
				}
			}
		}
	}
}

func cmpFilterEmailData(data []MailDevEmail) {
	sort.Slice(data, func(i, j int) bool {
		if data[i].Text == data[j].Text {
			return data[i].Headers.Subject < data[j].Headers.Subject
		}
		return data[i].Text < data[j].Text
	})
}

func cmpFilterSlackData(data []TestSlackMsg) {
	sort.Slice(data, func(i, j int) bool {
		if len(data[i].Attachments) < 1 {
			return false
		}
		if len(data[j].Attachments) < 1 {
			return true
		}
		return data[i].Attachments[0].Title < data[j].Attachments[0].Title
	})
}

func cmpFilterPagerDutyData(data []TestPagerDutyEvent) {
	sort.Slice(data, func(i, j int) bool {
		return data[i].Payload.Summary < data[j].Payload.Summary
	})
}

func cmpFilterRateLimit(data []ormapi.McRateLimitSettings) {
	sort.Slice(data, func(i, j int) bool {
		if data[i].ApiName != data[j].ApiName {
			return data[i].ApiName < data[j].ApiName
		}
		return data[i].RateLimitTarget < data[j].RateLimitTarget
	})
}

func cmpFilterRateLimitFlow(data []ormapi.McRateLimitFlowSettings) {
	sort.Slice(data, func(i, j int) bool {
		if data[i].ApiName != data[j].ApiName {
			return data[i].ApiName < data[j].ApiName
		}
		return data[i].RateLimitTarget < data[j].RateLimitTarget
	})
}

func cmpFilterRateLimitMaxReqs(data []ormapi.McRateLimitMaxReqsSettings) {
	sort.Slice(data, func(i, j int) bool {
		if data[i].ApiName != data[j].ApiName {
			return data[i].ApiName < data[j].ApiName
		}
		return data[i].RateLimitTarget < data[j].RateLimitTarget
	})
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
	tx := util.NewTransformer()
	tx.AddSetZeroTypeField(node.AggrVal{}, "DocCount")
	tx.AddSetZeroTypeField(edgeproto.TimeRange{}, "StartTime", "EndTime", "StartAge", "EndAge")
	tx.Apply(data)
	for ii := 0; ii < len(data); ii++ {
		terms := data[ii].Terms
		if terms == nil {
			continue
		}
		newNames := []node.AggrVal{}
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
			// no websocket equivalent so leads to
			// different results for EventTerms for cli vs api
			if terms.Names[jj].Key == "/api/v1/auth/ctrl/AccessCloudlet" {
				continue
			}
			newNames = append(newNames, terms.Names[jj])
		}
		terms.Names = newNames
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
	tx := util.NewTransformer()
	tx.AddSetZeroTypeField(node.AggrVal{}, "DocCount")
	tx.AddSetZeroTypeField(edgeproto.TimeRange{}, "StartTime", "EndTime", "StartAge", "EndAge")
	// Ignore messages and tags because they will change often.
	// Hostnames will depend on local machine name so have to
	// ignore those too.
	tx.AddSetZeroTypeField(node.SpanTerms{}, "Msgs", "Tags", "Hostnames")
	tx.Apply(data)
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
