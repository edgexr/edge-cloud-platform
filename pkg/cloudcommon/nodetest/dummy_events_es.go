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

package nodetest

import (
	"encoding/json"
	fmt "fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/node"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/jarcoal/httpmock"
)

// This captures events meant to be sent to elastic search.
// This allows verification of events/audit logs in unit-tests,
// without needing to run elastic search.
// This does not capture jaeger logs.
type DummyEventsES struct {
	Events []*node.EventData
	Mux    sync.Mutex
}

// This assumes httpmock has already been initialized via:
// httpmock.Activate()
// defer httpmock.DeactiveAndReset()
func (s *DummyEventsES) InitHttpMock(addr string, mockTransport *httpmock.MockTransport) {
	s.Events = make([]*node.EventData, 0)

	matchAll := "=~" + addr + `/.*\z`
	//"mock.es/events-log-*/_search"
	matchSearch := "=~" + addr + `/.*/_search\z`

	// ignore searches(They are POSTS in opensearch)
	mockTransport.RegisterResponder("POST", matchSearch, s.HandleIgnore)
	// regexp match POST events
	mockTransport.RegisterResponder("POST", matchAll, s.Handle)
	//	mockTransport.RegisterResponder("GET", matchAll, s.HandleIgnore)
	// ignore PUT index template
	mockTransport.RegisterResponder("PUT", matchAll, s.HandleIgnore)
}

func (s *DummyEventsES) Handle(req *http.Request) (*http.Response, error) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		fmt.Printf("failed to read body from request %s: %v\n", req.URL.String(), err)
		return httpmock.NewStringResponse(400, "failed to read body"), nil
	}
	// data is {{index{}}}\ndata\n
	data := strings.Split(string(body), "\n")
	for ii := 0; ii < len(data); ii++ {
		// ignore first line, it's {index:{}}
		ii++
		if ii >= len(data) {
			continue
		}
		event := node.EventData{}
		err = json.Unmarshal([]byte(data[ii]), &event)
		if err != nil {
			fmt.Printf("failed to unmarshal data %s: %v\n", data[ii], err)
			continue
		}
		fmt.Printf("Received event %s type %s\n", event.Name, event.Type)
		s.Mux.Lock()
		s.Events = append(s.Events, &event)
		s.Mux.Unlock()
	}
	return httpmock.NewStringResponse(200, ""), nil
}

func (s *DummyEventsES) HandleIgnore(req *http.Request) (*http.Response, error) {
	fmt.Printf("DummyEventsES ignoring request %s\n", req.URL.String())
	return httpmock.NewStringResponse(200, `{"hits":{"total":{"value":0}}}`), nil
}

func (s *DummyEventsES) GetNumEvents() int {
	s.Mux.Lock()
	defer s.Mux.Unlock()
	return len(s.Events)
}

func (s *DummyEventsES) WaitLastEventMatches(startEvent int, matchFunc func(e *node.EventData) bool) bool {
	matches := false
	for ii := 0; ii < 60; ii++ {
		s.Mux.Lock()
		if len(s.Events) == 0 {
			s.Mux.Unlock()
			time.Sleep(100 * time.Millisecond)
			continue
		}
		log.DebugLog(log.DebugLevelInfo, "WaitLastEventMatches", "numEvents", len(s.Events))
		for _, event := range s.Events[startEvent:] {
			if matchFunc(event) {
				s.Mux.Unlock()
				return true
			}
		}
		s.Mux.Unlock()
		time.Sleep(100 * time.Millisecond)
	}
	return matches
}
