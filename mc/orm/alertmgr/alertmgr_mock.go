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

package alertmgr

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"testing"

	"github.com/go-openapi/strfmt"
	"github.com/jarcoal/httpmock"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud/cloudcommon"
	dme "github.com/edgexr/edge-cloud/d-match-engine/dme-proto"
	"github.com/edgexr/edge-cloud/edgeproto"

	//	open_api_models "github.com/prometheus/alertmanager/api/v2/models"
	// TODO - below is to replace the above for right now - once we update go and modules we can use prometheus directly
	open_api_models "github.com/edgexr/edge-cloud-infra/mc/orm/alertmgr/prometheus_structs/models"

	// alertmanager_config "github.com/prometheus/alertmanager/config"
	// TODO - below is to replace the above for right now - once we update go and modules we can use prometheus directly
	alertmanager_config "github.com/edgexr/edge-cloud-infra/mc/orm/alertmgr/prometheus_structs/config"

	//	"github.com/prometheus/common/model"
	// TODO - below is to replace the above for right now - once we update go and modules we can use prometheus directly
	model "github.com/edgexr/edge-cloud-infra/mc/orm/alertmgr/prometheus_structs/model"

	"github.com/stretchr/testify/require"
)

type AlertmanagerMock struct {
	addr            string
	configFile      string
	alerts          map[string]model.Alert
	receivers       []*alertmanager_config.Receiver
	route           *alertmanager_config.Route
	AlertPosts      int
	AlertGets       int
	ReceiversGets   int
	SilencesGets    int
	SilencesPosts   int
	SilencesDeletes int
	ConfigReloads   int
}

func NewAlertmanagerMock(addr string, cfg string) *AlertmanagerMock {
	alertMgr := AlertmanagerMock{}
	alertMgr.addr = addr
	alertMgr.alerts = make(map[string]model.Alert)
	alertMgr.configFile = cfg
	if err := alertMgr.readConfig(); err != nil {
		fmt.Printf("Error reading config file, %v\n", err)
		return nil
	}
	alertMgr.registerMockResponders()
	return &alertMgr
}

func (s *AlertmanagerMock) readConfig() error {
	amCfg, err := alertmanager_config.LoadFile(s.configFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	s.receivers = amCfg.Receivers
	s.route = amCfg.Route
	return nil
}

func (s *AlertmanagerMock) registerMockResponders() {
	// Create/Get Alerts
	s.registerCreateAlerts()
	s.registerGetAlerts()

	// Create/Delete/Get silences
	s.registerCreateSilences()
	s.registerGetSilences()
	s.registerDeleteSilences()

	// Get receivers
	s.registerGetReceivers()

	// Reload method
	s.registerConfigReload()

	// Base URL handler
	s.registerBaseUrl()
}

func (s *AlertmanagerMock) registerBaseUrl() {
	httpmock.RegisterResponder("GET", s.addr+"/",
		func(req *http.Request) (*http.Response, error) {
			return httpmock.NewStringResponse(200, "Success"), nil
		},
	)
	httpmock.RegisterResponder("GET", s.addr,
		func(req *http.Request) (*http.Response, error) {
			return httpmock.NewStringResponse(200, "Success"), nil
		},
	)
}

func (s *AlertmanagerMock) registerConfigReload() {
	httpmock.RegisterResponder("POST", s.addr+ReloadConfigApi,
		func(req *http.Request) (*http.Response, error) {
			err := s.readConfig()
			s.ConfigReloads++
			if err != nil {
				return httpmock.NewStringResponse(500, "Unable to read new configuration:"+err.Error()), nil
			}
			return httpmock.NewStringResponse(200, "Success"), nil
		},
	)
}

func (s *AlertmanagerMock) registerCreateAlerts() {
	httpmock.RegisterResponder("POST", s.addr+AlertApi,
		func(req *http.Request) (*http.Response, error) {
			alerts := []model.Alert{}
			err := json.NewDecoder(req.Body).Decode(&alerts)
			if err != nil {
				return httpmock.NewStringResponse(500, "Unable to decode JSON body"), nil
			}
			for _, alert := range alerts {
				// set of labels is the key
				key := alert.Labels.String()
				_, found := s.alerts[key]
				if !found {
					s.alerts[key] = alert
				}
			}
			s.AlertPosts++
			return httpmock.NewStringResponse(200, "Success"), nil
		},
	)
}

func (s *AlertmanagerMock) registerGetAlerts() {
	httpmock.RegisterResponder("GET", s.addr+AlertApi,
		func(req *http.Request) (*http.Response, error) {
			alerts := open_api_models.GettableAlerts{}
			for _, alert := range s.alerts {
				labels := open_api_models.LabelSet{}
				annotations := open_api_models.LabelSet{}
				for k, v := range alert.Labels {
					labels[string(k)] = string(v)
				}
				for k, v := range alert.Annotations {
					annotations[string(k)] = string(v)
				}

				start := strfmt.DateTime(alert.StartsAt)
				end := strfmt.DateTime(alert.EndsAt)

				alerts = append(alerts, &open_api_models.GettableAlert{
					Alert: open_api_models.Alert{
						Labels: labels,
					},
					Annotations: annotations,
					StartsAt:    &start,
					EndsAt:      &end,
				})
			}
			s.AlertGets++
			return httpmock.NewJsonResponse(200, alerts)
		},
	)
}

func (s *AlertmanagerMock) registerCreateSilences() {
	httpmock.RegisterResponder("POST", s.addr+SilenceApi,
		func(req *http.Request) (*http.Response, error) {
			// TODO
			s.SilencesPosts++
			return httpmock.NewStringResponse(200, "Success"), nil
		},
	)
}

func (s *AlertmanagerMock) registerDeleteSilences() {
	httpmock.RegisterResponder("DELETE", s.addr+SilenceApi,
		func(req *http.Request) (*http.Response, error) {
			// TODO
			s.SilencesDeletes++
			return httpmock.NewStringResponse(200, "Success"), nil
		},
	)
}

func (s *AlertmanagerMock) registerGetSilences() {
	httpmock.RegisterResponder("GET", s.addr+SilenceApi,
		func(req *http.Request) (*http.Response, error) {
			// TODO
			s.SilencesGets++
			return httpmock.NewStringResponse(200, "Success"), nil
		},
	)
}

func (s *AlertmanagerMock) registerGetReceivers() {
	httpmock.RegisterResponder("GET", s.addr+ReceiverApi,
		func(req *http.Request) (*http.Response, error) {
			names := []string{}
			for _, receiver := range s.receivers {
				names = append(names, receiver.Name)
			}
			s.ReceiversGets++
			return httpmock.NewJsonResponse(200, names)
		},
	)
}

func (s *AlertmanagerMock) verifyAlertCnt(t *testing.T, cnt int) {
	require.Equal(t, cnt, len(s.alerts))
}

// verify the receiver is present and return this receiver
func (s *AlertmanagerMock) findReceiver(receiver *ormapi.AlertReceiver) *alertmanager_config.Receiver {
	name := getAlertmgrReceiverName(receiver)
	for ii, rec := range s.receivers {
		if rec.Name == name {
			return s.receivers[ii]
		}
	}
	return nil
}

func (s *AlertmanagerMock) findRouteByReceiver(receiver *ormapi.AlertReceiver) *alertmanager_config.Route {
	name := getAlertmgrReceiverName(receiver)
	for ii, route := range s.route.Routes {
		if route.Receiver == name {
			return s.route.Routes[ii]
		}
	}
	return nil
}

// Convert alert into alertmanager alert and check
func (s *AlertmanagerMock) verifyAlertPresent(t *testing.T, alert *edgeproto.Alert) {
	labelSet := model.LabelSet{}
	for k, v := range alert.Labels {
		// Convert to string of integer
		if k == cloudcommon.AlertHealthCheckStatus {
			if tmp, err := strconv.ParseInt(v, 10, 32); err == nil {
				if statusVal, ok := dme.HealthCheck_CamelName[int32(tmp)]; ok {
					v = statusVal
				}
			}
		}
		labelSet[model.LabelName(k)] = model.LabelValue(v)
	}
	key := labelSet.String()
	_, found := s.alerts[key]
	require.True(t, found)
}

func (s *AlertmanagerMock) verifyReceiversCnt(t *testing.T, cnt int) {
	require.Equal(t, cnt, len(s.receivers))
}

func (s *AlertmanagerMock) resetCounters() {
	s.AlertPosts = 0
	s.AlertGets = 0
	s.SilencesDeletes = 0
	s.SilencesGets = 0
	s.SilencesPosts = 0
	s.ReceiversGets = 0
	s.ConfigReloads = 0
}
