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

package edgeproto

import (
	"fmt"
	"time"

	"github.com/edgexr/edge-cloud-platform/pkg/objstore"
)

type SettingsKey string

// There is only one settings object allowed
var settingsKey = "settings"
var SettingsKeySingular = SettingsKey(settingsKey)

func (m SettingsKey) GetKeyString() string {
	return settingsKey
}

func (m *SettingsKey) Matches(o *SettingsKey) bool {
	return true
}

func (m SettingsKey) ValidateKey() error {
	return nil
}

func (m SettingsKey) NotFoundError() error {
	// n/a
	return nil
}

func (m SettingsKey) ExistsError() error {
	// n/a
	return nil
}

func (m SettingsKey) GetTags() map[string]string {
	return map[string]string{}
}

func (m *Settings) GetObjKey() objstore.ObjKey {
	return m.GetKey()
}

func (s *Settings) GetKey() *SettingsKey {
	return &SettingsKeySingular
}

func (s *Settings) GetKeyVal() SettingsKey {
	return SettingsKeySingular
}

func (s *Settings) SetKey(key *SettingsKey) {}

func SettingsKeyStringParse(str string, obj *Settings) {}

func (s *Settings) Validate(fmap objstore.FieldMap) error {
	dur0 := Duration(0)
	v := NewFieldValidator(SettingsAllFieldsStringMap)
	for _, f := range fmap.Fields() {
		switch f {
		case SettingsFieldShepherdMetricsCollectionInterval:
			v.CheckGT(f, s.ShepherdMetricsCollectionInterval, dur0)
		case SettingsFieldShepherdAlertEvaluationInterval:
			v.CheckGT(f, s.ShepherdAlertEvaluationInterval, dur0)
		case SettingsFieldShepherdMetricsScrapeInterval:
			v.CheckGT(f, s.ShepherdMetricsScrapeInterval, dur0)
		case SettingsFieldShepherdHealthCheckRetries:
			v.CheckGT(f, s.ShepherdHealthCheckRetries, int32(0))
		case SettingsFieldShepherdHealthCheckInterval:
			v.CheckGT(f, s.ShepherdHealthCheckInterval, dur0)
		case SettingsFieldAutoDeployIntervalSec:
			v.CheckGT(f, s.AutoDeployIntervalSec, float64(0))
		case SettingsFieldAutoDeployOffsetSec:
			v.CheckGTE(f, s.AutoDeployOffsetSec, float64(0))
		case SettingsFieldAutoDeployMaxIntervals:
			v.CheckGT(f, s.AutoDeployMaxIntervals, uint32(0))
		case SettingsFieldCreateAppInstTimeout:
			v.CheckGT(f, s.CreateAppInstTimeout, dur0)
		case SettingsFieldUpdateAppInstTimeout:
			v.CheckGT(f, s.UpdateAppInstTimeout, dur0)
		case SettingsFieldDeleteAppInstTimeout:
			v.CheckGT(f, s.DeleteAppInstTimeout, dur0)
		case SettingsFieldCreateClusterInstTimeout:
			v.CheckGT(f, s.CreateClusterInstTimeout, dur0)
		case SettingsFieldUpdateClusterInstTimeout:
			v.CheckGT(f, s.UpdateClusterInstTimeout, dur0)
		case SettingsFieldDeleteClusterInstTimeout:
			v.CheckGT(f, s.DeleteClusterInstTimeout, dur0)
		case SettingsFieldCreateCloudletTimeout:
			v.CheckGT(f, s.CreateCloudletTimeout, dur0)
		case SettingsFieldUpdateCloudletTimeout:
			v.CheckGT(f, s.UpdateCloudletTimeout, dur0)
		case SettingsFieldMasterNodeFlavor:
			// no validation
		case SettingsFieldMaxTrackedDmeClients:
			v.CheckGT(f, s.MaxTrackedDmeClients, int32(0))
		case SettingsFieldCloudletMaintenanceTimeout:
			v.CheckGT(f, s.CloudletMaintenanceTimeout, dur0)
		case SettingsFieldInfluxDbMetricsRetention:
			// no validation
		case SettingsFieldInfluxDbCloudletUsageMetricsRetention:
			// no validation
		case SettingsFieldInfluxDbDownsampledMetricsRetention:
			// no validation
		case SettingsFieldUpdateVmPoolTimeout:
			v.CheckGT(f, s.UpdateVmPoolTimeout, dur0)
		case SettingsFieldUpdateTrustPolicyTimeout:
			v.CheckGT(f, s.UpdateTrustPolicyTimeout, dur0)
		case SettingsFieldDmeApiMetricsCollectionInterval:
			v.CheckGT(f, s.DmeApiMetricsCollectionInterval, dur0)
		case SettingsFieldCleanupReservableAutoClusterIdletime:
			v.CheckGT(f, s.CleanupReservableAutoClusterIdletime, Duration(30*time.Second))
		case SettingsFieldAppinstClientCleanupInterval:
			v.CheckGT(f, s.AppinstClientCleanupInterval, Duration(2*time.Second))
		case SettingsFieldEdgeEventsMetricsContinuousQueriesCollectionIntervalsInterval:
			// no validation
		case SettingsFieldEdgeEventsMetricsContinuousQueriesCollectionIntervalsRetention:
			// no validation
		case SettingsFieldEdgeEventsMetricsCollectionInterval:
			v.CheckGT(f, s.EdgeEventsMetricsCollectionInterval, dur0)
		case SettingsFieldEdgeEventsMetricsContinuousQueriesCollectionIntervals:
			for _, val := range s.EdgeEventsMetricsContinuousQueriesCollectionIntervals {
				if v.CheckGT(f, val.Interval, dur0); v.err != nil {
					break
				}
				v.CheckGTE(f, val.Retention, dur0)
			}
		case SettingsFieldInfluxDbEdgeEventsMetricsRetention:
			// no validation
		case SettingsFieldLocationTileSideLengthKm:
			v.CheckGT(f, s.LocationTileSideLengthKm, int64(0))
		case SettingsFieldClusterAutoScaleAveragingDurationSec:
			v.CheckGT(f, s.ClusterAutoScaleAveragingDurationSec, int64(0))
		case SettingsFieldClusterAutoScaleRetryDelay:
			v.CheckGT(f, s.ClusterAutoScaleRetryDelay, dur0)
		case SettingsFieldAlertPolicyMinTriggerTime:
			v.CheckGT(f, s.AlertPolicyMinTriggerTime, dur0)
		case SettingsFieldDisableRateLimit:
			// no validation
		case SettingsFieldRateLimitMaxTrackedIps:
			v.CheckGT(f, s.RateLimitMaxTrackedIps, int64(0))
		case SettingsFieldResourceSnapshotThreadInterval:
			v.CheckGT(f, s.ResourceSnapshotThreadInterval, Duration(30*time.Second))
		case SettingsFieldPlatformHaInstanceActiveExpireTime:
			v.CheckGTE(f, s.PlatformHaInstanceActiveExpireTime, Duration(500*time.Millisecond))
		case SettingsFieldPlatformHaInstancePollInterval:
			v.CheckGT(f, s.PlatformHaInstancePollInterval, Duration(10*time.Millisecond))
		case SettingsFieldCcrmApiTimeout:
			v.CheckGT(f, s.CcrmApiTimeout, dur0)
		default:
			// If this is a setting field (and not "fields"), ensure there is an entry in the switch
			// above.  If no validation is to be done for a field, make an empty case entry
			ok := SettingsAllFieldsMap.Has(f)
			if ok {
				return fmt.Errorf("No validation set for settings field: %s - %s", v.fieldDesc[f], f)
			}
		}
	}
	return v.err
}

func GetDefaultSettings() *Settings {
	s := Settings{}
	// Set default values
	s.ShepherdMetricsCollectionInterval = Duration(5 * time.Second)
	s.ShepherdAlertEvaluationInterval = Duration(15 * time.Second)
	s.ShepherdMetricsScrapeInterval = Duration(15 * time.Second)
	s.ShepherdHealthCheckRetries = 3
	s.ShepherdHealthCheckInterval = Duration(5 * time.Second)
	s.AutoDeployIntervalSec = 300
	s.AutoDeployOffsetSec = 20
	s.AutoDeployMaxIntervals = 10
	s.CreateAppInstTimeout = Duration(30 * time.Minute)
	s.UpdateAppInstTimeout = Duration(30 * time.Minute)
	s.DeleteAppInstTimeout = Duration(20 * time.Minute)
	s.CreateClusterInstTimeout = Duration(30 * time.Minute)
	s.UpdateClusterInstTimeout = Duration(20 * time.Minute)
	s.DeleteClusterInstTimeout = Duration(20 * time.Minute)
	s.CreateCloudletTimeout = Duration(30 * time.Minute)
	s.UpdateCloudletTimeout = Duration(20 * time.Minute)
	s.MasterNodeFlavor = ""
	s.MaxTrackedDmeClients = 100
	s.CloudletMaintenanceTimeout = Duration(5 * time.Minute)
	s.UpdateVmPoolTimeout = Duration(20 * time.Minute)
	s.UpdateTrustPolicyTimeout = Duration(10 * time.Minute)
	s.DmeApiMetricsCollectionInterval = Duration(30 * time.Second)
	s.InfluxDbMetricsRetention = Duration(672 * time.Hour) // 28 days is a default
	s.CleanupReservableAutoClusterIdletime = Duration(30 * time.Minute)
	s.InfluxDbCloudletUsageMetricsRetention = Duration(8760 * time.Hour) // 1 year
	s.AppinstClientCleanupInterval = Duration(24 * time.Hour)            // 24 hours, dme's cookieExpiration
	s.LocationTileSideLengthKm = 2
	s.EdgeEventsMetricsCollectionInterval = Duration(1 * time.Hour)  // Collect every hour
	s.InfluxDbEdgeEventsMetricsRetention = Duration(672 * time.Hour) // 28 days
	s.EdgeEventsMetricsContinuousQueriesCollectionIntervals = []*CollectionInterval{
		&CollectionInterval{
			Interval:  Duration(24 * time.Hour),  // Downsample into daily intervals
			Retention: Duration(168 * time.Hour), // Retain for a week
		},
		&CollectionInterval{
			Interval:  Duration(168 * time.Hour), // Downsample into weekly intervals
			Retention: Duration(672 * time.Hour), // Retain for a month
		},
		&CollectionInterval{
			Interval:  Duration(672 * time.Hour),      // Downsample into monthly intervals
			Retention: Duration(672 * 12 * time.Hour), // Retain for a year
		},
	}
	s.InfluxDbDownsampledMetricsRetention = Duration(8760 * time.Hour) // 1 year
	s.ClusterAutoScaleAveragingDurationSec = 60
	s.ClusterAutoScaleRetryDelay = Duration(time.Minute)
	s.AlertPolicyMinTriggerTime = Duration(30 * time.Second)
	s.DisableRateLimit = false
	s.RateLimitMaxTrackedIps = 10000
	s.ResourceSnapshotThreadInterval = Duration(60 * time.Minute)
	s.PlatformHaInstanceActiveExpireTime = Duration(1 * time.Second)
	s.PlatformHaInstancePollInterval = Duration(300 * time.Millisecond)
	s.CcrmApiTimeout = Duration(30 * time.Second)

	return &s
}

func (s *SettingsCache) Singular() *Settings {
	cur := Settings{}
	if s.Get(&SettingsKeySingular, &cur) {
		return &cur
	}
	return GetDefaultSettings()
}
