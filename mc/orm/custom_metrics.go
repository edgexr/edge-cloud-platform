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

package orm

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	prom_api "github.com/prometheus/client_golang/api"
	v1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/common/model"

	"github.com/labstack/echo"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud-infra/mc/ormutil"
	"github.com/edgexr/edge-cloud-infra/promutils"
	edgeproto "github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/util"
)

const (
	CustomMetricMeasurementName = "custom_metric"
)

var (
	// Anonymous appinst, just to get a list of tags
	validAppinstTags = map[string]struct{}{
		"app":         {},
		"apporg":      {},
		"appver":      {},
		"cluster":     {},
		"clusterorg":  {},
		"cloudlet":    {},
		"cloudletorg": {},
		"port":        {},
		"region":      {},
	}

	AggrFuncLabelSet = []string{"app", "appver", "apporg", "cluster", "clusterorg", "cloudlet", "cloudletorg", "region"}
)

func GetAppMetricsV2(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := ormutil.GetContext(c)
	if !strings.HasSuffix(c.Path(), "metrics/app/v2") {
		return fmt.Errorf("Unsupported path")
	}
	in := ormapi.RegionCustomAppMetrics{}
	_, err = ReadConn(c, &in)
	if err != nil {
		return err
	}

	cloudletList, err := checkPermissionsAndGetCloudletList(ctx, claims.Username, in.Region, []string{in.AppInst.AppKey.Organization},
		ResourceAppAnalytics, []edgeproto.CloudletKey{in.AppInst.ClusterInstKey.CloudletKey})
	if err != nil {
		return err
	}

	// validate all the passed in arguments
	if err = util.ValidateNames(in.AppInst.GetTags()); err != nil {
		return err
	}

	// Validate measurements and other parameters
	if err = validateAppMetricArgs(ctx, claims.Username, &in); err != nil {
		return err
	}

	settings, err := getSettings(ctx, in.Region)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Unable to get metrics settings for region %v - error is %s", in.Region, err.Error())
	}
	timeRange := getPromTimeRange(&in, settings)

	query := getPromAppQuery(&in, cloudletList)
	metric := getMetricName(&in)
	resp, err := thanosProxy(ctx, metric, in.Region, query, timeRange)
	if err != nil {
		return err
	}
	return ormutil.SetReply(c, resp)
}

// if this is one of the pre-built named queries
func isNamedQuery(measurement string) bool {
	switch measurement {
	case "connections":
		return true
	default:
		return false
	}
}

// How to call the metric in the returned data
func getMetricName(obj *ormapi.RegionCustomAppMetrics) string {
	if isNamedQuery(obj.Measurement) {
		return obj.Measurement
	}
	// "custom_metric" for free form query
	return CustomMetricMeasurementName
}

func validateAppMetricArgs(ctx context.Context, username string, obj *ormapi.RegionCustomAppMetrics) error {
	if obj == nil {
		return fmt.Errorf("Invalid region app metrics object")
	}

	if obj.Measurement == "" {
		return fmt.Errorf("Measurement is required")
	}

	if obj.Region == "" {
		return fmt.Errorf("Region is required")
	}

	emptyMetrics := ormapi.MetricsCommon{}
	// We don't need to validate timestamps if it's empty, as for prom query we have a
	// slightly different logic for handling empty timestamps - return just the last element
	if obj.MetricsCommon != emptyMetrics {
		if err := validateAndResolvePrometheusMetricsCommon(&obj.MetricsCommon); err != nil {
			return err
		}
	}

	switch obj.Measurement {
	case "connections":
		// only "sum" is supported currently
		if obj.AggrFunction != "" && obj.AggrFunction != "sum" {
			return fmt.Errorf("Only \"sum\" aggregation function is supported")
		}
		// validate port is an int
		if obj.Port != "" {
			if _, err := strconv.ParseUint(obj.Port, 10, 64); err != nil {
				return fmt.Errorf("Port must be an interger - %s", obj.Port)
			}
		}
	default:
		// free-form queries are only allowed for admin for now
		if !isAdmin(ctx, username) {
			log.SpanLog(ctx, log.DebugLevelInfo, "Only admin is allowed to run free-form queries", "query", obj.Measurement)
			return echo.ErrForbidden
		}
		// for free form metrics, only measurements should be allowed
		if obj.Port != "" {
			return fmt.Errorf("Only \"connections\" measurement supports specifying port")
		}
		if obj.AggrFunction != "" {
			return fmt.Errorf("Only \"connections\" measurement supports aggregate function")
		}
	}
	return nil
}

func getPromLabelsFromAppInstKey(appInstKey *edgeproto.AppInstKey) []string {
	labelFilters := []string{}
	if appInstKey == nil {
		return labelFilters
	}
	if appInstKey.AppKey.Name != "" {
		labelFilters = append(labelFilters, `app="`+appInstKey.AppKey.Name+`"`)
	}
	if appInstKey.AppKey.Organization != "" {
		labelFilters = append(labelFilters, `apporg="`+appInstKey.AppKey.Organization+`"`)
	}
	if appInstKey.AppKey.Version != "" {
		labelFilters = append(labelFilters, `appver="`+appInstKey.AppKey.Version+`"`)
	}
	if appInstKey.ClusterInstKey.ClusterKey.Name != "" {
		labelFilters = append(labelFilters, `cluster="`+appInstKey.ClusterInstKey.ClusterKey.Name+`"`)
	}
	if appInstKey.ClusterInstKey.Organization != "" {
		labelFilters = append(labelFilters, `clusterorg="`+appInstKey.ClusterInstKey.Organization+`"`)
	}
	if appInstKey.ClusterInstKey.CloudletKey.Name != "" {
		labelFilters = append(labelFilters, `cloudlet="`+appInstKey.ClusterInstKey.CloudletKey.Name+`"`)
	}
	if appInstKey.ClusterInstKey.CloudletKey.Organization != "" {
		labelFilters = append(labelFilters, `cloudletorg="`+appInstKey.ClusterInstKey.CloudletKey.Organization+`"`)
	}
	return labelFilters
}

func getPromTimeRange(obj *ormapi.RegionCustomAppMetrics, settings *edgeproto.Settings) *v1.Range {
	emptyMetrics := ormapi.MetricsCommon{}
	if obj.MetricsCommon == emptyMetrics {
		return nil
	}

	// call validation to be sure the required fields are populated
	if err := validateAndResolvePrometheusMetricsCommon(&obj.MetricsCommon); err != nil {
		return nil
	}

	minTimeDef := DefaultAppInstTimeWindow
	if settings != nil {
		minTimeDef = time.Duration(settings.DmeApiMetricsCollectionInterval)
	}
	timeDef := getTimeDefinitionDuration(&obj.MetricsCommon, minTimeDef)
	return &v1.Range{
		Start: obj.StartTime,
		End:   obj.EndTime,
		Step:  timeDef,
	}
}

// Generate expression with an aggregate function wrapping it
func wrapExpressionWithAggrFunc(query, aggrFunc string) string {
	return aggrFunc + " by(" +
		strings.Join(AggrFuncLabelSet, ",") + ")(" +
		query + ")"
}

// for now allow freeform metrics only for admin users
func getPromAppQuery(obj *ormapi.RegionCustomAppMetrics, cloudletList []string) string {
	var query string
	labelFilters := getPromLabelsFromAppInstKey(&obj.AppInst)
	if obj.Port != "" {
		labelFilters = append(labelFilters, `port="`+obj.Port+`"`)
	}
	labelFilter := strings.Join(labelFilters, ",")

	switch obj.Measurement {
	case "connections":
		query = promutils.PromQConnections + "{" + labelFilter + "}"
		// add aggregation function here
		if obj.AggrFunction != "" {
			query = wrapExpressionWithAggrFunc(query, obj.AggrFunction)
		}
	default:
		// Free form string - experimental(admin-only)
		// find all filters and splice in the appInst details
		queries := strings.Split(obj.Measurement, "{")
		if len(queries) == 1 {
			return obj.Measurement + "{" + labelFilter + "}"
		}
		// for each sub-query splice in the org filter for all the intermediate filters
		for ii := range queries {
			// for last one - don't do anything
			if ii == len(queries)-1 {
				break
			}
			queries[ii] = queries[ii] + "{" + labelFilter + ","
		}
		query = strings.Join(queries, "")
	}
	return query
}

// Dispatch prometheus query to a regional thanos collector
// Use prometheus client library to get a generic response and
// build AllMetrics type from model.Value interface
func thanosProxy(ctx context.Context, measurement, region, query string, timeRange *v1.Range) (*ormapi.AllMetrics, error) {
	var err error
	var warnings v1.Warnings
	var result model.Value
	var metricData ormapi.AllMetrics

	log.SpanLog(ctx, log.DebugLevelApi, "start Thanos api", "region", region, "query", query, "range", timeRange)
	defer log.SpanLog(ctx, log.DebugLevelApi, "finish Thanos api")

	addr, err := GetThanosUrl(ctx, region)
	if err != nil {
		return nil, err
	}

	client, err := prom_api.NewClient(prom_api.Config{
		Address: addr,
	})

	if err != nil {
		return nil, err
	}

	v1api := v1.NewAPI(client)
	thCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if timeRange == nil {
		result, warnings, err = v1api.Query(thCtx, query, time.Now())
	} else {
		result, warnings, err = v1api.QueryRange(thCtx, query, *timeRange)
	}
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelInfo, "Error querying Prometheus", "err", err, "query", query, "range", timeRange)
		return nil, err
	}
	if len(warnings) > 0 {
		log.SpanLog(ctx, log.DebugLevelInfo, "Got warnings querying prometheus", "warnings", warnings)
	}

	switch result.Type() {
	case model.ValMatrix:
		data, err := parsePrometheusMatrix(result, measurement)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfo, "Error parsing matrix", "err", err, "result", result.String())
			return nil, err
		}
		if data != nil {
			metricData.Data = append(metricData.Data, *data)
		}
	case model.ValVector:
		data, err := parsePrometheusVector(result, measurement)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfo, "Error parsing vector", "err", err, "result", result.String())
			return nil, err
		}
		if data != nil {
			metricData.Data = append(metricData.Data, *data)
		}
	default:
		return nil, fmt.Errorf("Unsupported result format: %s", result.Type().String())
	}
	return &metricData, nil
}

// For now Thanos URL is the same as influxDB, just different port
func GetThanosUrl(ctx context.Context, region string) (string, error) {
	ctrl, err := getControllerObj(ctx, region)
	if err != nil {
		return "", err
	}
	if ctrl.ThanosMetrics != "" {
		return ctrl.ThanosMetrics, nil
	}
	return "", fmt.Errorf("No monitoring DB address is configured for the region")
}

// Convert matrix type prometheus response into ormapi.MetricData struct
func parsePrometheusMatrix(value model.Value, measurement string) (*ormapi.MetricData, error) {
	data, ok := value.(model.Matrix)
	if !ok {
		return nil, fmt.Errorf("Unsupported result format: %s", value.Type().String())
	}

	if data.Len() == 0 {
		return nil, nil
	}

	metricData := ormapi.MetricData{
		Series: []ormapi.MetricSeries{},
	}
	for _, stream := range data {
		series := ormapi.MetricSeries{
			Name:   measurement,
			Tags:   map[string]string{},
			Values: make([][]interface{}, 0),
		}

		for k, v := range stream.Metric {
			if _, found := validAppinstTags[string(k)]; found {
				series.Tags[string(k)] = string(v)
			}
		}

		for _, v := range stream.Values {
			// validate the values
			if math.IsNaN(float64(v.Value)) {
				continue
			}
			tuple := []interface{}{
				float64(v.Value),
				float64(v.Timestamp.Unix() * 1000), // Timestamp truncates milliseconds
			}
			series.Values = append(series.Values, tuple)
		}
		metricData.Series = append(metricData.Series, series)
	}
	return &metricData, nil
}

// Convert vector type prometheus response into ormapi.MetricData struct
func parsePrometheusVector(value model.Value, measurement string) (*ormapi.MetricData, error) {
	data, ok := value.(model.Vector)
	if !ok {
		return nil, fmt.Errorf("Unsupported result format: %s", value.Type().String())
	}

	if data.Len() == 0 {
		return nil, nil
	}

	metricData := ormapi.MetricData{
		Series: []ormapi.MetricSeries{},
	}
	for _, sample := range data {
		series := ormapi.MetricSeries{
			Name:   measurement,
			Tags:   map[string]string{},
			Values: make([][]interface{}, 0),
		}

		for k, v := range sample.Metric {
			if _, found := validAppinstTags[string(k)]; found {
				series.Tags[string(k)] = string(v)
			}
		}
		if math.IsNaN(float64(sample.Value)) {
			continue
		}
		tuple := []interface{}{
			float64(sample.Value),
			float64(sample.Timestamp.Unix() * 1000), // Timestamp truncates milliseconds
		}
		series.Values = append(series.Values, tuple)
		metricData.Series = append(metricData.Series, series)
	}
	return &metricData, nil
}
