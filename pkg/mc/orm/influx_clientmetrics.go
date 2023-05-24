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
	"bytes"
	fmt "fmt"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"

	influxq "github.com/edgexr/edge-cloud-platform/cmd/controller/influxq_client"

	edgeproto "github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
)

var devInfluxClientMetricsDBTemplate *template.Template
var operatorInfluxClientMetricsDBTemplate *template.Template

type influxClientMetricsQueryArgs struct {
	// Query args
	metricsCommonQueryArgs
	Selector       string
	Measurement    string
	AppInstName    string
	AppInstOrg     string
	AppName        string
	AppOrg         string
	AppVersion     string
	ClusterName    string
	ClusterOrg     string
	CloudletName   string
	CloudletList   string
	CloudletOrg    string
	CloudletFedOrg string
	// ClientApi metric query args
	Method           string
	FoundCloudlet    string
	FoundCloudletOrg string
	// ClientAppUsage and ClientCloudletUsage metric query args
	DeviceCarrier   string
	DataNetworkType string
	DeviceModel     string
	DeviceOs        string
	LocationTile    string
	TagSet          string
}

// ClientApiUsageTags is DME metrics
var ClientApiUsageTags = []string{
	strconv.Quote(edgeproto.AppKeyTagName),
	strconv.Quote(edgeproto.AppKeyTagOrganization),
	strconv.Quote(edgeproto.AppKeyTagVersion),
	strconv.Quote(edgeproto.CloudletKeyTagName),
	strconv.Quote(edgeproto.CloudletKeyTagOrganization),
	strconv.Quote(cloudcommon.MetricTagDmeId),
	strconv.Quote(cloudcommon.MetricTagMethod),
}

var ApiFields = []string{
	"\"reqs\"",
	"\"errs\"",
	"\"foundCloudlet\"",
	"\"foundOperator\"",
}

var ClientApiAggregationFunctions = map[string]string{
	"reqs":          "last(\"reqs\")",
	"errs":          "last(\"errs\")",
	"foundCloudlet": "last(\"foundCloudlet\")",
	"foundOperator": "last(\"foundOperator\")",
}

// Common key tags for DME Device and Latency measurements
var ClientAppUsageTags = []string{
	strconv.Quote(edgeproto.AppInstKeyTagName),
	strconv.Quote(edgeproto.AppInstKeyTagOrganization),
	strconv.Quote(edgeproto.AppKeyTagName),
	strconv.Quote(edgeproto.AppKeyTagVersion),
	strconv.Quote(edgeproto.AppKeyTagOrganization),
	strconv.Quote(edgeproto.CloudletKeyTagName),
	strconv.Quote(edgeproto.CloudletKeyTagOrganization),
	strconv.Quote(edgeproto.CloudletKeyTagFederatedOrganization),
}

var ClientCloudletUsageTags = []string{
	strconv.Quote(edgeproto.CloudletKeyTagName),
	strconv.Quote(edgeproto.CloudletKeyTagOrganization),
}

var ClientAppUsageLatencyTags = []string{
	strconv.Quote(cloudcommon.MetricTagLocationTile),
	strconv.Quote(cloudcommon.MetricTagDataNetworkType),
}

var ClientCloudletUsageLatencyTags = []string{
	strconv.Quote(cloudcommon.MetricTagLocationTile),
	strconv.Quote(cloudcommon.MetricTagDeviceCarrier),
	strconv.Quote(cloudcommon.MetricTagDataNetworkType),
}

var ClientAppUsageDeviceInfoTags = []string{
	strconv.Quote(cloudcommon.MetricTagDeviceOS),
	strconv.Quote(cloudcommon.MetricTagDeviceModel),
	strconv.Quote(cloudcommon.MetricTagDeviceCarrier),
	strconv.Quote(cloudcommon.MetricTagDataNetworkType),
}

var ClientCloudletUsageDeviceInfoTags = []string{
	strconv.Quote(cloudcommon.MetricTagDeviceOS),
	strconv.Quote(cloudcommon.MetricTagDeviceModel),
	strconv.Quote(cloudcommon.MetricTagDeviceCarrier),
	strconv.Quote(cloudcommon.MetricTagLocationTile),
}

var LatencyFields = []string{
	//"\"0ms\"", // TODO: make sure this is ms
	"\"0s\"",
	"\"5ms\"",
	"\"10ms\"",
	"\"25ms\"",
	"\"50ms\"",
	"\"100ms\"",
	"\"max\"",
	"\"min\"",
	"\"avg\"",
	"\"variance\"",
	"\"stddev\"",
	"\"numsamples\"",
}

var DeviceInfoFields = []string{
	"\"numsessions\"",
}

const (
	CLIENT_APIUSAGE      = "dme"
	CLIENT_APPUSAGE      = "clientappusage"
	CLIENT_CLOUDLETUSAGE = "clientcloudletusage"
)

var devInfluxClientMetricsDBT = fmt.Sprintf(`SELECT {{.Selector}} `+
	`from {{.Measurement}} WHERE`+
	`{{if .AppInstName}}{{.And}} "%s"='{{.AppInstName}}'{{end}}`+
	`{{if .AppInstOrg}}{{.And}} "%s"='{{.AppInstOrg}}'{{end}}`+
	`{{if .AppName}}{{.And}} "%s"='{{.AppName}}'{{end}}`+
	`{{if .AppOrg}}{{.And}} "%s"='{{.AppOrg}}'{{end}}`+
	`{{if .AppVersion}}{{.And}} "%s"='{{.AppVersion}}'{{end}}`+
	`{{if .ClusterName}}{{.And}} "%s"='{{.ClusterName}}'{{end}}`+
	`{{if .ClusterOrg}}{{.And}} "%s"='{{.ClusterOrg}}'{{end}}`+
	`{{if .CloudletName}}{{.And}} "%s"='{{.CloudletName}}'{{end}}`+
	`{{if .CloudletOrg}}{{.And}} "%s"='{{.CloudletOrg}}'{{end}}`+
	`{{if .CloudletFedOrg}}{{.And}} "%s"='{{.CloudletFedOrg}}'{{end}}`+
	`{{if .CloudletList}}{{.And}} ({{.CloudletList}}){{end}}`+
	`{{if .Method}}{{.And}} "%s"='{{.Method}}'{{end}}`+
	`{{if .DeviceCarrier}}{{.And}} "%s"='{{.DeviceCarrier}}'{{end}}`+
	`{{if .DataNetworkType}}{{.And}} "%s"='{{.DataNetworkType}}'{{end}}`+
	`{{if .DeviceOs}}{{.And}} "%s"='{{.DeviceOs}}'{{end}}`+
	`{{if .DeviceModel}}{{.And}} "%s"='{{.DeviceModel}}'{{end}}`+
	`{{if .LocationTile}}{{.And}} "%s"='{{.LocationTile}}'{{end}}`+
	`{{if .FoundCloudlet}}{{.And}} "%s"='{{.FoundCloudlet}}'{{end}}`+
	`{{if .FoundCloudletOrg}}{{.And}} "%s"='{{.FoundCloudletOrg}}'{{end}}`+
	`{{if .StartTime}}{{.And}} time >= '{{.StartTime}}'{{end}}`+
	`{{if .EndTime}}{{.And}} time <= '{{.EndTime}}'{{end}}`+
	`{{if or .TimeDefinition .TagSet}} group by {{end}}`+
	`{{if .TimeDefinition}}time({{.TimeDefinition}}),{{end}}{{.TagSet}}`+
	` order by time desc{{if ne .Limit 0}} limit {{.Limit}}{{end}}`,
	edgeproto.AppInstKeyTagName,
	edgeproto.AppInstKeyTagOrganization,
	edgeproto.AppKeyTagName,
	edgeproto.AppKeyTagOrganization,
	edgeproto.AppKeyTagVersion,
	edgeproto.ClusterKeyTagName,
	edgeproto.ClusterKeyTagOrganization,
	edgeproto.CloudletKeyTagName,
	edgeproto.CloudletKeyTagOrganization,
	edgeproto.CloudletKeyTagFederatedOrganization,
	cloudcommon.MetricTagMethod,
	cloudcommon.MetricTagDeviceCarrier,
	cloudcommon.MetricTagDataNetworkType,
	cloudcommon.MetricTagDeviceOS,
	cloudcommon.MetricTagDeviceModel,
	cloudcommon.MetricTagLocationTile,
	cloudcommon.MetricTagFoundCloudlet,
	cloudcommon.MetricTagFoundOperator)

var operatorInfluxClientMetricsDBT = fmt.Sprintf(`SELECT {{.Selector}} `+
	`from {{.Measurement}} WHERE`+
	`{{if .CloudletName}}{{.And}} "%s"='{{.CloudletName}}'{{end}}`+
	`{{if .CloudletOrg}}{{.And}} "%s"='{{.CloudletOrg}}'{{end}}`+
	`{{if .CloudletFedOrg}}{{.And}} "%s"='{{.CloudletFedOrg}}'{{end}}`+
	`{{if .DeviceCarrier}}{{.And}} "%s"='{{.DeviceCarrier}}'{{end}}`+
	`{{if .DataNetworkType}}{{.And}} "%s"='{{.DataNetworkType}}'{{end}}`+
	`{{if .DeviceOs}}{{.And}} "%s"='{{.DeviceOs}}'{{end}}`+
	`{{if .DeviceModel}}{{.And}} "%s"='{{.DeviceModel}}'{{end}}`+
	`{{if .LocationTile}}{{.And}} "%s"='{{.LocationTile}}'{{end}}`+
	`{{if .StartTime}}{{.And}} time >= '{{.StartTime}}'{{end}}`+
	`{{if .EndTime}}{{.And}} time <= '{{.EndTime}}'{{end}}`+
	`{{if or .TimeDefinition .TagSet}} group by {{end}}`+
	`{{if .TimeDefinition}}time({{.TimeDefinition}}),{{end}}{{.TagSet}}`+
	` order by time desc{{if ne .Limit 0}} limit {{.Limit}}{{end}}`,
	edgeproto.CloudletKeyTagName,
	edgeproto.CloudletKeyTagOrganization,
	edgeproto.CloudletKeyTagFederatedOrganization,
	cloudcommon.MetricTagDeviceCarrier,
	cloudcommon.MetricTagDataNetworkType,
	cloudcommon.MetricTagDeviceOS,
	cloudcommon.MetricTagDeviceModel,
	cloudcommon.MetricTagLocationTile)

var locationTileFormatMatch = regexp.MustCompile(`^[0-9-][0-9_.,-]+$`)

func init() {
	devInfluxClientMetricsDBTemplate = template.Must(template.New("influxquery").Parse(devInfluxClientMetricsDBT))
	operatorInfluxClientMetricsDBTemplate = template.Must(template.New("influxquery").Parse(operatorInfluxClientMetricsDBT))
}

func getInfluxClientMetricsQueryCmd(q *influxClientMetricsQueryArgs, tmpl *template.Template) string {
	buf := bytes.Buffer{}
	if err := tmpl.Execute(&buf, q); err != nil {
		log.DebugLog(log.DebugLevelApi, "Failed to run template", "tmpl", tmpl, "args", q, "error", err)
		return ""
	}
	return buf.String()
}

func validateMethodString(obj *ormapi.RegionClientApiUsageMetrics) error {
	switch obj.Method {
	case "RegisterClient":
		fallthrough
	case "VerifyLocation":
		if obj.CloudletKey.Name != "" ||
			obj.CloudletKey.Organization != "" {
			return fmt.Errorf("Cloudlet and Cloudlet org can be specified only for FindCloudlet or PlatformFindCloudlet")
		}
		return nil
	case "":
		fallthrough
	case "FindCloudlet":
		fallthrough
	case "PlatformFindCloudlet":
		return nil
	}
	return fmt.Errorf("Method is invalid, must be one of FindCloudlet,PlatformFindCloudlet,RegisterClient,VerifyLocation")
}

func ClientApiUsageMetricsQuery(obj *ormapi.RegionClientApiUsageMetrics, cloudletList []string, settings *edgeproto.Settings) string {
	// get time definition
	minTimeDef := DefaultClientUsageTimeWindow
	if settings != nil {
		minTimeDef = time.Duration(settings.DmeApiMetricsCollectionInterval)
	}
	definition := getTimeDefinitionDuration(&obj.MetricsCommon, minTimeDef)
	arg := influxClientMetricsQueryArgs{
		Selector:         getClientMetricsSelector(obj.Selector, CLIENT_APIUSAGE, definition, ClientApiAggregationFunctions),
		Measurement:      fmt.Sprintf("%q", getMeasurementString(obj.Selector, CLIENT_APIUSAGE)),
		AppName:          obj.AppKey.Name,
		AppOrg:           obj.AppKey.Organization,
		AppVersion:       obj.AppKey.Version,
		CloudletList:     generateDmeApiUsageCloudletList(cloudletList),
		CloudletName:     obj.DmeCloudlet,
		CloudletOrg:      obj.DmeCloudletOrg,
		FoundCloudlet:    obj.CloudletKey.Name,
		FoundCloudletOrg: obj.CloudletKey.Organization,
		Method:           obj.Method,
		TagSet:           getTagSet(CLIENT_APIUSAGE, obj.Selector),
	}
	// set MetricsCommonQueryArgs
	fillMetricsCommonQueryArgs(&arg.metricsCommonQueryArgs, &obj.MetricsCommon, definition.String(), 0) // TODO: PULL MIN from settings
	return getInfluxClientMetricsQueryCmd(&arg, devInfluxClientMetricsDBTemplate)
}

func ClientAppUsageMetricsQuery(obj *ormapi.RegionClientAppUsageMetrics, cloudletList []string, settings *edgeproto.Settings) (cmd string, db string) {
	// get time definition
	minTimeDef := DefaultClientUsageTimeWindow
	if settings != nil {
		minTimeDef = time.Duration(settings.EdgeEventsMetricsCollectionInterval)
	}
	definition := getTimeDefinitionDuration(&obj.MetricsCommon, minTimeDef)
	// get measurement and db based on time definition
	var measurement string
	var functionMap map[string]string
	measurement, db, functionMap = getMeasurementAndDbAndMapFromClientUsageReq(settings, obj.Selector, definition)
	arg := influxClientMetricsQueryArgs{
		Selector:        getClientMetricsSelector(obj.Selector, CLIENT_APPUSAGE, definition, functionMap),
		Measurement:     measurement,
		AppInstName:     obj.AppInstKey.Name,
		AppInstOrg:      obj.AppInstKey.Organization,
		AppName:         obj.AppKey.Name,
		AppOrg:          obj.AppKey.Organization,
		AppVersion:      obj.AppKey.Version,
		CloudletList:    generateCloudletList(cloudletList),
		DeviceCarrier:   obj.DeviceCarrier,
		DataNetworkType: obj.DataNetworkType,
		DeviceOs:        obj.DeviceOs,
		DeviceModel:     obj.DeviceModel,
		LocationTile:    obj.LocationTile,
		TagSet:          getTagSet(CLIENT_APPUSAGE, obj.Selector),
	}
	// set MetricsCommonQueryArgs
	fillMetricsCommonQueryArgs(&arg.metricsCommonQueryArgs, &obj.MetricsCommon, definition.String(), 0) // TODO: PULL MIN from settings
	return getInfluxClientMetricsQueryCmd(&arg, devInfluxClientMetricsDBTemplate), db
}

func ClientCloudletUsageMetricsQuery(obj *ormapi.RegionClientCloudletUsageMetrics, settings *edgeproto.Settings) (cmd string, db string) {
	// get time definition
	minTimeDef := DefaultClientUsageTimeWindow
	if settings != nil {
		minTimeDef = time.Duration(settings.EdgeEventsMetricsCollectionInterval)
	}
	definition := getTimeDefinitionDuration(&obj.MetricsCommon, minTimeDef)
	// get measurement and db based on time definition
	var measurement string
	var functionMap map[string]string
	measurement, db, functionMap = getMeasurementAndDbAndMapFromClientUsageReq(settings, obj.Selector, definition)
	arg := influxClientMetricsQueryArgs{
		Selector:        getClientMetricsSelector(obj.Selector, CLIENT_CLOUDLETUSAGE, definition, functionMap),
		Measurement:     measurement,
		CloudletName:    obj.Cloudlet.Name,
		CloudletOrg:     obj.Cloudlet.Organization,
		DeviceCarrier:   obj.DeviceCarrier,
		DataNetworkType: obj.DataNetworkType,
		DeviceOs:        obj.DeviceOs,
		DeviceModel:     obj.DeviceModel,
		LocationTile:    obj.LocationTile,
		TagSet:          getTagSet(CLIENT_CLOUDLETUSAGE, obj.Selector),
	}
	// set MetricsCommonQueryArgs
	fillMetricsCommonQueryArgs(&arg.metricsCommonQueryArgs, &obj.MetricsCommon, definition.String(), 0) // TODO: PULL MIN from settings
	return getInfluxClientMetricsQueryCmd(&arg, operatorInfluxClientMetricsDBTemplate), db
}

// Gets all the tags to group by (these will be put into the Tags map in MetricSeries)
func getTagSet(measurementType string, selector string) string {
	var tags []string
	switch measurementType {
	case CLIENT_APIUSAGE:
		tags = ClientApiUsageTags
	case CLIENT_APPUSAGE:
		tags = ClientAppUsageTags
		if selector == "latency" {
			tags = append(tags, ClientAppUsageLatencyTags...)
		} else if selector == "deviceinfo" {
			tags = append(tags, ClientAppUsageDeviceInfoTags...)
		}
	case CLIENT_CLOUDLETUSAGE:
		tags = ClientCloudletUsageTags
		if selector == "latency" {
			tags = append(tags, ClientCloudletUsageLatencyTags...)
		} else if selector == "deviceinfo" {
			tags = append(tags, ClientCloudletUsageDeviceInfoTags...)
		}
	default:
		return ""
	}
	return strings.Join(tags, ",")
}

/*
 * Get selector
 * If definition is non-zero, then we will aggregate data with the aggregation function in selectorFuncMap for each field
 * If definition is zero, then grab data as-is
 */
func getClientMetricsSelector(selector string, measurementType string, definition time.Duration, selectorFuncMap map[string]string) string {
	if definition == 0 {
		return getFields(selector, measurementType)
	} else {
		// get all fields
		f := getFieldsSlice(selector, measurementType)
		fieldsWithFuncs := make([]string, 0)
		for _, field := range f {
			// find aggregation function for field
			field = strings.ReplaceAll(field, `\`, ``)
			field = strings.ReplaceAll(field, `"`, ``)
			function, ok := selectorFuncMap[field]
			if ok {
				function = fmt.Sprintf("%s AS %q", function, field)
				fieldsWithFuncs = append(fieldsWithFuncs, function)
			}
		}
		if len(fieldsWithFuncs) > 0 {
			return strings.Join(fieldsWithFuncs, ",")
		} else {
			return getFields(selector, measurementType)
		}
	}
}

func getMeasurementAndDbAndMapFromClientUsageReq(settings *edgeproto.Settings, selector string, definition time.Duration) (measurement string, db string, lookupMap map[string]string) {
	// Get base measurement (ie. "latency-metric")
	basemeasurement := ""
	switch selector {
	case "latency":
		basemeasurement = cloudcommon.LatencyMetric
		lookupMap = influxq.LatencyAggregationFunctions
	case "deviceinfo":
		basemeasurement = cloudcommon.DeviceMetric
		lookupMap = influxq.DeviceInfoAggregationFunctions
	}

	optCi := getOptimalCollectionInterval(settings, basemeasurement, definition)
	if optCi == nil { // raw data
		db = cloudcommon.EdgeEventsMetricsDbName
		measurement = fmt.Sprintf("%q", basemeasurement)
	} else { // downsampled data
		db = cloudcommon.DownsampledMetricsDbName
		measurement = influxq.CreateInfluxFullyQualifiedMeasurementName(db, basemeasurement, time.Duration(optCi.Interval), time.Duration(optCi.Retention))
	}

	return measurement, db, lookupMap
}

/*
 * Get the correct collection interval for already downsampled data for specified time definition
 * The optimal interval will be the interval that is less than the time definition and closest to the time definition
 * For example, if the time definition is 1.5 hr and we have continuous queries that aggregate hourly, daily, and weekly, this function will return the hourly collection interval.
 * If the duration is 25 hours, this function will return the daily collection interval
 */
func getOptimalCollectionInterval(settings *edgeproto.Settings, baseMeasurement string, definition time.Duration) *edgeproto.CollectionInterval {
	if settings == nil {
		return nil
	}
	// Find Continuous Query interval that is closest to definition but less than definition (ie. finer granularity)
	var minDiff time.Duration = 0
	var optCi *edgeproto.CollectionInterval
	for _, cq := range settings.EdgeEventsMetricsContinuousQueriesCollectionIntervals {
		diff := definition - time.Duration(cq.Interval)
		if diff >= 0 {
			if diff < minDiff || minDiff == 0 {
				minDiff = diff
				optCi = cq
			}
		}
	}

	if optCi == nil {
		log.DebugLog(log.DebugLevelMetrics, "Unable find interval with finer granularity than time definition - using raw data", "definition", definition)
	}
	return optCi
}

// TODO: HANDLE selector == "*"
// Make sure correct optional fields are provided for ClientAppUsage
// eg. DeviceOS is not allowed for latency selector/metric
func validateClientAppUsageMetricReq(req *ormapi.RegionClientAppUsageMetrics, selector string) error {
	// validate LocationTile format
	if req.LocationTile != "" {
		if !locationTileFormatMatch.MatchString(req.LocationTile) {
			return fmt.Errorf("Invalid format for the location tile.")
		}
	}
	switch selector {
	case "latency":
		if req.DeviceOs != "" {
			return fmt.Errorf("DeviceOS not allowed for appinst latency metric")
		}
		if req.DeviceModel != "" {
			return fmt.Errorf("DeviceModel not allowed for appinst latency metric")
		}
		if req.DeviceCarrier != "" {
			return fmt.Errorf("DeviceCarrier not allowed for appinst latency metric")
		}
	case "deviceinfo":
		// all options are valid for deviceinfo
	default:
		return fmt.Errorf("Provided selector \"%s\" is not valid, must provide only one of \"%s\"", selector, strings.Join(ormapi.ClientAppUsageSelectors, "\", \""))
	}
	return nil
}

// Make sure correct optional fields are provided for ClientCloudletUsage
// eg. DeviceOS is not allowed for latency selector/metric
func validateClientCloudletUsageMetricReq(req *ormapi.RegionClientCloudletUsageMetrics, selector string) error {
	switch selector {
	case "latency":
		if req.DeviceOs != "" {
			return fmt.Errorf("DeviceOS not allowed for cloudlet latency metric")
		}
		if req.DeviceModel != "" {
			return fmt.Errorf("DeviceModel not allowed for cloudlet latency metric")
		}
	case "deviceinfo":
		if req.DataNetworkType != "" {
			return fmt.Errorf("DataNetworkType not allowed for cloudlet deviceinfo metric")
		}
	default:
		return fmt.Errorf("Provided selector \"%s\" is not valid, must provide only one of \"%s\"", selector, strings.Join(ormapi.ClientCloudletUsageSelectors, "\", \""))
	}
	return nil
}
