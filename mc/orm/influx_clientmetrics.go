package orm

import (
	"bytes"
	fmt "fmt"
	"strconv"
	"strings"
	"text/template"
	"time"

	influxq "github.com/mobiledgex/edge-cloud/controller/influxq_client"

	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
)

var devInfluxClientMetricsDBTemplate *template.Template
var operatorInfluxClientMetricsDBTemplate *template.Template

type influxClientMetricsQueryArgs struct {
	// Query args
	metricsCommonQueryArgs
	Selector     string
	Measurement  string
	AppInstName  string
	AppVersion   string
	ClusterName  string
	CloudletName string
	CloudletList string
	OrgField     string
	ApiCallerOrg string
	CloudletOrg  string
	ClusterOrg   string
	AppOrg       string
	// ClientApi metric query args
	Method string
	CellId string
	// ClientAppUsage and ClientCloudletUsage metric query args
	DeviceCarrier   string
	DataNetworkType string
	DeviceModel     string
	DeviceOs        string
	LocationTile    string
}

// ClientApiUsageFields is DME metrics
var ClientApiUsageFields = []string{
	"\"apporg\"",
	"\"app\"",
	"\"ver\"",
	"\"cloudletorg\"",
	"\"cloudlet\"",
}

var ApiFields = []string{
	"\"dmeId\"",
	"\"cellID\"",
	"\"method\"",
	"\"foundCloudlet\"",
	"\"foundOperator\"",
	"\"reqs\"",
	"\"errs\"",
	"\"0s\"",
	"\"5ms\"",
	"\"10ms\"",
	"\"25ms\"",
	"\"50ms\"",
	"\"100ms\"",
}

var ClientApiAggregationFunctions = map[string]string{
	"reqs":  "sum(\"reqs\")",
	"errs":  "sum(\"errs\")",
	"0s":    "sum(\"0s\")",
	"5ms":   "sum(\"5ms\")",
	"10ms":  "sum(\"10ms\")",
	"25ms":  "sum(\"25ms\")",
	"50ms":  "sum(\"50ms\")",
	"100ms": "sum(\"100ms\")",
}

var ClientAppUsageFields = []string{
	"\"app\"",
	"\"apporg\"",
	"\"ver\"",
	"\"cluster\"",
	"\"clusterorg\"",
	"\"cloudlet\"",
	"\"cloudletorg\"",
}

var ClientCloudletUsageFields = []string{
	"\"cloudlet\"",
	"\"cloudletorg\"",
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

var ClientAppUsageLatencyFields = []string{
	"\"locationtile\"",
	"\"datanetworktype\"",
}

var ClientCloudletUsageLatencyFields = []string{
	"\"locationtile\"",
	"\"devicecarrier\"",
	"\"datanetworktype\"",
}

var DeviceInfoFields = []string{
	"\"deviceos\"",
	"\"devicemodel\"",
	"\"devicecarrier\"",
	"\"numsessions\"",
}

var ClientAppUsageDeviceInfoFields = []string{
	"\"datanetworktype\"",
}

var ClientCloudletUsageDeviceInfoFields = []string{
	"\"locationtile\"",
}

const (
	CLIENT_APIUSAGE      = "dme"
	CLIENT_APPUSAGE      = "clientappusage"
	CLIENT_CLOUDLETUSAGE = "clientcloudletusage"
)

var devInfluxClientMetricsDBT = `SELECT {{.Selector}} from /{{.Measurement}}/` +
	` WHERE "{{.OrgField}}"='{{.ApiCallerOrg}}'` +
	`{{if .AppInstName}} AND "app"='{{.AppInstName}}'{{end}}` +
	`{{if .AppOrg}} AND "apporg"='{{.AppOrg}}'{{end}}` +
	`{{if .ClusterName}} AND "cluster"='{{.ClusterName}}'{{end}}` +
	`{{if .AppVersion}} AND "ver"='{{.AppVersion}}'{{end}}` +
	`{{if .CloudletName}} AND "cloudlet"='{{.CloudletName}}'{{end}}` +
	`{{if .CloudletList}} AND ({{.CloudletList}}){{end}}` +
	`{{if .CloudletOrg}} AND "cloudletorg"='{{.CloudletOrg}}'{{end}}` +
	`{{if .Method}} AND "method"='{{.Method}}'{{end}}` +
	`{{if .CellId}} AND "cellID"='{{.CellId}}'{{end}}` +
	`{{if .DeviceCarrier}} AND "devicecarrier"='{{.DeviceCarrier}}'{{end}}` +
	`{{if .DataNetworkType}} AND "datanetworktype"='{{.DataNetworkType}}'{{end}}` +
	`{{if .DeviceOs}} AND "deviceos"='{{.DeviceOs}}'{{end}}` +
	`{{if .DeviceModel}} AND "devicemodel"='{{.DeviceModel}}'{{end}}` +
	`{{if .LocationTile}} AND "locationtile"='{{.LocationTile}}'{{end}}` +
	`{{if .StartTime}} AND time >= '{{.StartTime}}'{{end}}` +
	`{{if .EndTime}} AND time <= '{{.EndTime}}'{{end}}` +
	`{{if .TimeDefinition}} group by time({{.TimeDefinition}}){{end}}` +
	` order by time desc{{if ne .Limit 0}} limit {{.Limit}}{{end}}`

var operatorInfluxClientMetricsDBT = `SELECT {{.Selector}} from /{{.Measurement}}/` +
	` WHERE "cloudletorg"='{{.CloudletOrg}}'` +
	`{{if .CloudletName}} AND "cloudlet"='{{.CloudletName}}'{{end}}` +
	`{{if .DeviceCarrier}} AND "devicecarrier"='{{.DeviceCarrier}}'{{end}}` +
	`{{if .DataNetworkType}} AND "datanetworktype"='{{.DataNetworkType}}'{{end}}` +
	`{{if .DeviceOs}} AND "deviceos"='{{.DeviceOs}}'{{end}}` +
	`{{if .DeviceModel}} AND "devicemodel"='{{.DeviceModel}}'{{end}}` +
	`{{if .LocationTile}} AND "locationtile"='{{.LocationTile}}'{{end}}` +
	`{{if .StartTime}} AND time >= '{{.StartTime}}'{{end}}` +
	`{{if .EndTime}} AND time <= '{{.EndTime}}'{{end}}` +
	`{{if .TimeDefinition}} group by time({{.TimeDefinition}}){{end}}` +
	` order by time desc{{if ne .Limit 0}} limit {{.Limit}}{{end}}`

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

func ClientApiUsageMetricsQuery(obj *ormapi.RegionClientApiUsageMetrics, cloudletList []string, settings *edgeproto.Settings) string {
	// get time definition
	minTimeDef := DefaultClientUsageTimeWindow
	if settings != nil {
		minTimeDef = time.Duration(settings.DmeApiMetricsCollectionInterval)
	}
	definition := getTimeDefinitionDuration(&obj.MetricsCommon, minTimeDef)
	arg := influxClientMetricsQueryArgs{
		Selector:     getClientMetricsSelector(obj.Selector, CLIENT_APIUSAGE, definition, ClientApiAggregationFunctions),
		Measurement:  getMeasurementString(obj.Selector, CLIENT_APIUSAGE),
		AppInstName:  obj.AppInst.AppKey.Name,
		AppVersion:   obj.AppInst.AppKey.Version,
		ApiCallerOrg: obj.AppInst.AppKey.Organization,
		ClusterOrg:   obj.AppInst.ClusterInstKey.Organization,
		CloudletList: generateCloudletList(cloudletList),
		ClusterName:  obj.AppInst.ClusterInstKey.ClusterKey.Name,
		Method:       obj.Method,
	}
	if obj.AppInst.AppKey.Organization != "" {
		arg.OrgField = "apporg"
		arg.ApiCallerOrg = obj.AppInst.AppKey.Organization
		arg.CloudletOrg = obj.AppInst.ClusterInstKey.CloudletKey.Organization
	} else {
		arg.OrgField = "cloudletorg"
		arg.ApiCallerOrg = obj.AppInst.ClusterInstKey.CloudletKey.Organization
		arg.AppOrg = obj.AppInst.AppKey.Organization
	}
	if obj.CellId != 0 {
		arg.CellId = strconv.FormatUint(uint64(obj.CellId), 10)
	}
	// set MetricsCommonQueryArgs
	fillMetricsCommonQueryArgs(&arg.metricsCommonQueryArgs, devInfluxClientMetricsDBTemplate, &obj.MetricsCommon, definition.String(), 0) // TODO: PULL MIN from settings
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
		AppInstName:     obj.AppInst.AppKey.Name,
		AppVersion:      obj.AppInst.AppKey.Version,
		ApiCallerOrg:    obj.AppInst.AppKey.Organization,
		ClusterOrg:      obj.AppInst.ClusterInstKey.Organization,
		CloudletList:    generateCloudletList(cloudletList),
		ClusterName:     obj.AppInst.ClusterInstKey.ClusterKey.Name,
		DeviceCarrier:   obj.DeviceCarrier,
		DataNetworkType: obj.DataNetworkType,
		DeviceOs:        obj.DeviceOs,
		DeviceModel:     obj.DeviceModel,
		LocationTile:    obj.LocationTile,
	}
	if obj.AppInst.AppKey.Organization != "" {
		arg.OrgField = "apporg"
		arg.ApiCallerOrg = obj.AppInst.AppKey.Organization
		arg.CloudletOrg = obj.AppInst.ClusterInstKey.CloudletKey.Organization
	} else {
		arg.OrgField = "cloudletorg"
		arg.ApiCallerOrg = obj.AppInst.ClusterInstKey.CloudletKey.Organization
		arg.AppOrg = obj.AppInst.AppKey.Organization
	}
	// set MetricsCommonQueryArgs
	fillMetricsCommonQueryArgs(&arg.metricsCommonQueryArgs, devInfluxClientMetricsDBTemplate, &obj.MetricsCommon, definition.String(), 0) // TODO: PULL MIN from settings
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
	}
	// set MetricsCommonQueryArgs
	fillMetricsCommonQueryArgs(&arg.metricsCommonQueryArgs, devInfluxClientMetricsDBTemplate, &obj.MetricsCommon, definition.String(), 0) // TODO: PULL MIN from settings
	return getInfluxClientMetricsQueryCmd(&arg, operatorInfluxClientMetricsDBTemplate), db
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
				function = fmt.Sprintf("%s AS \"%s\"", function, field)
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

	// Get downsampled measurement if time definition is greater than a cq interval (ie. "latency-metric-10s")
	measurement = basemeasurement
	if definition != 0 {
		measurement = getClientMetricsMeasurementString(settings, basemeasurement, definition)
	}

	// Get db from measurement (either EdgeEventsMetricsDb or DownsampledMetricsDb)
	if measurement == basemeasurement {
		db = cloudcommon.EdgeEventsMetricsDbName
	} else {
		db = cloudcommon.DownsampledMetricsDbName
	}
	return measurement, db, lookupMap
}

/*
 * Get the correct measurement string for already downsampled data for specified time definition
 * For example, if the time definition is 1.5 hr and we have continuous queries that aggregate hourly, daily, and weekly, this function will return the hourly measurement.
 * If the duration is 25 hours, this function will return the daily measurement
 */
func getClientMetricsMeasurementString(settings *edgeproto.Settings, baseMeasurement string, definition time.Duration) string {
	if settings == nil {
		return baseMeasurement
	}
	// Find Continuous Query interval that is closest to definition but less than definition (ie. finer granularity)
	var optimalInterval time.Duration = 0
	var minDiff time.Duration = 0
	for _, cqs := range settings.EdgeEventsMetricsContinuousQueriesCollectionIntervals {
		diff := definition - time.Duration(cqs.Interval)
		if diff >= 0 {
			if diff < minDiff || minDiff == 0 {
				minDiff = diff
				optimalInterval = time.Duration(cqs.Interval)
			}
		}
	}

	if optimalInterval == 0 {
		log.DebugLog(log.DebugLevelMetrics, "Unable find interval with finer granularity than time definition - using raw data", "definition", definition)
		return baseMeasurement
	}
	return cloudcommon.CreateInfluxMeasurementName(baseMeasurement, optimalInterval)
}

// TODO: HANDLE selector == "*"
// Make sure correct optional fields are provided for ClientAppUsage
// eg. DeviceOS is not allowed for latency selector/metric
func validateClientAppUsageMetricReq(req *ormapi.RegionClientAppUsageMetrics, selector string) error {
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
		if req.LocationTile != "" {
			return fmt.Errorf("LocationTile not allowed for appinst deviceinfo metric")
		}
	case "custom":
		return fmt.Errorf("Custom stat not implemented yet")
	default:
		return fmt.Errorf("Provided selector \"%s\" is not valid. Must provide only one of \"%s\"", selector, strings.Join(ormapi.ClientAppUsageSelectors, "\", \""))
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
		return fmt.Errorf("Provided selector \"%s\" is not valid. Must provide only one of \"%s\"", selector, strings.Join(ormapi.ClientCloudletUsageSelectors, "\", \""))
	}
	return nil
}
