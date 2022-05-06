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
	"context"
	"fmt"
	"strings"
	"sync"
	"text/template"
	"time"

	client "github.com/influxdata/influxdb/client/v2"
	influxdb "github.com/influxdata/influxdb/client/v2"
	"github.com/labstack/echo"
	"github.com/edgexr/edge-cloud-infra/mc/ctrlclient"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud-infra/mc/ormutil"
	pf "github.com/edgexr/edge-cloud/cloud-resource-manager/platform"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/cloudcommon/influxsup"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/util"
)

var devInfluxDBTemplate *template.Template
var operatorInfluxDBTemplate *template.Template

// 100 values at a time
var queryChunkSize = 100

var maxEntriesFromInfluxDb = 10000

type InfluxDBContext struct {
	region string
	claims *UserClaims
	conn   influxdb.Client
}

type influxQueryArgs struct {
	metricsCommonQueryArgs
	Selector       string
	Measurement    string
	AppInstName    string
	AppVersion     string
	ClusterName    string
	CloudletName   string
	OrgField       string
	ApiCallerOrg   string
	CloudletOrg    string
	ClusterOrg     string
	AppOrg         string
	DeploymentType string
	CloudletList   string
	QueryFilter    string
	GroupFields    string
}

type metricsCommonQueryArgs struct {
	StartTime      string
	EndTime        string
	Limit          int
	TimeDefinition string
}

// AppFields are the field names used to query the DB
var AppFields = []string{
	"\"app\"",
	"\"ver\"",
	"\"cluster\"",
	"\"clusterorg\"",
	"\"cloudlet\"",
	"\"cloudletorg\"",
	"\"apporg\"",
}

var ClusterFields = []string{
	"\"cluster\"",
	"\"clusterorg\"",
	"\"cloudlet\"",
	"\"cloudletorg\"",
}

var CloudletFields = []string{
	"\"cloudlet\"",
	"\"cloudletorg\"",
}

var PodFields = []string{
	"\"pod\"",
}

var CpuFields = []string{
	"cpu",
}

var MemFields = []string{
	"mem",
}

var DiskFields = []string{
	"disk",
}

var NetworkFields = []string{
	"sendBytes",
	"recvBytes",
}

var TcpFields = []string{
	"tcpConns",
	"tcpRetrans",
}

var UdpFields = []string{
	"udpSent",
	"udpRecv",
	"udpRecvErr",
}

var ConnectionsFields = []string{
	"port",
	"active",
	"handled",
	"accepts",
	"bytesSent",
	"bytesRecvd",
	"P0",
	"P25",
	"P50",
	"P75",
	"P90",
	"P95",
	"P99",
	"\"P99.5\"",
	"\"P99.9\"",
	"P100",
}

var appUdpFields = []string{
	"port",
	"bytesSent",
	"bytesRecvd",
	"datagramsSent",
	"datagramsRecvd",
	"sentErrs",
	"recvErrs",
	"overflow",
	"missed",
}

var UtilizationFields = []string{
	"vCpuUsed",
	"vCpuMax",
	"memUsed",
	"memMax",
	"diskUsed",
	"diskMax",
}

var CloudletNetworkFields = []string{
	"netSend",
	"netRecv",
}

var IpUsageFields = []string{
	"floatingIpsUsed",
	"floatingIpsMax",
	"ipv4Used",
	"ipv4Max",
}

var ResourceUsageFields = []string{
	"vcpusUsed",
	"ramUsed",
	"instancesUsed",
	"gpusUsed",
	"externalIpsUsed",
	"floatingIpsUsed",
}

var FlavorUsageFields = []string{
	"flavor",
	"count",
}

const (
	APPINST       = "appinst"
	CLUSTER       = "cluster"
	CLOUDLET      = "cloudlet"
	CLOUDLETUSAGE = "cloudletusage"
)

var devInfluxDBT = `SELECT {{.Selector}} from {{.Measurement}}` +
	` WHERE "{{.OrgField}}"='{{.ApiCallerOrg}}'` +
	`{{if .AppInstName}} AND "app"='{{.AppInstName}}'{{end}}` +
	`{{if .AppOrg}} AND "apporg"='{{.AppOrg}}'{{end}}` +
	`{{if .ClusterName}} AND "cluster"='{{.ClusterName}}'{{end}}` +
	`{{if .ClusterOrg}} AND "clusterorg"='{{.ClusterOrg}}'{{end}}` +
	`{{if .AppVersion}} AND "ver"='{{.AppVersion}}'{{end}}` +
	`{{if .CloudletName}} AND "cloudlet"='{{.CloudletName}}'{{end}}` +
	`{{if .CloudletOrg}} AND "cloudletorg"='{{.CloudletOrg}}'{{end}}` +
	`{{if .StartTime}} AND time >= '{{.StartTime}}'{{end}}` +
	`{{if .EndTime}} AND time <= '{{.EndTime}}'{{end}}` +
	`{{if .DeploymentType}} AND deployment = '{{.DeploymentType}}'{{end}}` +
	`{{if .CloudletList}} AND ({{.CloudletList}}){{end}}` +
	` order by time desc{{if ne .Limit 0}} limit {{.Limit}}{{end}}`

var operatorInfluxDBT = `SELECT {{.Selector}} from {{.Measurement}}` +
	` WHERE "cloudletorg"='{{.CloudletOrg}}'` +
	`{{if .CloudletName}} AND "cloudlet"='{{.CloudletName}}'{{end}}` +
	`{{if .StartTime}} AND time >= '{{.StartTime}}'{{end}}` +
	`{{if .EndTime}} AND time <= '{{.EndTime}}'{{end}}` +
	` order by time desc{{if ne .Limit 0}} limit {{.Limit}}{{end}}`

type InfluxDbConnCache struct {
	sync.RWMutex
	clients map[string]influxdb.Client
}

var influxDbConnCache InfluxDbConnCache

func (c *InfluxDbConnCache) InitCache() {
	c.clients = make(map[string]influxdb.Client)

}

func (c *InfluxDbConnCache) GetClient(region string) (influxdb.Client, error) {
	c.RLock()
	defer c.RUnlock()
	if client, found := c.clients[region]; found {
		return client, nil
	}
	return nil, fmt.Errorf("Client no found in cache")
}

func (c *InfluxDbConnCache) AddClient(client influxdb.Client, region string) {
	c.Lock()
	defer c.Unlock()
	if oldClient, found := c.clients[region]; found {
		oldClient.Close()
	}
	c.clients[region] = client
}

func (c *InfluxDbConnCache) DeleteClient(region string) {
	c.Lock()
	defer c.Unlock()
	if client, found := c.clients[region]; found {
		client.Close()
	}
	delete(c.clients, region)
}

func (c *InfluxDbConnCache) CloseIdleConnections(region string) {
	c.Lock()
	defer c.Unlock()
	if client, found := c.clients[region]; found {
		client.Close()
	}
}

func init() {
	devInfluxDBTemplate = template.Must(template.New("influxquery").Parse(devInfluxDBT))
	operatorInfluxDBTemplate = template.Must(template.New("influxquery").Parse(operatorInfluxDBT))
	influxDbConnCache.InitCache()
}

func ConnectInfluxDB(ctx context.Context, region string) (influxdb.Client, error) {
	// If we have a cached client - return it
	if client, err := influxDbConnCache.GetClient(region); err == nil {
		return client, nil
	}
	addr, err := getInfluxDBAddrForRegion(ctx, region)
	if err != nil {
		return nil, err
	}
	creds, err := cloudcommon.GetInfluxDataAuth(serverConfig.vaultConfig, region)
	if err != nil {
		return nil, fmt.Errorf("get influxDB auth failed, %v", err)
	}
	if creds == nil {
		// default to empty auth
		creds = &cloudcommon.InfluxCreds{}
	}
	client, err := influxsup.GetClient(addr, creds.User, creds.Pass)
	log.SpanLog(ctx, log.DebugLevelMetrics, "connecting to influxdb",
		"addr", addr, "err", err)
	if err != nil {
		return nil, err
	}
	// cache this client for future use
	influxDbConnCache.AddClient(client, region)
	return client, nil
}

func getInfluxDBAddrForRegion(ctx context.Context, region string) (string, error) {
	ctrl, err := getControllerObj(ctx, region)
	if err != nil {
		return "", err
	}
	return ctrl.InfluxDB, nil
}

func getSettings(ctx context.Context, region string) (*edgeproto.Settings, error) {
	// Grab settings for specified region
	in := &edgeproto.Settings{}
	rc := &ormutil.RegionContext{
		Region:    region,
		SkipAuthz: true, // this is internal call, so no auth needed
		Database:  database,
	}
	return ctrlclient.ShowSettingsObj(ctx, rc, in, connCache)
}

// Fill in MetricsCommonQueryArgs: Depending on if the user specified "Limit", "NumSamples", "StartTime", and "EndTime", adjust the query
func fillMetricsCommonQueryArgs(m *metricsCommonQueryArgs, c *ormapi.MetricsCommon, timeDefinition string, minTimeWindow time.Duration) {
	// Set one of Last or TimeDefinition
	if c.Limit != 0 {
		m.Limit = c.Limit
	} else {
		m.TimeDefinition = timeDefinition
		m.Limit = c.NumSamples
	}
	// add start and end times
	if !c.StartTime.IsZero() {
		buf, err := c.StartTime.MarshalText()
		if err == nil {
			m.StartTime = string(buf)
		}
	}
	if !c.EndTime.IsZero() {
		buf, err := c.EndTime.MarshalText()
		if err == nil {
			m.EndTime = string(buf)
		}
	}
}

func getInfluxQueryCmd(q *influxQueryArgs, tmpl *template.Template) string {
	buf := bytes.Buffer{}
	if err := tmpl.Execute(&buf, q); err != nil {
		log.DebugLog(log.DebugLevelApi, "Failed to run template", "tmpl", tmpl, "args", q, "error", err)
		return ""
	}
	return buf.String()
}

func addQuotesToMeasurementNames(measurement string) string {
	// add quotes to measurement names for exact matching
	measurementNames := []string{}
	measurements := strings.Split(measurement, ",")
	for _, m := range measurements {
		measurementNames = append(measurementNames, `"`+m+`"`)
	}
	return strings.Join(measurementNames, ",")
}

// Query is a template with a specific set of if/else
func AppInstMetricsQuery(obj *ormapi.RegionAppInstMetrics, cloudletList []string) string {
	arg := influxQueryArgs{
		Selector:     getFields(obj.Selector, APPINST),
		Measurement:  getMeasurementString(obj.Selector, APPINST),
		AppInstName:  util.DNSSanitize(obj.AppInst.AppKey.Name),
		AppVersion:   util.DNSSanitize(obj.AppInst.AppKey.Version),
		ClusterName:  obj.AppInst.ClusterInstKey.ClusterKey.Name,
		ClusterOrg:   obj.AppInst.ClusterInstKey.Organization,
		CloudletList: generateCloudletList(cloudletList),
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
	fillMetricsCommonQueryArgs(&arg.metricsCommonQueryArgs, &obj.MetricsCommon, "", 0)
	return getInfluxMetricsQueryCmd(&arg, devInfluxDBTemplate)
}

// Query is a template with a specific set of if/else
func ClusterMetricsQuery(obj *ormapi.RegionClusterInstMetrics, cloudletList []string) string {
	arg := influxQueryArgs{
		Selector:     getFields(obj.Selector, CLUSTER),
		Measurement:  getMeasurementString(obj.Selector, CLUSTER),
		ClusterName:  obj.ClusterInst.ClusterKey.Name,
		CloudletList: generateCloudletList(cloudletList),
	}
	if obj.ClusterInst.Organization != "" {
		arg.OrgField = "clusterorg"
		arg.ApiCallerOrg = obj.ClusterInst.Organization
		arg.CloudletOrg = obj.ClusterInst.CloudletKey.Organization
	} else {
		arg.OrgField = "cloudletorg"
		arg.ApiCallerOrg = obj.ClusterInst.CloudletKey.Organization
		arg.ClusterOrg = obj.ClusterInst.Organization
	}
	fillMetricsCommonQueryArgs(&arg.metricsCommonQueryArgs, &obj.MetricsCommon, "", 0)
	return getInfluxMetricsQueryCmd(&arg, devInfluxDBTemplate)
}

// Query is a template with a specific set of if/else
func CloudletMetricsQuery(obj *ormapi.RegionCloudletMetrics) string {
	arg := influxQueryArgs{
		Selector:     getFields(obj.Selector, CLOUDLET),
		Measurement:  getMeasurementString(obj.Selector, CLOUDLET),
		CloudletName: obj.Cloudlet.Name,
		CloudletOrg:  obj.Cloudlet.Organization,
	}
	fillMetricsCommonQueryArgs(&arg.metricsCommonQueryArgs, &obj.MetricsCommon, "", 0)
	return getInfluxMetricsQueryCmd(&arg, operatorInfluxDBTemplate)
}

// Query is a template with a specific set of if/else
func CloudletUsageMetricsQuery(obj *ormapi.RegionCloudletMetrics, platformTypes map[string]struct{}) string {
	arg := influxQueryArgs{
		Selector:     "*",
		Measurement:  getCloudletUsageMeasurementString(obj.Selector, platformTypes),
		CloudletName: obj.Cloudlet.Name,
		CloudletOrg:  obj.Cloudlet.Organization,
	}
	fillMetricsCommonQueryArgs(&arg.metricsCommonQueryArgs, &obj.MetricsCommon, "", 0)
	return getInfluxMetricsQueryCmd(&arg, operatorInfluxDBTemplate)
}

// TODO: This function should be a streaming function, but currently client library for influxDB
// doesn't implement it in a way could really be using it
func influxStream(ctx context.Context, rc *InfluxDBContext, databases []string, dbQuery string, cb func(Data interface{}) error) error {
	log.SpanLog(ctx, log.DebugLevelApi, "start influxDB api", "region", rc.region)
	defer log.SpanLog(ctx, log.DebugLevelApi, "finish influxDB api")

	if rc.conn == nil {
		conn, err := ConnectInfluxDB(ctx, rc.region)
		if err != nil {
			return err
		}
		rc.conn = conn
	}
	var results []influxdb.Result
	for _, database := range databases {
		query := influxdb.Query{
			Command:   dbQuery,
			Database:  database,
			Chunked:   false, // TODO - add chunking. Client lib doesn't support chunk response processing yet
			ChunkSize: queryChunkSize,
		}
		resp, err := rc.conn.Query(query)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelMetrics, "InfluxDB query failed",
				"query", query, "resp", resp, "err", err)
			// If the query failed, clean up idle connections
			influxDbConnCache.CloseIdleConnections(rc.region)
			// We return a different error, as we don't want to expose a URL-encoded query to influxDB
			return fmt.Errorf("Connection to InfluxDB failed")
		}
		if resp.Error() != nil {
			return resp.Error()
		}
		results = append(results, resp.Results...)
	}
	return cb(results)
}

func Contains(slice []string, elem string) bool {
	for _, val := range slice {
		if val == elem {
			return true
		}
	}
	return false
}

// Function validates the selector passed, we support several selectors: cpu, mem, disk, net
func validateSelectorString(selector, metricType string) error {
	var validSelectors []string
	switch metricType {
	case APPINST:
		validSelectors = ormapi.AppSelectors
	case CLUSTER:
		validSelectors = ormapi.ClusterSelectors
	case CLOUDLET:
		validSelectors = ormapi.CloudletSelectors
	case CLOUDLETUSAGE:
		validSelectors = ormapi.CloudletUsageSelectors
	case CLIENT_APIUSAGE:
		validSelectors = ormapi.ClientApiUsageSelectors
	case CLIENT_APPUSAGE:
		validSelectors = ormapi.ClientAppUsageSelectors
	case CLIENT_CLOUDLETUSAGE:
		validSelectors = ormapi.ClientCloudletUsageSelectors
	default:
		return fmt.Errorf("Invalid metric type %s", metricType)
	}
	if selector == "*" {
		return nil
	}
	selectors := strings.Split(selector, ",")
	for _, s := range selectors {
		if !Contains(validSelectors, s) {
			helpStr := strings.Join(validSelectors, "\", \"")
			if len(validSelectors) > 1 {
				helpStr = "must be one of \"" + helpStr + "\""
			} else {
				helpStr = "only \"" + helpStr + "\" is supported"
			}

			return fmt.Errorf("Invalid %s selector: %s, %s", metricType, s, helpStr)
		}
	}
	return nil
}

func getMeasurementString(selector, measurementType string) string {
	var measurements []string
	switch measurementType {
	case APPINST:
		measurements = ormapi.AppSelectors
	case CLUSTER:
		measurements = ormapi.ClusterSelectors
	case CLOUDLET:
		measurements = ormapi.CloudletSelectors
	case CLIENT_APIUSAGE:
		measurements = ormapi.ClientApiUsageSelectors
	}
	if selector != "*" {
		measurements = strings.Split(selector, ",")
	}
	prefix := measurementType + "-"
	return prefix + strings.Join(measurements, ","+prefix)
}

func getCloudletUsageMeasurementString(selector string, platformTypes map[string]struct{}) string {
	measurements := []string{}
	selectors := ormapi.CloudletUsageSelectors
	if selector != "*" {
		selectors = strings.Split(selector, ",")
	}
	for _, cSelector := range selectors {
		if cSelector == "resourceusage" {
			for platformType, _ := range platformTypes {
				measurements = append(measurements, fmt.Sprintf("%s-resource-usage", platformType))
			}
		} else if selector == "flavorusage" {
			measurements = append(measurements, "cloudlet-flavor-usage")
		} else {
			measurements = append(measurements, cSelector)
		}
	}
	return strings.Join(measurements, ",")
}

func getFields(selector, measurementType string) string {
	fields := getFieldsSlice(selector, measurementType)
	return strings.Join(fields, ",")
}

func getFieldsSlice(selector, measurementType string) []string {
	var fields, selectors []string
	switch measurementType {
	case APPINST:
		fields = AppFields
		// If this is not connections selector add pod field
		if selector != "connections" {
			fields = append(fields, PodFields...)
		}
		selectors = ormapi.AppSelectors
	case CLUSTER:
		fields = ClusterFields
		selectors = ormapi.ClusterSelectors
	case CLOUDLET:
		fields = CloudletFields
		selectors = ormapi.CloudletSelectors
	case CLOUDLETUSAGE:
		fields = CloudletFields
		selectors = ormapi.CloudletUsageSelectors
	case CLIENT_APIUSAGE:
		selectors = ormapi.ClientApiUsageSelectors
	case CLIENT_APPUSAGE:
		selectors = ormapi.ClientAppUsageSelectors
	case CLIENT_CLOUDLETUSAGE:
		selectors = ormapi.ClientCloudletUsageSelectors
	default:
		return []string{"*"}
	}
	if selector != "*" {
		selectors = strings.Split(selector, ",")
	}
	for _, v := range selectors {
		switch v {
		case "cpu":
			fields = append(fields, CpuFields...)
		case "mem":
			fields = append(fields, MemFields...)
		case "disk":
			fields = append(fields, DiskFields...)
		case "network":
			if measurementType == CLOUDLET {
				fields = append(fields, CloudletNetworkFields...)
			} else {
				fields = append(fields, NetworkFields...)
			}
		case "connections":
			fields = append(fields, ConnectionsFields...)
		case "tcp":
			fields = append(fields, TcpFields...)
		case "udp":
			if measurementType == APPINST {
				fields = append(fields, appUdpFields...)
			} else {
				fields = append(fields, UdpFields...)
			}
		case "utilization":
			fields = append(fields, UtilizationFields...)
		case "ipusage":
			fields = append(fields, IpUsageFields...)
		case "api":
			fields = append(fields, ApiFields...)
		case "resourceusage":
			fields = append(fields, ResourceUsageFields...)
		case "flavorusage":
			fields = append(fields, FlavorUsageFields...)
		case "latency":
			fields = append(fields, LatencyFields...)
		case "deviceinfo":
			fields = append(fields, DeviceInfoFields...)
		}
	}
	return fields
}

func getCloudletPlatformTypes(ctx context.Context, username, region string, keys []edgeproto.CloudletKey) (map[string]struct{}, error) {
	platformTypes := make(map[string]struct{})
	rc := &ormutil.RegionContext{}
	rc.Username = username
	rc.Region = region
	rc.Database = database

	err := ctrlclient.ShowCloudletStream(ctx, rc, &edgeproto.Cloudlet{}, connCache, nil, func(res *edgeproto.Cloudlet) error {
		// only process the passed in cloudlets
		foundMatch := false
		for ii := range keys {
			if res.Key.Matches(&keys[ii], edgeproto.MatchFilter()) {
				foundMatch = true
				break
			}
		}
		// no match found - continue looking
		if foundMatch == false {
			return nil
		}
		pfType := pf.GetType(res.PlatformType.String())
		platformTypes[pfType] = struct{}{}
		return nil
	})
	if err != nil {
		return nil, err
	}

	if len(platformTypes) == 0 {
		return nil, fmt.Errorf("Cloudlet does not exist")
	}
	return platformTypes, nil
}

func getClientApiUsageMetricsArgs(in *ormapi.RegionClientApiUsageMetrics) map[string]string {
	args := in.AppInst.GetTags()
	args["method"] = in.Method
	args["dme cloudlet"] = in.DmeCloudlet
	args["dme cloudlet org"] = in.DmeCloudletOrg
	return args
}

func getClientAppUsageMetricsArgs(in *ormapi.RegionClientAppUsageMetrics) map[string]string {
	args := in.AppInst.GetTags()
	args["device carrier"] = in.DeviceCarrier
	args["data network type"] = in.DataNetworkType
	args["device model"] = in.DeviceModel
	args["device os"] = in.DeviceOs
	args["signal strength"] = in.SignalStrength
	return args
}

func getClientCloudletUsageMetricsArgs(in *ormapi.RegionClientCloudletUsageMetrics) map[string]string {
	args := in.Cloudlet.GetTags()
	args["device carrier"] = in.DeviceCarrier
	args["data network type"] = in.DataNetworkType
	args["device model"] = in.DeviceModel
	args["device os"] = in.DeviceOs
	args["signal strength"] = in.SignalStrength
	return args
}

// Common method to handle both app and cluster metrics
func GetMetricsCommon(c echo.Context) error {
	var cmd, org string

	rc := &InfluxDBContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.claims = claims
	ctx := ormutil.GetContext(c)
	// Get the current config
	config, err := getConfig(ctx)
	if err == nil {
		maxEntriesFromInfluxDb = config.MaxMetricsDataPoints
	}
	dbNames := []string{}
	if strings.HasSuffix(c.Path(), "metrics/app") {
		in := ormapi.RegionAppInstMetrics{}
		_, err := ReadConn(c, &in)
		if err != nil {
			return err
		}
		// validate all the passed in arguments
		if err = util.ValidateNames(in.AppInst.GetTags()); err != nil {
			return err
		}

		if err = validateAndResolveInfluxMetricsCommon(&in.MetricsCommon); err != nil {
			return err
		}

		// New metrics api request
		if len(in.AppInsts) > 0 {
			return GetAppMetrics(c, &in)
		}
		dbNames = append(dbNames, cloudcommon.DeveloperMetricsDbName)
		rc.region = in.Region
		cloudletList, err := checkPermissionsAndGetCloudletList(ctx, claims.Username, in.Region, []string{in.AppInst.AppKey.Organization},
			ResourceAppAnalytics, []edgeproto.CloudletKey{in.AppInst.ClusterInstKey.CloudletKey})
		if err != nil {
			return err
		}
		if err = validateSelectorString(in.Selector, APPINST); err != nil {
			return err
		}
		cmd = AppInstMetricsQuery(&in, cloudletList)
	} else if strings.HasSuffix(c.Path(), "metrics/cluster") {
		dbNames = append(dbNames, cloudcommon.DeveloperMetricsDbName)
		in := ormapi.RegionClusterInstMetrics{}
		_, err := ReadConn(c, &in)
		if err != nil {
			return err
		}
		// validate all the passed in arguments
		if err = util.ValidateNames(in.ClusterInst.GetTags()); err != nil {
			return err
		}

		if err = validateAndResolveInfluxMetricsCommon(&in.MetricsCommon); err != nil {
			return err
		}

		// New metrics api request
		if len(in.ClusterInsts) > 0 {
			return GetClusterMetrics(c, &in)
		}

		rc.region = in.Region
		cloudletList, err := checkPermissionsAndGetCloudletList(ctx, claims.Username, in.Region, []string{in.ClusterInst.Organization},
			ResourceClusterAnalytics, []edgeproto.CloudletKey{in.ClusterInst.CloudletKey})
		if err != nil {
			return err
		}
		if err = validateSelectorString(in.Selector, CLUSTER); err != nil {
			return err
		}
		cmd = ClusterMetricsQuery(&in, cloudletList)
	} else if strings.HasSuffix(c.Path(), "metrics/cloudlet") {
		dbNames = append(dbNames, cloudcommon.DeveloperMetricsDbName)
		in := ormapi.RegionCloudletMetrics{}
		_, err := ReadConn(c, &in)
		if err != nil {
			return err
		}

		// validate all the passed in arguments
		if err = util.ValidateNames(in.Cloudlet.GetTags()); err != nil {
			return err
		}

		if err = validateAndResolveInfluxMetricsCommon(&in.MetricsCommon); err != nil {
			return err
		}

		// New metrics api request
		if len(in.Cloudlets) > 0 {
			return GetCloudletMetrics(c, &in)
		}

		// Operator name has to be specified
		if in.Cloudlet.Organization == "" {
			return fmt.Errorf("Cloudlet details must be present")
		}

		rc.region = in.Region
		org = in.Cloudlet.Organization
		if err = validateSelectorString(in.Selector, CLOUDLET); err != nil {
			return err
		}
		// Check the operator against who is logged in
		if err := authorized(ctx, rc.claims.Username, org, ResourceCloudletAnalytics, ActionView); err != nil {
			return err
		}
		cmd = CloudletMetricsQuery(&in)

	} else if strings.HasSuffix(c.Path(), "metrics/clientapiusage") {
		dbNames = append(dbNames, cloudcommon.DeveloperMetricsDbName)
		in := ormapi.RegionClientApiUsageMetrics{}
		_, err := ReadConn(c, &in)
		if err != nil {
			return err
		}
		// validate all the passed in arguments
		args := getClientApiUsageMetricsArgs(&in)
		if err = util.ValidateNames(args); err != nil {
			return err
		}

		rc.region = in.Region
		cloudletList, err := checkPermissionsAndGetCloudletList(ctx, claims.Username, in.Region, []string{in.AppInst.AppKey.Organization},
			ResourceAppAnalytics, []edgeproto.CloudletKey{in.AppInst.ClusterInstKey.CloudletKey})
		if err != nil {
			return err
		}
		if err = validateSelectorString(in.Selector, CLIENT_APIUSAGE); err != nil {
			return err
		}
		if err = validateMethodString(&in); err != nil {
			return err
		}
		if err = validateAndResolveInfluxMetricsCommon(&in.MetricsCommon); err != nil {
			return err
		}
		settings, err := getSettings(ctx, rc.region)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelMetrics, "Unable to get metrics settings for region %v - error is %s", rc.region, err.Error())
		}
		cmd = ClientApiUsageMetricsQuery(&in, cloudletList, settings)

	} else if strings.HasSuffix(c.Path(), "metrics/cloudlet/usage") {
		dbNames = append(dbNames, cloudcommon.CloudletResourceUsageDbName)
		in := ormapi.RegionCloudletMetrics{}
		_, err := ReadConn(c, &in)
		if err != nil {
			return err
		}
		// validate all the passed in arguments
		if err = util.ValidateNames(in.Cloudlet.GetTags()); err != nil {
			return err
		}

		if err = validateAndResolveInfluxMetricsCommon(&in.MetricsCommon); err != nil {
			return err
		}
		rc.region = in.Region
		org = in.Cloudlet.Organization

		// New metrics api request
		if len(in.Cloudlets) > 0 {
			return GetCloudletUsageMetrics(c, &in)
		}

		// Operator name has to be specified
		if in.Cloudlet.Organization == "" {
			return fmt.Errorf("Cloudlet details must be present")
		}

		if err = validateSelectorString(in.Selector, CLOUDLETUSAGE); err != nil {
			return err
		}

		// Check the operator against who is logged in
		if err := authorized(ctx, rc.claims.Username, org, ResourceCloudletAnalytics, ActionView); err != nil {
			return err
		}

		// Platform type is required for cloudlet resource usage, but for consistency check for all selectors
		platformTypes, err := getCloudletPlatformTypes(ctx, claims.Username, in.Region, []edgeproto.CloudletKey{in.Cloudlet})
		if err != nil {
			return err
		}
		cmd = CloudletUsageMetricsQuery(&in, platformTypes)

	} else if strings.HasSuffix(c.Path(), "metrics/clientappusage") {
		in := ormapi.RegionClientAppUsageMetrics{}
		_, err := ReadConn(c, &in)
		if err != nil {
			return err
		}
		// validate all the passed in arguments
		args := getClientAppUsageMetricsArgs(&in)
		if err = util.ValidateNames(args); err != nil {
			return err
		}

		rc.region = in.Region
		cloudletList, err := checkPermissionsAndGetCloudletList(ctx, claims.Username, in.Region, []string{in.AppInst.AppKey.Organization},
			ResourceAppAnalytics, []edgeproto.CloudletKey{in.AppInst.ClusterInstKey.CloudletKey})
		if err != nil {
			return err
		}
		if err = validateClientAppUsageMetricReq(&in, in.Selector); err != nil {
			return err
		}
		if err = validateAndResolveInfluxMetricsCommon(&in.MetricsCommon); err != nil {
			return err
		}
		settings, err := getSettings(ctx, rc.region)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelMetrics, "Unable to get metrics settings for region %v - error is %s", rc.region, err.Error())
		}
		var db string
		cmd, db = ClientAppUsageMetricsQuery(&in, cloudletList, settings)
		dbNames = append(dbNames, db)
	} else if strings.HasSuffix(c.Path(), "metrics/clientcloudletusage") {
		in := ormapi.RegionClientCloudletUsageMetrics{}
		_, err := ReadConn(c, &in)
		if err != nil {
			return err
		}
		// Operator name has to be specified
		if in.Cloudlet.Organization == "" {
			return fmt.Errorf("Cloudlet details must be present")
		}
		// validate all the passed in arguments
		args := getClientCloudletUsageMetricsArgs(&in)
		if err = util.ValidateNames(args); err != nil {
			return err
		}

		rc.region = in.Region
		org = in.Cloudlet.Organization
		if err = validateSelectorString(in.Selector, CLIENT_CLOUDLETUSAGE); err != nil {
			return err
		}
		if err = validateClientCloudletUsageMetricReq(&in, in.Selector); err != nil {
			return err
		}
		if err = validateAndResolveInfluxMetricsCommon(&in.MetricsCommon); err != nil {
			return err
		}
		// Check the operator against who is logged in
		if err := authorized(ctx, rc.claims.Username, org, ResourceCloudletAnalytics, ActionView); err != nil {
			return err
		}

		settings, err := getSettings(ctx, rc.region)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelMetrics, "Unable to get metrics settings for region %v - error is %s", rc.region, err.Error())
		}
		var db string
		cmd, db = ClientCloudletUsageMetricsQuery(&in, settings)
		dbNames = append(dbNames, db)

	} else {
		return echo.ErrNotFound
	}

	err = influxStream(ctx, rc, dbNames, cmd, func(res interface{}) error {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		filterInfluxPayload(ctx, &payload, c.Path())
		return WriteStream(c, &payload)
	})
	if err != nil {
		return err
	}
	return nil
}

func filterInfluxPayload(ctx context.Context, payload *ormapi.StreamPayload, path string) {
	switch results := payload.Data.(type) {
	case []client.Result:
		if strings.HasSuffix(path, "metrics/clientappusage") || strings.HasSuffix(path, "metrics/clientcloudletusage") {
			// Set downsampled row.Name to "latency-metric" or "device-metric", because users don't care that data may have come from "latency-metric-10s"
			for ii := range results {
				for jj := range results[ii].Series {
					name := results[ii].Series[jj].Name
					if strings.Contains(name, cloudcommon.LatencyMetric) {
						results[ii].Series[jj].Name = cloudcommon.LatencyMetric
					} else if strings.Contains(name, cloudcommon.DeviceMetric) {
						results[ii].Series[jj].Name = cloudcommon.DeviceMetric
					} else {
						log.SpanLog(ctx, log.DebugLevelMetrics, "Row name does not contain \"latency-metric\" or \"device-metric\"", "name", name)
					}
				}
			}
		}
	default:
		log.SpanLog(ctx, log.DebugLevelMetrics, "Invalid type switch value. Expected []client.Result")
	}
}

// Check that the user is authorized to access all of the devOrgsPruned's devResource resources
func isDeveloperAuthorized(ctx context.Context, username string, devOrgsPruned []string, devResource string) (bool, map[string]struct{}, error) {
	authDevOrgs, err := enforcer.GetAuthorizedOrgs(ctx, username, devResource, ActionView)
	if err != nil {
		return false, nil, err
	}
	if _, found := authDevOrgs[""]; found {
		// admin
		return true, authDevOrgs, nil
	}
	// no args specified, so not authorized
	if len(devOrgsPruned) == 0 {
		return false, authDevOrgs, nil
	}
	// walk dev orgs and make sure that the developer is authorized for all the orgs passed in
	for _, devOrg := range devOrgsPruned {
		if _, devOrgPermOk := authDevOrgs[devOrg]; !devOrgPermOk {
			// in case we find that any of the orgs passed are not authorized, this developer is not authorized
			return false, authDevOrgs, nil
		}
	}
	return true, authDevOrgs, nil
}

// helper function to convert keys in a map to a list
func getListFromMap(mapIn map[edgeproto.CloudletKey]struct{}) []string {
	// collect all the list and return it
	listOut := []string{}
	for k, _ := range mapIn {
		listOut = append(listOut, k.Name)
	}
	return listOut
}

// Given a username, a list of devOrgs(from the api) and a list of cloudlets(from the api again)
// get the list of allowed Cloudlets.
// If this is a developer and it's authorized, the return list is either empty(all cloudlets allowed),
// or a list of cloudlets that was passed in.
// If this is an operator, the list of cloudlet keys passed in is checked against the cloudlet pools
// owned by the operator, if no cloudlet names are passed, the list of returned cloudlets will be
// a list of all cloudlets for an operator that are part of a cloudlet pool
func checkPermissionsAndGetCloudletList(ctx context.Context, username, region string, devOrgsIn []string, devResource string, cloudletKeys []edgeproto.CloudletKey) ([]string, error) {
	var err error

	regionRc := &ormutil.RegionContext{}
	regionRc.Username = username
	regionRc.Region = region
	regionRc.Database = database
	uniqueCloudlets := make(map[edgeproto.CloudletKey]struct{})
	devOrgPermOk := false
	operOrgPermOk := false
	devOrgs := []string{}
	cloudletOrgs := map[string]struct{}{}
	authDevOrgs := map[string]struct{}{}

	// remove all empty strings
	for ii, devOrg := range devOrgsIn {
		if devOrg != "" {
			devOrgs = append(devOrgs, devOrgsIn[ii])
		}
	}

	// since cloudletKeys is a slice, it could be an empty slice,
	// or a slice with a cloudletKeys that are empty keys
	// append to the list the specified cloudlets
	for _, cloudletKey := range cloudletKeys {
		if cloudletKey.Name != "" {
			uniqueCloudlets[cloudletKey] = struct{}{}
		}
		if cloudletKey.Organization != "" {
			cloudletOrgs[cloudletKey.Organization] = struct{}{}
		}
	}

	// orgField for better error string
	orgField := "App"
	if devResource == ResourceClusterAnalytics {
		orgField = "Cluster"
	}

	if len(devOrgs) == 0 && len(cloudletOrgs) == 0 {
		return []string{}, fmt.Errorf("Must provide either %s organization or Cloudlet organization", orgField)
	}

	// check if the developer is authorized
	if devOrgPermOk, authDevOrgs, err = isDeveloperAuthorized(ctx, username, devOrgs, devResource); err != nil {
		return []string{}, err
	}

	// At this point we need to check what cloudlets(cloudletPool members) are allowed for this operator
	authOperOrgs, err := enforcer.GetAuthorizedOrgs(ctx, username, ResourceCloudletAnalytics, ActionView)
	if err != nil {
		return []string{}, err
	}
	if _, found := authOperOrgs[""]; found {
		// admin
		operOrgPermOk = true
	} else if len(cloudletKeys) > 0 {
		operOrgPermOk = true
		for _, cloudletKey := range cloudletKeys {
			_, operOrgPermOk = authOperOrgs[cloudletKey.Organization]
			if !operOrgPermOk {
				operOrgPermOk = false
				break
			}
		}
	}

	// if a developer is authorized, just return the list now
	if devOrgPermOk {
		return getListFromMap(uniqueCloudlets), nil
	} else if !operOrgPermOk { // it could be operator and developer
		// no perms for specified orgs, or they forgot to specify an org that
		// they have perms to (since there are two choices)
		if len(devOrgs) == 0 && len(authDevOrgs) > 0 {
			// developer but didn't specify App org
			return []string{}, fmt.Errorf("Developers please specify the %s Organization", orgField)
		}
	}

	if !operOrgPermOk {
		if len(cloudletOrgs) == 0 && len(authOperOrgs) > 0 {
			return []string{}, fmt.Errorf("Operators please specify the Cloudlet Organization")
		} else {
			return []string{}, echo.ErrForbidden
		}
	}

	// only grab the cloudletpools if no specific cloudlet was mentioned
	if operOrgPermOk && len(uniqueCloudlets) == 0 {
		for cloudletOrg := range cloudletOrgs {
			cloudletpoolQuery := edgeproto.CloudletPool{Key: edgeproto.CloudletPoolKey{Organization: cloudletOrg}}
			err = ctrlclient.ShowCloudletPoolStream(ctx, regionRc, &cloudletpoolQuery, connCache, nil, func(pool *edgeproto.CloudletPool) error {
				for _, cloudlet := range pool.Cloudlets {
					uniqueCloudlets[cloudlet] = struct{}{}
				}
				return nil
			})
			if err != nil {
				return []string{}, err
			}
		}
	} else if len(uniqueCloudlets) >= 1 {
		//make sure the cloudlet is in a pool
		if operOrgPermOk {
			for _, cloudletKey := range cloudletKeys {
				if !allRegionCaches.InPool(region, cloudletKey) {
					return []string{}, fmt.Errorf("Operators must specify a cloudlet in a cloudletPool")
				}
			}
		}
	}
	if operOrgPermOk && len(uniqueCloudlets) == 0 {
		return []string{}, fmt.Errorf("No non-empty CloudletPools to show")
	}
	return getListFromMap(uniqueCloudlets), nil
}
