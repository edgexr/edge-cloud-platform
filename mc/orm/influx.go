package orm

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"text/template"
	"time"

	influxdb "github.com/influxdata/influxdb/client/v2"
	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	pf "github.com/mobiledgex/edge-cloud/cloud-resource-manager/platform"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/cloudcommon/influxsup"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/util"
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
	StartTime      string
	EndTime        string
	Last           int
	DeploymentType string
	CloudletList   string
	QueryFilter    string
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
	"*",
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

var devInfluxDBT = `SELECT {{.Selector}} from /{{.Measurement}}/` +
	` WHERE "{{.OrgField}}"='{{.ApiCallerOrg}}'` +
	`{{if .AppInstName}} AND "app"='{{.AppInstName}}'{{end}}` +
	`{{if .AppOrg}} AND "apporg"='{{.AppOrg}}'{{end}}` +
	`{{if .ClusterName}} AND "cluster"='{{.ClusterName}}'{{end}}` +
	`{{if .AppVersion}} AND "ver"='{{.AppVersion}}'{{end}}` +
	`{{if .CloudletName}} AND "cloudlet"='{{.CloudletName}}'{{end}}` +
	`{{if .CloudletOrg}} AND "cloudletorg"='{{.CloudletOrg}}'{{end}}` +
	`{{if .StartTime}} AND time >= '{{.StartTime}}'{{end}}` +
	`{{if .EndTime}} AND time <= '{{.EndTime}}'{{end}}` +
	`{{if .DeploymentType}} AND deployment = '{{.DeploymentType}}'{{end}}` +
	`{{if .CloudletList}} AND ({{.CloudletList}}){{end}}` +
	` order by time desc{{if ne .Last 0}} limit {{.Last}}{{end}}`

var operatorInfluxDBT = `SELECT {{.Selector}} from /{{.Measurement}}/` +
	` WHERE "cloudletorg"='{{.CloudletOrg}}'` +
	`{{if .CloudletName}} AND "cloudlet"='{{.CloudletName}}'{{end}}` +
	`{{if .StartTime}} AND time >= '{{.StartTime}}'{{end}}` +
	`{{if .EndTime}} AND time <= '{{.EndTime}}'{{end}}` +
	` order by time desc{{if ne .Last 0}} limit {{.Last}}{{end}}`

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

func fillTimeAndGetCmd(q *influxQueryArgs, tmpl *template.Template, start *time.Time, end *time.Time) string {
	// Figure out the start/end time range for the query
	if !start.IsZero() {
		buf, err := start.MarshalText()
		if err == nil {
			q.StartTime = string(buf)
		}
	}
	if !end.IsZero() {
		buf, err := end.MarshalText()
		if err == nil {
			q.EndTime = string(buf)
		}
	}
	// We set max number of responses we will get from InfluxDB
	if q.Last == 0 {
		q.Last = maxEntriesFromInfluxDb
	}
	// now that we know all the details of the query - build it
	buf := bytes.Buffer{}
	if err := tmpl.Execute(&buf, q); err != nil {
		log.DebugLog(log.DebugLevelApi, "Failed to run template", "tmpl", tmpl, "args", q, "error", err)
		return ""
	}
	return buf.String()
}

// Query is a template with a specific set of if/else
func AppInstMetricsQuery(obj *ormapi.RegionAppInstMetrics, cloudletList []string) string {
	arg := influxQueryArgs{
		Selector:     getFields(obj.Selector, APPINST),
		Measurement:  getMeasurementString(obj.Selector, APPINST),
		AppInstName:  util.DNSSanitize(obj.AppInst.AppKey.Name),
		AppVersion:   util.DNSSanitize(obj.AppInst.AppKey.Version),
		ClusterName:  obj.AppInst.ClusterInstKey.ClusterKey.Name,
		CloudletList: generateCloudletList(cloudletList),
		Last:         obj.Last,
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
	return fillTimeAndGetCmd(&arg, devInfluxDBTemplate, &obj.StartTime, &obj.EndTime)
}

// Query is a template with a specific set of if/else
func ClusterMetricsQuery(obj *ormapi.RegionClusterInstMetrics, cloudletList []string) string {
	arg := influxQueryArgs{
		Selector:     getFields(obj.Selector, CLUSTER),
		Measurement:  getMeasurementString(obj.Selector, CLUSTER),
		ClusterName:  obj.ClusterInst.ClusterKey.Name,
		CloudletList: generateCloudletList(cloudletList),
		Last:         obj.Last,
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
	return fillTimeAndGetCmd(&arg, devInfluxDBTemplate, &obj.StartTime, &obj.EndTime)
}

// Query is a template with a specific set of if/else
func CloudletMetricsQuery(obj *ormapi.RegionCloudletMetrics) string {
	arg := influxQueryArgs{
		Selector:     getFields(obj.Selector, CLOUDLET),
		Measurement:  getMeasurementString(obj.Selector, CLOUDLET),
		CloudletName: obj.Cloudlet.Name,
		CloudletOrg:  obj.Cloudlet.Organization,
		Last:         obj.Last,
	}
	return fillTimeAndGetCmd(&arg, operatorInfluxDBTemplate, &obj.StartTime, &obj.EndTime)
}

// Query is a template with a specific set of if/else
func CloudletUsageMetricsQuery(obj *ormapi.RegionCloudletMetrics) string {
	arg := influxQueryArgs{
		//Selector:     getFields(obj.Selector, CLOUDLETUSAGE),
		Selector:     "*",
		Measurement:  getCloudletUsageMeasurementString(obj.Selector, obj.PlatformType),
		CloudletName: obj.Cloudlet.Name,
		CloudletOrg:  obj.Cloudlet.Organization,
		Last:         obj.Last,
	}
	return fillTimeAndGetCmd(&arg, operatorInfluxDBTemplate, &obj.StartTime, &obj.EndTime)
}

// TODO: This function should be a streaming function, but currently client library for influxDB
// doesn't implement it in a way could really be using it
func influxStream(ctx context.Context, rc *InfluxDBContext, databases []string, dbQuery string, cb func(Data interface{}) error) error {
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
			return fmt.Errorf("Invalid %s selector: %s", metricType, s)
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
	return prefix + strings.Join(measurements, "|"+prefix)
}

func getCloudletUsageMeasurementString(selector, platformType string) string {
	measurements := []string{}
	selectors := ormapi.CloudletUsageSelectors
	if selector != "*" {
		selectors = strings.Split(selector, ",")
	}
	for _, cSelector := range selectors {
		if cSelector == "resourceusage" {
			measurements = append(measurements, fmt.Sprintf("%s-resource-usage", platformType))
		} else if selector == "flavorusage" {
			measurements = append(measurements, "cloudlet-flavor-usage")
		} else {
			measurements = append(measurements, cSelector)
		}
	}
	return strings.Join(measurements, "|")
}

func getFields(selector, measurementType string) string {
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
		fields = ClientApiUsageFields
		selectors = ormapi.ClientApiUsageSelectors
	case CLIENT_APPUSAGE:
		fields = ClientAppUsageFields
		selectors = ormapi.ClientAppUsageSelectors
	case CLIENT_CLOUDLETUSAGE:
		fields = ClientCloudletUsageFields
		selectors = ormapi.ClientCloudletUsageSelectors
	default:
		return "*"
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
			if measurementType == CLIENT_APPUSAGE {
				fields = append(fields, ClientAppUsageLatencyFields...)
			} else {
				fields = append(fields, ClientCloudletUsageLatencyFields...)
			}
		case "deviceinfo":
			fields = append(fields, DeviceInfoFields...)
			if measurementType == CLIENT_APPUSAGE {
				fields = append(fields, ClientAppUsageDeviceInfoFields...)
			} else {
				fields = append(fields, ClientCloudletUsageDeviceInfoFields...)
			}
		case "custom":
		}
	}
	return strings.Join(fields, ",")
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
	ctx := GetContext(c)
	// Get the current config
	config, err := getConfig(ctx)
	if err == nil {
		maxEntriesFromInfluxDb = config.MaxMetricsDataPoints
	}
	dbNames := []string{}
	if strings.HasSuffix(c.Path(), "metrics/app") {
		in := ormapi.RegionAppInstMetrics{}
		success, err := ReadConn(c, &in)
		if !success {
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
		success, err := ReadConn(c, &in)
		if !success {
			return err
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
		success, err := ReadConn(c, &in)
		if !success {
			return err
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
		cmd = CloudletMetricsQuery(&in)

		// Check the operator against who is logged in
		if err := authorized(ctx, rc.claims.Username, org, ResourceCloudletAnalytics, ActionView); err != nil {
			return err
		}
	} else if strings.HasSuffix(c.Path(), "metrics/clientapiusage") {
		dbNames = append(dbNames, cloudcommon.DeveloperMetricsDbName)
		in := ormapi.RegionClientApiUsageMetrics{}
		success, err := ReadConn(c, &in)
		if !success {
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
		cmd = ClientApiUsageMetricsQuery(&in, cloudletList)

	} else if strings.HasSuffix(c.Path(), "metrics/cloudlet/usage") {
		dbNames = append(dbNames, cloudcommon.CloudletResourceUsageDbName)
		in := ormapi.RegionCloudletMetrics{}
		success, err := ReadConn(c, &in)
		if !success {
			return err
		}
		// Operator name has to be specified
		if in.Cloudlet.Organization == "" {
			return fmt.Errorf("Cloudlet details must be present")
		}
		// Platform type is required for cloudlet resource usage
		platformTypes := make(map[string]struct{})
		if in.Selector == "resourceusage" {
			rc := &RegionContext{}
			rc.username = claims.Username
			rc.region = in.Region
			obj := edgeproto.Cloudlet{
				Key: in.Cloudlet,
			}
			err = ShowCloudletStream(ctx, rc, &obj, func(res *edgeproto.Cloudlet) error {
				pfType := pf.GetType(res.PlatformType.String())
				platformTypes[pfType] = struct{}{}
				return nil
			})
			if err != nil {
				return err
			}
			if len(platformTypes) == 0 {
				return setReply(c, nil)
			}
		}
		rc.region = in.Region
		org = in.Cloudlet.Organization
		if err = validateSelectorString(in.Selector, CLOUDLETUSAGE); err != nil {
			return err
		}
		cmd = CloudletUsageMetricsQuery(&in)

		// Check the operator against who is logged in
		if err := authorized(ctx, rc.claims.Username, org, ResourceCloudletAnalytics, ActionView); err != nil {
			return err
		}
	} else if strings.HasSuffix(c.Path(), "metrics/clientappusage") {
		in := ormapi.RegionClientAppUsageMetrics{}
		success, err := ReadConn(c, &in)
		if !success {
			return err
		}
		// If not raw data, pull from downsampled metrics
		if in.RawData {
			dbNames = append(dbNames, cloudcommon.EdgeEventsMetricsDbName)
		} else {
			dbNames = append(dbNames, cloudcommon.DownsampledMetricsDbName)
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
		cmd = ClientAppUsageMetricsQuery(&in, cloudletList)
	} else if strings.HasSuffix(c.Path(), "metrics/clientcloudletusage") {
		in := ormapi.RegionClientCloudletUsageMetrics{}
		success, err := ReadConn(c, &in)
		if !success {
			return err
		}
		// If not raw data, pull from downsampled metrics
		if in.RawData {
			dbNames = append(dbNames, cloudcommon.EdgeEventsMetricsDbName)
		} else {
			dbNames = append(dbNames, cloudcommon.DownsampledMetricsDbName)
		}
		// Operator name has to be specified
		if in.Cloudlet.Organization == "" {
			return fmt.Errorf("Cloudlet details must be present")
		}
		rc.region = in.Region
		org = in.Cloudlet.Organization
		if err = validateSelectorString(in.Selector, CLIENT_CLOUDLETUSAGE); err != nil {
			return err
		}
		if err = validateClientCloudletUsageMetricReq(&in, in.Selector); err != nil {
			return err
		}
		cmd = ClientCloudletUsageMetricsQuery(&in)

		// Check the operator against who is logged in
		if err := authorized(ctx, rc.claims.Username, org, ResourceCloudletAnalytics, ActionView); err != nil {
			return err
		}
	} else {
		return echo.ErrNotFound
	}

	err = influxStream(ctx, rc, dbNames, cmd, func(res interface{}) error {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		return WriteStream(c, &payload)
	})
	if err != nil {
		return err
	}
	return nil
}

func checkForTimeError(errStr string) string {
	// special case for errors regarding time format
	// golang's reference time is "2006-01-02T15:04:05Z07:00" (123456 in the posix date command), which is confusing
	refTime := "2006-01-02T15:04:05Z07:00"
	if strings.Contains(errStr, refTime) {
		return fmt.Sprintf("%s into RFC3339 format failed. Example: \"%s\"", strings.Split(errStr, " as")[0], refTime)
	}
	return errStr
}

func checkPermissionsAndGetCloudletList(ctx context.Context, username, region string, devOrgsIn []string, devResource string, cloudletKeys []edgeproto.CloudletKey) ([]string, error) {
	regionRc := &RegionContext{}
	regionRc.username = username
	regionRc.region = region
	uniqueCloudlets := make(map[string]struct{})
	devOrgPermOk := false
	operOrgPermOk := false
	devOrgs := []string{}
	cloudletOrgs := map[string]struct{}{}

	// remove all empty strings
	for ii, devOrg := range devOrgsIn {
		if devOrg != "" {
			devOrgs = append(devOrgs, devOrgsIn[ii])
		}
	}

	// append to the list the specified cloudlets
	for _, cloudletKey := range cloudletKeys {
		if cloudletKey.Name != "" {
			uniqueCloudlets[cloudletKey.Name] = struct{}{}
		}
		if cloudletKey.Organization != "" {
			cloudletOrgs[cloudletKey.Organization] = struct{}{}
		}
	}

	if len(devOrgs) == 0 && len(cloudletOrgs) == 0 {
		return []string{}, fmt.Errorf("Must provide either App organization or Cloudlet organization")
	}
	authDevOrgs, err := enforcer.GetAuthorizedOrgs(ctx, username, devResource, ActionView)
	if err != nil {
		return []string{}, err
	}
	if _, found := authDevOrgs[""]; found {
		// admin
		devOrgPermOk = true
	} else if len(devOrgs) > 0 {
		devOrgPermOk = true
		for _, devOrg := range devOrgs {
			_, devOrgPermOk = authDevOrgs[devOrg]
			if !devOrgPermOk {
				// in case we find that any of the orgs passed are not authorized, break
				devOrgPermOk = false
				break
			}
		}
	}
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
	if !devOrgPermOk && !operOrgPermOk {
		// no perms for specified orgs, or they forgot to specify an org that
		// they have perms to (since there are two choices)
		if len(devOrgs) == 0 && len(authDevOrgs) > 0 {
			// developer but didn't specify App org
			orgField := "App"
			if devResource == ResourceClusterAnalytics {
				orgField = "Cluster"
			}
			return []string{}, fmt.Errorf("Developers please specify the %s Organization", orgField)
		} else if len(cloudletKeys) == 0 && len(authOperOrgs) > 0 {
			return []string{}, fmt.Errorf("Operators please specify the Cloudlet Organization")
		} else {
			return []string{}, echo.ErrForbidden
		}
	}

	// only grab the cloudletpools if no specific cloudlet was mentioned
	getPools := false
	if operOrgPermOk && len(uniqueCloudlets) == 0 {
		getPools = true
		// operator specified an apporg. If it is an org the user is a part of then just show everything tied to that org
		// if the user is not part of the org, then only show the metrics of the org inside the operator's cloudletpools
		if devOrgPermOk {
			getPools = false
		}
	}
	if getPools {
		for cloudletOrg := range cloudletOrgs {
			cloudletpoolQuery := edgeproto.CloudletPool{Key: edgeproto.CloudletPoolKey{Organization: cloudletOrg}}
			cloudletPools, err := ShowCloudletPoolObj(ctx, regionRc, &cloudletpoolQuery)
			if err != nil {
				return []string{}, err
			}
			for _, pool := range cloudletPools {
				for _, cloudlet := range pool.Cloudlets {
					uniqueCloudlets[cloudlet] = struct{}{}
				}
			}
		}
	} else if len(uniqueCloudlets) >= 1 {
		//make sure the cloudlet is in a pool
		if operOrgPermOk && !devOrgPermOk {
			for _, cloudletKey := range cloudletKeys {
				if !allRegionCaches.InPool(region, cloudletKey) {
					return []string{}, fmt.Errorf("Operators must specify a cloudlet in a cloudletPool")
				}
			}
		}
	}
	if operOrgPermOk && !devOrgPermOk && len(uniqueCloudlets) == 0 {
		return []string{}, fmt.Errorf("No non-empty CloudletPools to show")
	}
	// collect all the list and return it
	cloudletList := []string{}
	for k, _ := range uniqueCloudlets {
		cloudletList = append(cloudletList, k)
	}
	return cloudletList, nil
}
