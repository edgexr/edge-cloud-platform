package orm

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"text/template"
	"time"

	influxdb "github.com/influxdata/influxdb/client/v2"
	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/cloudcommon/influxsup"
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
	Method         string
	CellId         string
	StartTime      string
	EndTime        string
	DeploymentType string
	Last           int
	CloudletList   string
}

var AppSelectors = []string{
	"cpu",
	"mem",
	"disk",
	"network",
	"connections",
	"udp",
}

var ClusterSelectors = []string{
	"cpu",
	"mem",
	"disk",
	"network",
	"tcp",
	"udp",
}

var CloudletSelectors = []string{
	"network",
	"utilization",
	"ipusage",
}

var ClientSelectors = []string{
	"api",
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

// ClientFields is DME metrics
var ClientFields = []string{
	"\"apporg\"",
	"\"app\"",
	"\"ver\"",
	"\"cloudletorg\"",
	"\"cloudlet\"",
}

var ApiFields = []string{
	"\"id\"",
	"\"cellID\"",
	"\"method\"",
	"\"foundCloudlet\"",
	"\"foundOperator\"",
	"\"reqs\"",
	"\"errs\"",
	"\"5ms\"",
	"\"10ms\"",
	"\"25ms\"",
	"\"50ms\"",
	"\"100ms\"",
	"\"inf\"",
}

var PodFields = []string{
	"\"pod\"",
}

var CpuFields = []string{
	"\"cpu\"",
}

var MemFields = []string{
	"\"mem\"",
}

var DiskFields = []string{
	"\"disk\"",
}

var NetworkFields = []string{
	"\"sendBytes\"",
	"\"recvBytes\"",
}

var TcpFields = []string{
	"\"tcpConns\"",
	"\"tcpRetrans\"",
}

var UdpFields = []string{
	"\"udpSent\"",
	"\"udpRecv\"",
	"\"udpRecvErr\"",
}

var ConnectionsFields = []string{
	"\"port\"",
	"\"active\"",
	"\"handled\"",
	"\"accepts\"",
	"\"bytesSent\"",
	"\"bytesRecvd\"",
	"\"P0\"",
	"\"P25\"",
	"\"P50\"",
	"\"P75\"",
	"\"P90\"",
	"\"P95\"",
	"\"P99\"",
	"\"P99.5\"",
	"\"P99.9\"",
	"\"P100\"",
}

var appUdpFields = []string{
	"\"port\"",
	"\"bytesSent\"",
	"\"bytesRecvd\"",
	"\"datagramsSent\"",
	"\"datagramsRecvd\"",
	"\"sentErrs\"",
	"\"recvErrs\"",
	"\"overflow\"",
	"\"missed\"",
}

var UtilizationFields = []string{
	"\"vCpuUsed\"",
	"\"vCpuMax\"",
	"\"memUsed\"",
	"\"memMax\"",
	"\"diskUsed\"",
	"\"diskMax\"",
}

var CloudletNetworkFields = []string{
	"\"netSend\"",
	"\"netRecv\"",
}

var IpUsageFields = []string{
	"\"floatingIpsUsed\"",
	"\"floatingIpsMax\"",
	"\"ipv4Used\"",
	"\"ipv4Max\"",
}

const (
	APPINST  = "appinst"
	CLUSTER  = "cluster"
	CLOUDLET = "cloudlet"
	CLIENT   = "dme"
)

var devInfluxDBT = `SELECT {{.Selector}} from "{{.Measurement}}"` +
	` WHERE "{{.OrgField}}"='{{.ApiCallerOrg}}'` +
	`{{if .AppInstName}} AND "app"='{{.AppInstName}}'{{end}}` +
	`{{if .ClusterName}} AND "cluster"='{{.ClusterName}}'{{end}}` +
	`{{if .AppVersion}} AND "ver"='{{.AppVersion}}'{{end}}` +
	`{{if .CloudletName}} AND "cloudlet"='{{.CloudletName}}'{{end}}` +
	`{{if .CloudletOrg}} AND "cloudletorg"='{{.CloudletOrg}}'{{end}}` +
	`{{if .Method}} AND "method"='{{.Method}}'{{end}}` +
	`{{if .CellId}} AND "cellID"='{{.CellId}}'{{end}}` +
	`{{if .StartTime}} AND time >= '{{.StartTime}}'{{end}}` +
	`{{if .EndTime}} AND time <= '{{.EndTime}}'{{end}}` +
	`{{if .DeploymentType}} AND deployment = '{{.DeploymentType}}'{{end}}` +
	` order by time desc{{if ne .Last 0}} limit {{.Last}}{{end}}`

var operatorInfluxDBT = `SELECT {{.Selector}} from "{{.Measurement}}"` +
	` WHERE "cloudletorg"='{{.CloudletOrg}}'` +
	`{{if .CloudletName}} AND "cloudlet"='{{.CloudletName}}'{{end}}` +
	`{{if .StartTime}} AND time >= '{{.StartTime}}'{{end}}` +
	`{{if .EndTime}} AND time <= '{{.EndTime}}'{{end}}` +
	` order by time desc{{if ne .Last 0}} limit {{.Last}}{{end}}`

func init() {
	devInfluxDBTemplate = template.Must(template.New("influxquery").Parse(devInfluxDBT))
	operatorInfluxDBTemplate = template.Must(template.New("influxquery").Parse(operatorInfluxDBT))
}

func ConnectInfluxDB(ctx context.Context, region string) (influxdb.Client, error) {
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

func ClientMetricsQuery(obj *ormapi.RegionClientMetrics) string {
	arg := influxQueryArgs{
		Selector:     getFields(obj.Selector, CLIENT),
		Measurement:  getMeasurementString(obj.Selector, CLIENT),
		AppInstName:  obj.AppInst.AppKey.Name,
		AppVersion:   obj.AppInst.AppKey.Version,
		OrgField:     "apporg",
		ApiCallerOrg: obj.AppInst.AppKey.Organization,
		ClusterOrg:   obj.AppInst.ClusterInstKey.Organization,
		CloudletName: obj.AppInst.ClusterInstKey.CloudletKey.Name,
		ClusterName:  obj.AppInst.ClusterInstKey.ClusterKey.Name,
		CloudletOrg:  obj.AppInst.ClusterInstKey.CloudletKey.Organization,
		Method:       obj.Method,
		Last:         obj.Last,
	}
	if obj.CellId != 0 {
		arg.CellId = strconv.FormatUint(uint64(obj.CellId), 10)
	}
	return fillTimeAndGetCmd(&arg, devInfluxDBTemplate, &obj.StartTime, &obj.EndTime)
}

// Query is a template with a specific set of if/else
func AppInstMetricsQuery(obj *ormapi.RegionAppInstMetrics) string {
	arg := influxQueryArgs{
		Selector:     getFields(obj.Selector, APPINST),
		Measurement:  getMeasurementString(obj.Selector, APPINST),
		AppInstName:  util.DNSSanitize(obj.AppInst.AppKey.Name),
		AppVersion:   util.DNSSanitize(obj.AppInst.AppKey.Version),
		OrgField:     "apporg",
		ApiCallerOrg: obj.AppInst.AppKey.Organization,
		CloudletName: obj.AppInst.ClusterInstKey.CloudletKey.Name,
		ClusterName:  obj.AppInst.ClusterInstKey.ClusterKey.Name,
		CloudletOrg:  obj.AppInst.ClusterInstKey.CloudletKey.Organization,
		Last:         obj.Last,
	}
	return fillTimeAndGetCmd(&arg, devInfluxDBTemplate, &obj.StartTime, &obj.EndTime)
}

// Query is a template with a specific set of if/else
func ClusterMetricsQuery(obj *ormapi.RegionClusterInstMetrics) string {
	arg := influxQueryArgs{
		Selector:     getFields(obj.Selector, CLUSTER),
		Measurement:  getMeasurementString(obj.Selector, CLUSTER),
		CloudletName: obj.ClusterInst.CloudletKey.Name,
		ClusterName:  obj.ClusterInst.ClusterKey.Name,
		OrgField:     "clusterorg",
		ApiCallerOrg: obj.ClusterInst.Organization,
		CloudletOrg:  obj.ClusterInst.CloudletKey.Organization,
		Last:         obj.Last,
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

// TODO: This function should be a streaming function, but currently client library for influxDB
// doesn't implement it in a way could really be using it
func influxStream(ctx context.Context, rc *InfluxDBContext, database, dbQuery string, cb func(Data interface{})) error {
	if rc.conn == nil {
		conn, err := ConnectInfluxDB(ctx, rc.region)
		if err != nil {
			return err
		}
		rc.conn = conn
		defer func() {
			rc.conn.Close()
			rc.conn = nil
		}()
	}

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
		// We return a different error, as we don't want to expose a URL-encoded query to influxDB
		return fmt.Errorf("Connection to InfluxDB failed")
	}
	if resp.Error() != nil {
		return resp.Error()
	}
	cb(resp.Results)
	return nil
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
		validSelectors = AppSelectors
	case CLUSTER:
		validSelectors = ClusterSelectors
	case CLOUDLET:
		validSelectors = CloudletSelectors
	case CLIENT:
		validSelectors = ClientSelectors
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
	case "appinst":
		measurements = AppSelectors
	case "cluster":
		measurements = ClusterSelectors
	case "cloudlet":
		measurements = CloudletSelectors
	case "client":
		measurements = ClientSelectors
	}
	if selector != "*" {
		measurements = strings.Split(selector, ",")
	}
	prefix := measurementType + "-"
	return prefix + strings.Join(measurements, "\",\""+prefix)
}

func getFields(selector, measurementType string) string {
	var fields, selectors []string
	switch measurementType {
	case "appinst":
		fields = AppFields
		// If this is not connections selector add pod field
		if selector != "connections" {
			fields = append(fields, PodFields...)
		}
		selectors = AppSelectors
	case "cluster":
		fields = ClusterFields
		selectors = ClusterSelectors
	case "cloudlet":
		fields = CloudletFields
		selectors = CloudletSelectors
	case "client":
		fields = ClientFields
		selectors = ClientSelectors
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
			if measurementType == "cloudlet" {
				fields = append(fields, CloudletNetworkFields...)
			} else {
				fields = append(fields, NetworkFields...)
			}
		case "connections":
			fields = append(fields, ConnectionsFields...)
		case "tcp":
			fields = append(fields, TcpFields...)
		case "udp":
			if measurementType == "appinst" {
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
	if strings.HasSuffix(c.Path(), "metrics/app") {
		in := ormapi.RegionAppInstMetrics{}
		success, err := ReadConn(c, &in)
		if !success {
			return err
		}
		// Developer name has to be specified
		if in.AppInst.AppKey.Organization == "" {
			return setReply(c, fmt.Errorf("App details must be present"), nil)
		}
		rc.region = in.Region
		org = in.AppInst.AppKey.Organization
		if err = validateSelectorString(in.Selector, APPINST); err != nil {
			return setReply(c, err, nil)
		}
		cmd = AppInstMetricsQuery(&in)

		// Check the developer against who is logged in
		if err := authorized(ctx, rc.claims.Username, org, ResourceAppAnalytics, ActionView); err != nil {
			return setReply(c, err, nil)
		}
	} else if strings.HasSuffix(c.Path(), "metrics/cluster") {
		in := ormapi.RegionClusterInstMetrics{}
		success, err := ReadConn(c, &in)
		if !success {
			return err
		}
		// Developer organization name has to be specified
		if in.ClusterInst.Organization == "" {
			return setReply(c, fmt.Errorf("Cluster details must be present"), nil)
		}
		rc.region = in.Region
		org = in.ClusterInst.Organization
		if err = validateSelectorString(in.Selector, CLUSTER); err != nil {
			return setReply(c, err, nil)
		}
		cmd = ClusterMetricsQuery(&in)

		// Check the developer against who is logged in
		if err := authorized(ctx, rc.claims.Username, org, ResourceClusterAnalytics, ActionView); err != nil {
			return err
		}
	} else if strings.HasSuffix(c.Path(), "metrics/cloudlet") {
		in := ormapi.RegionCloudletMetrics{}
		success, err := ReadConn(c, &in)
		if !success {
			return err
		}
		// Operator name has to be specified
		if in.Cloudlet.Organization == "" {
			return setReply(c, fmt.Errorf("Cloudlet details must be present"), nil)
		}
		rc.region = in.Region
		org = in.Cloudlet.Organization
		if err = validateSelectorString(in.Selector, CLOUDLET); err != nil {
			return setReply(c, err, nil)
		}
		cmd = CloudletMetricsQuery(&in)

		// Check the operator against who is logged in
		if err := authorized(ctx, rc.claims.Username, org, ResourceCloudletAnalytics, ActionView); err != nil {
			return setReply(c, err, nil)
		}
	} else if strings.HasSuffix(c.Path(), "metrics/client") {
		in := ormapi.RegionClientMetrics{}
		success, err := ReadConn(c, &in)
		if !success {
			return err
		}
		// Developer name has to be specified
		if in.AppInst.AppKey.Organization == "" {
			return setReply(c, fmt.Errorf("App details must be present"), nil)
		}
		rc.region = in.Region
		org = in.AppInst.AppKey.Organization
		if err = validateSelectorString(in.Selector, CLIENT); err != nil {
			return setReply(c, err, nil)
		}
		cmd = ClientMetricsQuery(&in)
		// Check the developer against who is logged in
		// Should the operators logged in be allowed to see the API usage of the apps on their cloudlets?
		if err := authorized(ctx, rc.claims.Username, org, ResourceAppAnalytics, ActionView); err != nil {
			return setReply(c, err, nil)
		}
	} else {
		return setReply(c, echo.ErrNotFound, nil)
	}

	err = influxStream(ctx, rc, cloudcommon.DeveloperMetricsDbName, cmd, func(res interface{}) {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		WriteStream(c, &payload)
	})
	if err != nil {
		return WriteError(c, err)
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
