package orm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"text/template"

	influxdb "github.com/influxdata/influxdb/client/v2"
	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/log"
	"google.golang.org/grpc/status"
)

var devInfluxDBTemplate *template.Template
var operatorInfluxDBTemplate *template.Template

// 100 values at a time
var queryChunkSize = 100

type InfluxDBContext struct {
	region string
	claims *UserClaims
	conn   influxdb.Client
}

type influxQueryArgs struct {
	Selector      string
	Measurement   string
	AppInstName   string
	ClusterName   string
	DeveloperName string
	CloudletName  string
	OperatorName  string
	StartTime     string
	EndTime       string
	Last          int
}

var AppSelectors = []string{
	"cpu",
	"mem",
	"disk",
	"network",
	"connections",
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

const (
	APPINST  = "appinst"
	CLUSTER  = "cluster"
	CLOUDLET = "cloudlet"
)

var devInfluDBT = `SELECT {{.Selector}} from "{{.Measurement}}"` +
	` WHERE "dev"='{{.DeveloperName}}'` +
	`{{if .AppInstName}} AND "app"=~/{{.AppInstName}}/{{end}}` +
	`{{if .ClusterName}} AND "cluster"='{{.ClusterName}}'{{end}}` +
	`{{if .CloudletName}} AND "cloudlet"='{{.CloudletName}}'{{end}}` +
	`{{if .OperatorName}} AND "operator"='{{.OperatorName}}'{{end}}` +
	`{{if .StartTime}} AND time > '{{.StartTime}}'{{end}}` +
	`{{if .EndTime}} AND time < '{{.EndTime}}'{{end}}` +
	`order by time desc{{if ne .Last 0}} limit {{.Last}}{{end}}`

var operatorInfluDBT = `SELECT {{.Selector}} from "{{.Measurement}}"` +
	` WHERE "operator"='{{.OperatorName}}'` +
	`{{if .CloudletName}} AND "cloudlet"='{{.CloudletName}}'{{end}}` +
	`{{if .StartTime}} AND time > '{{.StartTime}}'{{end}}` +
	`{{if .EndTime}} AND time < '{{.EndTime}}'{{end}}` +
	`order by time desc{{if ne .Last 0}} limit {{.Last}}{{end}}`

func init() {
	devInfluxDBTemplate = template.Must(template.New("influxquery").Parse(devInfluDBT))
	operatorInfluxDBTemplate = template.Must(template.New("influxquery").Parse(operatorInfluDBT))
}

func connectInfluxDB(ctx context.Context, region string) (influxdb.Client, error) {
	addr, err := getInfluxDBAddrForRegion(ctx, region)
	if err != nil {
		return nil, err
	}
	creds, err := cloudcommon.GetInfluxDataAuth(serverConfig.vaultConfig, region)
	if err != nil {
		return nil, fmt.Errorf("get influxDB auth failed, %v", err)
	}
	if creds == nil {
		// defeault to empty auth
		creds = &cloudcommon.InfluxCreds{}
	}
	client, err := influxdb.NewHTTPClient(influxdb.HTTPConfig{
		Addr:     addr,
		Username: creds.User,
		Password: creds.Pass,
	})
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

// Query is a template with a specific set of if/else
func AppInstMetricsQuery(obj *ormapi.RegionAppInstMetrics) string {
	arg := influxQueryArgs{
		Selector:      "*",
		Measurement:   getMeasurementString(obj.Selector, APPINST),
		AppInstName:   k8smgmt.NormalizeName(obj.AppInst.AppKey.Name),
		DeveloperName: obj.AppInst.AppKey.DeveloperKey.Name,
		CloudletName:  obj.AppInst.ClusterInstKey.CloudletKey.Name,
		ClusterName:   obj.AppInst.ClusterInstKey.ClusterKey.Name,
		OperatorName:  obj.AppInst.ClusterInstKey.CloudletKey.OperatorKey.Name,
		Last:          obj.Last,
	}

	// Figure out the start/end time range for the query
	if !obj.StartTime.IsZero() {
		buf, err := obj.StartTime.MarshalText()
		if err == nil {
			arg.StartTime = string(buf)
		}
	}
	if !obj.EndTime.IsZero() {
		buf, err := obj.EndTime.MarshalText()
		if err == nil {
			arg.EndTime = string(buf)
		}
	}
	// now that we know all the details of the query - build it
	buf := bytes.Buffer{}
	if err := devInfluxDBTemplate.Execute(&buf, &arg); err != nil {
		return ""
	}
	return buf.String()
}

// Query is a template with a specific set of if/else
func ClusterMetricsQuery(obj *ormapi.RegionClusterInstMetrics) string {
	arg := influxQueryArgs{
		Selector:      "*",
		Measurement:   getMeasurementString(obj.Selector, CLUSTER),
		CloudletName:  obj.ClusterInst.CloudletKey.Name,
		ClusterName:   obj.ClusterInst.ClusterKey.Name,
		DeveloperName: obj.ClusterInst.Developer,
		OperatorName:  obj.ClusterInst.CloudletKey.OperatorKey.Name,
		Last:          obj.Last,
	}

	// Figure out the start/end time range for the query
	if !obj.StartTime.IsZero() {
		buf, err := obj.StartTime.MarshalText()
		if err == nil {
			arg.StartTime = string(buf)
		}
	}
	if !obj.EndTime.IsZero() {
		buf, err := obj.EndTime.MarshalText()
		if err == nil {
			arg.EndTime = string(buf)
		}
	}
	// now that we know all the details of the query - build it
	buf := bytes.Buffer{}
	if err := devInfluxDBTemplate.Execute(&buf, &arg); err != nil {
		return ""
	}
	return buf.String()
}

// Query is a template with a specific set of if/else
func CloudletMetricsQuery(obj *ormapi.RegionCloudletMetrics) string {
	arg := influxQueryArgs{
		Selector:     "*",
		Measurement:  getMeasurementString(obj.Selector, CLOUDLET),
		CloudletName: obj.Cloudlet.Name,
		OperatorName: obj.Cloudlet.OperatorKey.Name,
		Last:         obj.Last,
	}

	// Figure out the start/end time range for the query
	if !obj.StartTime.IsZero() {
		buf, err := obj.StartTime.MarshalText()
		if err == nil {
			arg.StartTime = string(buf)
		}
	}
	if !obj.EndTime.IsZero() {
		buf, err := obj.EndTime.MarshalText()
		if err == nil {
			arg.EndTime = string(buf)
		}
	}

	// now that we know all the details of the query - build it
	buf := bytes.Buffer{}
	if err := operatorInfluxDBTemplate.Execute(&buf, &arg); err != nil {
		return ""
	}
	return buf.String()

}

// TODO: This function should be a streaming fucntion, but currently client library for influxDB
// doesn't implement it in a way could really be using it
func metricsStream(ctx context.Context, rc *InfluxDBContext, dbQuery string, cb func(Data interface{})) error {
	if rc.conn == nil {
		conn, err := connectInfluxDB(ctx, rc.region)
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
		Database:  cloudcommon.DeveloperMetricsDbName,
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
	}
	if selector != "*" {
		measurements = strings.Split(selector, ",")
	}
	prefix := measurementType + "-"
	return prefix + strings.Join(measurements, "\",\""+prefix)
}

// Common method to handle both app and cluster metrics
func GetMetricsCommon(c echo.Context) error {
	var errStr, cmd, org string

	rc := &InfluxDBContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.claims = claims
	ctx := GetContext(c)

	if strings.HasSuffix(c.Path(), "metrics/app") {
		in := ormapi.RegionAppInstMetrics{}
		if err := c.Bind(&in); err != nil {
			errStr = fmt.Sprintf("Invalid POST data: %s", err.Error())
			return c.JSON(http.StatusBadRequest, Msg(errStr))
		}
		// Developer name has to be specified
		if in.AppInst.AppKey.DeveloperKey.Name == "" {
			return c.JSON(http.StatusBadRequest, Msg("App details must be present"))
		}
		rc.region = in.Region
		org = in.AppInst.AppKey.DeveloperKey.Name
		if err = validateSelectorString(in.Selector, APPINST); err != nil {
			return c.JSON(http.StatusBadRequest, Msg(err.Error()))
		}
		cmd = AppInstMetricsQuery(&in)

		// Check the developer against who is logged in
		if !authorized(ctx, rc.claims.Username, org, ResourceAppAnalytics, ActionView) {
			return echo.ErrForbidden
		}
	} else if strings.HasSuffix(c.Path(), "metrics/cluster") {
		in := ormapi.RegionClusterInstMetrics{}
		if err := c.Bind(&in); err != nil {
			errStr = fmt.Sprintf("Invalid POST data: %s", err.Error())
			return c.JSON(http.StatusBadRequest, Msg(errStr))
		}
		// Developer name has to be specified
		if in.ClusterInst.Developer == "" {
			return c.JSON(http.StatusBadRequest, Msg("Cluster details must be present"))
		}
		rc.region = in.Region
		org = in.ClusterInst.Developer
		if err = validateSelectorString(in.Selector, CLUSTER); err != nil {
			return c.JSON(http.StatusBadRequest, Msg(err.Error()))
		}
		cmd = ClusterMetricsQuery(&in)

		// Check the developer against who is logged in
		if !authorized(ctx, rc.claims.Username, org, ResourceClusterAnalytics, ActionView) {
			return echo.ErrForbidden
		}
	} else if strings.HasSuffix(c.Path(), "metrics/cloudlet") {
		in := ormapi.RegionCloudletMetrics{}
		if err := c.Bind(&in); err != nil {
			errStr = fmt.Sprintf("Invalid POST data: %s", err.Error())
			return c.JSON(http.StatusBadRequest, Msg(errStr))
		}
		// Operator name has to be specified
		if in.Cloudlet.OperatorKey.Name == "" {
			return c.JSON(http.StatusBadRequest, Msg("Cloudlet details must be present"))
		}
		rc.region = in.Region
		org = in.Cloudlet.OperatorKey.Name
		if err = validateSelectorString(in.Selector, CLOUDLET); err != nil {
			return c.JSON(http.StatusBadRequest, Msg(err.Error()))
		}
		cmd = CloudletMetricsQuery(&in)

		// Check the operator against who is logged in
		if !authorized(ctx, rc.claims.Username, org, ResourceCloudletAnalytics, ActionView) {
			return echo.ErrForbidden
		}
	} else {
		return echo.ErrNotFound
	}

	wroteHeader := false
	err = metricsStream(ctx, rc, cmd, func(res interface{}) {
		if !wroteHeader {
			c.Response().Header().Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			c.Response().WriteHeader(http.StatusOK)
			wroteHeader = true
		}
		payload := ormapi.StreamPayload{}
		payload.Data = res
		json.NewEncoder(c.Response()).Encode(payload)
		c.Response().Flush()
	})
	if err != nil {
		if st, ok := status.FromError(err); ok {
			err = fmt.Errorf("%s", st.Message())
		}
		if !wroteHeader {
			return setReply(c, err, nil)
		}
		res := ormapi.Result{}
		res.Message = err.Error()
		res.Code = http.StatusBadRequest
		payload := ormapi.StreamPayload{Result: &res}
		json.NewEncoder(c.Response()).Encode(payload)
	}
	return nil
}
