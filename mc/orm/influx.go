package orm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"text/template"

	influxdb "github.com/influxdata/influxdb/client/v2"
	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	"github.com/mobiledgex/edge-cloud/log"
	"google.golang.org/grpc/status"
)

var influxDBTemplate *template.Template

// 100 values at a time
var queryChunkSize = 100

type InfluxDBContext struct {
	region string
	claims *UserClaims
	conn   influxdb.Client
}

type influxQueryArgs struct {
	Selector     string
	Measurement  string
	AppInstName  string
	ClusterName  string
	CloudletName string
	OperatorName string
	StartTime    string
	EndTime      string
}

var influDBT = `SELECT {{if .Selector}}"{{.Selector}}"{{else}}*{{end}} from "{{.Measurement}}"` +
	` WHERE "cluster"='{{.ClusterName}}'` +
	`{{if .AppInstName}} AND "app"=~/{{.AppInstName}}/{{end}}` +
	`{{if .CloudletName}} AND "cloudlet"='{{.CloudletName}}'{{end}}` +
	`{{if .OperatorName}} AND "operator"='{{.OperatorName}}'{{end}}` +
	`{{if .StartTime}} AND time > '{{.StartTime}}'{{end}}` +
	`{{if .EndTime}} AND time < '{{.EndTime}}'{{end}}`

func init() {
	influxDBTemplate = template.Must(template.New("influxquery").Parse(influDBT))
}

func connectInfluxDB(region string) (influxdb.Client, error) {
	addr, err := getInfluxDBAddrForRegion(region)
	if err != nil {
		return nil, err
	}
	creds := cloudcommon.GetInfluxDataAuth(serverConfig.VaultAddr, region)
	if creds == nil {
		// defeault to empty auth
		creds = &cloudcommon.InfluxCreds{}
	}
	client, err := influxdb.NewHTTPClient(influxdb.HTTPConfig{
		Addr:     addr,
		Username: creds.User,
		Password: creds.Pass,
	})
	log.DebugLog(log.DebugLevelMetrics, "connecting to influxdb",
		"addr", addr, "err", err)
	if err != nil {
		return nil, err
	}
	return client, nil

}

func getInfluxDBAddrForRegion(region string) (string, error) {
	ctrl, err := getControllerObj(region)
	if err != nil {
		return "", err
	}
	return ctrl.InfluxDB, nil
}

// Query is a template with a specific set of if/else
func AppInstMetricsQuery(obj *ormapi.RegionAppInstMetrics, measurement string) string {
	arg := influxQueryArgs{
		Selector:     obj.Selector,
		Measurement:  measurement,
		AppInstName:  obj.AppInst.AppKey.Name,
		CloudletName: obj.AppInst.ClusterInstKey.CloudletKey.Name,
		ClusterName:  obj.AppInst.ClusterInstKey.ClusterKey.Name,
		OperatorName: obj.AppInst.ClusterInstKey.CloudletKey.OperatorKey.Name,
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
	if err := influxDBTemplate.Execute(&buf, &arg); err != nil {
		return ""
	}
	return buf.String()
}

// Query is a template with a specific set of if/else
func ClusterMetricsQuery(obj *ormapi.RegionClusterInstMetrics, measurement string) string {
	arg := influxQueryArgs{
		Selector:     obj.Selector,
		Measurement:  measurement,
		CloudletName: obj.ClusterInst.CloudletKey.Name,
		ClusterName:  obj.ClusterInst.ClusterKey.Name,
		OperatorName: obj.ClusterInst.CloudletKey.OperatorKey.Name,
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
	if err := influxDBTemplate.Execute(&buf, &arg); err != nil {
		return ""
	}
	return buf.String()
}

// TODO: This function should be a streaming fucntion, but currently client library for influxDB
// doesn't implement it in a way could really be using it
func metricsStream(rc *InfluxDBContext, dbQuery string, cb func(Data interface{})) error {
	if rc.conn == nil {
		conn, err := connectInfluxDB(rc.region)
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
		log.DebugLog(log.DebugLevelMetrics, "InfluxDB query failed",
			"query", query, "resp", resp, "err", err)
		return err
	}
	if resp.Error() != nil {
		return resp.Error()
	}
	cb(resp.Results)
	return nil
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

	if strings.HasSuffix(c.Path(), "metrics/app") {
		in := ormapi.RegionAppInstMetrics{}
		if err := c.Bind(&in); err != nil {
			return c.JSON(http.StatusBadRequest, Msg("Invalid GET data"))
		}
		// Cluster name has to be specified
		if in.AppInst.ClusterInstKey.ClusterKey.Name == "" {
			return c.JSON(http.StatusBadRequest, Msg("Cluster details must be present"))
		}
		rc.region = in.Region
		org = in.AppInst.AppKey.DeveloperKey.Name
		cmd = AppInstMetricsQuery(&in, cloudcommon.DeveloperAppMetrics)
	} else if strings.HasSuffix(c.Path(), "metrics/cluster") {
		in := ormapi.RegionClusterInstMetrics{}
		if err := c.Bind(&in); err != nil {
			return c.JSON(http.StatusBadRequest, Msg("Invalid GET data"))
		}
		// Cluster name has to be specified
		if in.ClusterInst.ClusterKey.Name == "" {
			return c.JSON(http.StatusBadRequest, Msg("Cluster details must be present"))
		}
		rc.region = in.Region
		org = in.ClusterInst.Developer
		cmd = ClusterMetricsQuery(&in, cloudcommon.DeveloperClusterMetric)
	} else {
		return echo.ErrNotFound
	}

	// Check the developer against who is logged in
	if !enforcer.Enforce(rc.claims.Username, org, ResourceAppAnalytics, ActionView) {
		return echo.ErrForbidden
	}

	wroteHeader := false
	err = metricsStream(rc, cmd, func(res interface{}) {
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
