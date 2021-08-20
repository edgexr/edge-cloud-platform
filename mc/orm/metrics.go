package orm

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"text/template"
	"time"

	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/util"
)

var appInstGroupQueryTemplate *template.Template

// select mean(cpu) from \"appinst-cpu\" where (apporg='DevOrg') and time >=now() -20m group by time(2m), app fill(previous)"
var (
	AppInstGroupQueryT = `SELECT {{.Selector}} FROM {{.Measurement}}` +
		` WHERE ({{.QueryFilter}}{{if .CloudletList}} AND ({{.CloudletList}}){{end}})` +
		`{{if .StartTime}} AND time >= '{{.StartTime}}'{{end}}` +
		`{{if .EndTime}} AND time <= '{{.EndTime}}'{{end}}` +
		` group by {{if .TimeDefinition}}time({{.TimeDefinition}}),{{end}}app,apporg,cluster,clusterorg,ver,cloudlet,cloudletorg` +
		` fill(previous)` +
		` order by time desc {{if ne .Limit 0}}limit {{.Limit}}{{end}}`
)

func init() {
	appInstGroupQueryTemplate = template.Must(template.New("influxquery").Parse(AppInstGroupQueryT))
}

// handle app metrics
func GetAppMetrics(c echo.Context, in *ormapi.RegionAppInstMetrics) error {
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

	// At least one AppInst org has to be specified
	if len(in.AppInsts) == 0 {
		return fmt.Errorf("At least one app org has to be specified")
	}
	rc.region = in.Region
	if in.Selector == "*" {
		return fmt.Errorf("MetricsV2 api does not allow for a wildcard selector")
	}
	if err = validateSelectorString(in.Selector, APPINST); err != nil {
		return err
	}
	orgsToCheck := []string{}
	cloudletsToCheck := []edgeproto.CloudletKey{}
	for _, app := range in.AppInsts {
		org = app.AppKey.Organization
		// Developer name has to be specified
		if org == "" {
			return fmt.Errorf("App org must be present")
		}
		// validate input
		if err = util.ValidateNames(app.GetTags()); err != nil {
			return err
		}

		orgsToCheck = append(orgsToCheck, org)
		cloudletsToCheck = append(cloudletsToCheck, app.ClusterInstKey.CloudletKey)
	}
	cloudletList, err := checkPermissionsAndGetCloudletList(ctx, claims.Username, in.Region, orgsToCheck,
		ResourceAppAnalytics, cloudletsToCheck)
	if err != nil {
		return err
	}
	settings, err := getSettings(ctx, rc)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Unable to get metrics settings for region %v - error is %s", rc.region, err.Error())
	}

	cmd = GetAppInstsGroupQuery(ctx, in, cloudletList, settings)

	err = influxStream(ctx, rc, []string{cloudcommon.DeveloperMetricsDbName}, cmd, func(res interface{}) error {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		return WriteStream(c, &payload)
	})
	if err != nil {
		return err
	}
	return nil
}

func GetAppInstsGroupQuery(ctx context.Context, apps *ormapi.RegionAppInstMetrics, cloudletList []string, settings *edgeproto.Settings) string {
	// get time definition
	minTimeDef := DefaultAppInstTimeWindow
	if settings != nil {
		minTimeDef = time.Duration(settings.DmeApiMetricsCollectionInterval)
	}
	timeDef := getTimeDefinition(&apps.MetricsCommon, minTimeDef)
	selectorFunction := getFuncForSelector(apps.Selector, timeDef)
	args := influxQueryArgs{
		Selector:    getSelectorForMeasurement(apps.Selector, selectorFunction),
		Measurement: getMeasurementString(apps.Selector, APPINST),
		QueryFilter: getAppInstQueryFilter(apps, cloudletList),
	}
	fillMetricsCommonQueryArgs(&args.metricsCommonQueryArgs, appInstGroupQueryTemplate, &apps.MetricsCommon, timeDef, minTimeDef)
	return getInfluxMetricsQueryCmd(&args, appInstGroupQueryTemplate)
}

// Combine appInst definitions into a filter string in influxDB
// Example: app1/v1.0/appOrg1/cluster1/cloudlet1,app2/v1.1/appOrg2/cluster2/cloudlet1
// string: ("apporg"='appOrg1' AND "app"='app1' AND "ver"='v10' AND "cluster"='cluster1' AND "cloudlet"='cloudlet1') OR
//           ("apporg"='appOrg2' AND "app"='app2' AND "ver"='v11' AND "cluster"='cluster2' AND "cloudlet"='cloudlet1')
func getAppInstQueryFilter(apps *ormapi.RegionAppInstMetrics, cloudletList []string) string {
	filterStr := ``
	for ii, app := range apps.AppInsts {
		filterStr += `("apporg"='` + app.AppKey.Organization + `'`
		if app.AppKey.Name != "" {
			filterStr += ` AND "app"='` + util.DNSSanitize(app.AppKey.Name) + `'`
		}
		if app.AppKey.Version != "" {
			filterStr += ` AND "ver"='` + util.DNSSanitize(app.AppKey.Version) + `'`
		}
		if app.ClusterInstKey.Organization != "" {
			filterStr += ` AND "clusterorg"='` + app.ClusterInstKey.Organization + `'`
		}
		if app.ClusterInstKey.ClusterKey.Name != "" {
			filterStr += ` AND "cluster"='` + app.ClusterInstKey.ClusterKey.Name + `'`
		}
		if app.ClusterInstKey.CloudletKey.Name != "" {
			filterStr += ` AND "cloudlet"='` + app.ClusterInstKey.CloudletKey.Name + `'`
		}
		if app.ClusterInstKey.CloudletKey.Organization != "" {
			filterStr += ` AND "cloudletorg"='` + app.ClusterInstKey.CloudletKey.Organization + `'`
		}

		filterStr += `)`
		// last element
		if len(apps.AppInsts) != ii+1 {
			filterStr += ` OR `
		}
	}

	// add extra filter a list of allowed cloudlets passed in the cloudlets List
	// this is mostly for operators monitorig their cloudletPools
	if len(cloudletList) > 0 {
		filterStr += ` AND (` + generateCloudletList(cloudletList) + `)`
	}
	return filterStr
}

func getFuncForSelector(selector, timeDefinition string) string {
	// If we don't group by time, we cannot accumulate using a function
	if timeDefinition == "" {
		return ""
	}
	switch selector {
	case "cpu":
		return "mean"
	case "disk":
		fallthrough
	case "mem":
		return "max"
	case "network":
		fallthrough
	case "connections":
		fallthrough
	case "udp":
		return "last"
	default:
		return ""
	}
}

func getSelectorForMeasurement(selector, function string) string {
	var fields []string

	switch selector {
	case "cpu":
		fields = CpuFields
	case "disk":
		fields = DiskFields
	case "mem":
		fields = MemFields
	case "network":
		fields = NetworkFields
	case "connections":
		fields = ConnectionsFields
	case "udp":
		fields = appUdpFields
	default:
		// if it's one of the unsupported selectors just return it back
		return selector
	}
	if function == "" {
		return strings.Join(fields, ",")
	}

	// cycle through fields and create the following: "cpu, mean" -> "mean(cpu) as cpu"
	// ah...wouldn't it be nice to have a map functionality here....
	var newSelectors []string
	for _, field := range fields {
		newSelectors = append(newSelectors, function+"("+field+") as "+field)
	}
	return strings.Join(newSelectors, ",")
}

func getInfluxMetricsQueryCmd(q *influxQueryArgs, tmpl *template.Template) string {
	buf := bytes.Buffer{}
	if q.Measurement != "" {
		q.Measurement = addQuotesToMeasurementNames(q.Measurement)
	}
	if err := tmpl.Execute(&buf, q); err != nil {
		log.DebugLog(log.DebugLevelApi, "Failed to run template", "tmpl", tmpl, "args", q, "error", err)
		return ""
	}
	return buf.String()
}
