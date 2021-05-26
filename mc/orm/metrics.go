package orm

import (
	"context"
	"fmt"
	"strings"
	"text/template"
	"time"

	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/cloudcommon"
	edgeproto "github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/util"
)

const (
	DefaultTimeWindow = 15 * time.Second
	// Max 100 data points on the graph
	MaxTimeDefinition = 100
)

var appInstGroupQueryTemplate *template.Template

// select mean(cpu) from \"appinst-cpu\" where (apporg='DevOrg') and time >=now() -20m group by time(2m), app fill(previous)"
var AppInstGroupQueryT = `SELECT {{.Selector}} FROM "{{.Measurement}}"` +
	` WHERE ({{.QueryFilter}}{{if .CloudletList}} AND ({{.CloudletList}}){{end}})` +
	`{{if .StartTime}} AND time >= '{{.StartTime}}'{{end}}` +
	`{{if .EndTime}} AND time <= '{{.EndTime}}'{{end}}` +
	` group by {{if .TimeDefinition}}time({{.TimeDefinition}}),{{end}}app,apporg,cluster,clusterorg,ver,cloudlet,cloudletorg` +
	` fill(previous)` +
	` order by time desc {{if ne .Last 0}}limit {{.Last}}{{end}}`

func init() {
	appInstGroupQueryTemplate = template.Must(template.New("influxquery").Parse(AppInstGroupQueryT))
}

// Common method to handle both app and cluster metrics
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
		orgsToCheck = append(orgsToCheck, org)
		cloudletsToCheck = append(cloudletsToCheck, app.ClusterInstKey.CloudletKey)
	}
	cloudletList, err := checkPermissionsAndGetCloudletList(ctx, claims.Username, in.Region, orgsToCheck,
		ResourceAppAnalytics, cloudletsToCheck)
	if err != nil {
		return err
	}
	cmd = GetAppInstsGroupQuery(ctx, in, cloudletList)

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

func getTimeDefinition(apps *ormapi.RegionAppInstMetrics) string {
	// In case we are requesting last n number of entries and don't provide time window
	// we should skip the function and time-based grouping
	if apps.StartTime.IsZero() && apps.EndTime.IsZero() && apps.Last != 0 {
		return ""
	}
	// set the max number of data points per grouping
	if apps.Last == 0 {
		apps.Last = MaxTimeDefinition
	}
	if apps.EndTime.IsZero() {
		apps.EndTime = time.Now().UTC()
	}
	// Default time to last 12hrs
	if apps.StartTime.IsZero() {
		apps.StartTime = apps.EndTime.Add(-12 * time.Hour).UTC()
	}

	// If start time is past end time, cannot group by time
	timeDiff := apps.EndTime.Sub(apps.StartTime)
	if timeDiff < 0 {
		return ""
	}
	// Make sure we don't have any fractional seconds in here
	timeWindow := time.Duration(timeDiff / time.Duration(apps.Last)).Truncate(time.Second)
	if timeWindow < DefaultTimeWindow {
		return DefaultTimeWindow.String()
	}
	return timeWindow.String()
}

func GetAppInstsGroupQuery(ctx context.Context, apps *ormapi.RegionAppInstMetrics, cloudletList []string) string {
	timeDef := getTimeDefinition(apps)
	selectorFunction := getFuncForSelector(apps.Selector, timeDef)
	args := influxQueryArgs{
		Selector:       getSelectorForMeasurement(apps.Selector, selectorFunction),
		Measurement:    getMeasurementString(apps.Selector, APPINST),
		QueryFilter:    getAppInstQueryFilter(apps, cloudletList),
		TimeDefinition: timeDef,
		Last:           apps.Last,
	}
	return fillTimeAndGetCmd(&args, appInstGroupQueryTemplate, &apps.StartTime, &apps.EndTime)
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
