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
	"text/template"
	"time"

	"github.com/labstack/echo"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud-infra/mc/ormutil"
	"github.com/edgexr/edge-cloud/cloudcommon"
	edgeproto "github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/util"
)

// select mean(cpu) from \"appinst-cpu\" where (apporg='DevOrg') and time >=now() -20m group by time(2m), app fill(previous)"
var (
	metricsGroupQueryTemplate *template.Template
	MetricsGroupQueryT        = `SELECT {{.Selector}} FROM {{.Measurement}}` +
		` WHERE ({{.QueryFilter}}{{if .CloudletList}} AND ({{.CloudletList}}){{end}})` +
		`{{if .StartTime}} AND time >= '{{.StartTime}}'{{end}}` +
		`{{if .EndTime}} AND time <= '{{.EndTime}}'{{end}}` +
		` group by {{if .TimeDefinition}}time({{.TimeDefinition}}),{{end}}{{.GroupFields}}` +
		` fill(previous)` +
		` order by time desc {{if ne .Limit 0}}limit {{.Limit}}{{end}}`

	AppInstGroupFields     = "app,apporg,cluster,clusterorg,ver,cloudlet,cloudletorg"
	ClusterInstGroupFields = "cluster,clusterorg,cloudlet,cloudletorg"
	CloudletGroupFields    = "cloudlet,cloudletorg"
)

type MetricsObject interface {
	InitObject(ctx context.Context, rc *InfluxDBContext) error
	GetType() string
	GetRegion() string
	// Get Selectors either gives a single selector, a list if several are passed, or all if "*" is passed in
	GetSelectors() []string
	GetMeasurementString(selector string) string
	GetObjCount() int
	GetMetricsCommon() *ormapi.MetricsCommon
	ValidateSelector() error
	ValidateObjects() error
	GetDbNames() []string
	CheckPermissionsAndGetCloudletList(ctx context.Context, username string) ([]string, error)
	GetQueryFilter(cloudletList []string) string
	GetGroupFields() string
	GetGroupQuery(cloudletList []string) string
}

type appInstMetrics struct {
	*ormapi.RegionAppInstMetrics
	settings *edgeproto.Settings
}

func (m *appInstMetrics) InitObject(ctx context.Context, rc *InfluxDBContext) error {
	settings, err := getSettings(ctx, rc.region)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Unable to get metrics settings for region %v - error is %s", rc.region, err.Error())
		return err
	}
	m.settings = settings
	return nil
}

func (m *appInstMetrics) GetType() string {
	return APPINST
}

func (m *appInstMetrics) GetSelectors() []string {
	if m.Selector == "*" {
		return ormapi.AppSelectors
	}
	return strings.Split(m.Selector, ",")
}

func (m *appInstMetrics) GetMeasurementString(selector string) string {
	return getMeasurementString(selector, m.GetType())
}

func (m *appInstMetrics) GetRegion() string {
	return m.Region
}

func (m *appInstMetrics) GetGroupFields() string {
	return AppInstGroupFields
}

func (m *appInstMetrics) GetObjCount() int {
	return len(m.AppInsts)
}

func (m *appInstMetrics) GetDbNames() []string {
	return []string{cloudcommon.DeveloperMetricsDbName}
}

func (m *appInstMetrics) GetMetricsCommon() *ormapi.MetricsCommon {
	return &m.MetricsCommon
}

func (m *appInstMetrics) ValidateSelector() error {
	return validateSelectorString(m.Selector, m.GetType())
}

func (m *appInstMetrics) ValidateObjects() error {
	for _, app := range m.AppInsts {
		org := app.AppKey.Organization
		// Developer name has to be specified
		if org == "" {
			return fmt.Errorf("App org must be present")
		}
		// validate input
		if err := util.ValidateNames(app.GetTags()); err != nil {
			return err
		}
	}
	return nil
}

func (m *appInstMetrics) CheckPermissionsAndGetCloudletList(ctx context.Context, username string) ([]string, error) {
	orgsToCheck := []string{}
	cloudletsToCheck := []edgeproto.CloudletKey{}
	for _, app := range m.AppInsts {
		org := app.AppKey.Organization
		orgsToCheck = append(orgsToCheck, org)
		cloudletsToCheck = append(cloudletsToCheck, app.ClusterInstKey.CloudletKey)
	}
	cloudletList, err := checkPermissionsAndGetCloudletList(ctx, username, m.GetRegion(), orgsToCheck,
		ResourceAppAnalytics, cloudletsToCheck)
	if err != nil {
		return nil, err
	}
	return cloudletList, nil
}

// Combine appInst definitions into a filter string in influxDB
// Example: app1/v1.0/appOrg1/cluster1/cloudlet1,app2/v1.1/appOrg2/cluster2/cloudlet1
// string:
// 		("apporg"='appOrg1' AND "app"='app1' AND "ver"='v10' AND "cluster"='cluster1' AND "cloudlet"='cloudlet1') OR
//		("apporg"='appOrg2' AND "app"='app2' AND "ver"='v11' AND "cluster"='cluster2' AND "cloudlet"='cloudlet1')
func (m *appInstMetrics) GetQueryFilter(cloudletList []string) string {
	filterStr := ``
	for ii, app := range m.AppInsts {
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
		if len(m.AppInsts) != ii+1 {
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

func (m *appInstMetrics) GetGroupQuery(cloudletList []string) string {
	return GetDeveloperGroupQuery(m, cloudletList, m.settings)
}

type clusterInstMetrics struct {
	*ormapi.RegionClusterInstMetrics
	settings *edgeproto.Settings
}

func (m *clusterInstMetrics) InitObject(ctx context.Context, rc *InfluxDBContext) error {
	settings, err := getSettings(ctx, rc.region)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Unable to get metrics settings for region %v - error is %s", rc.region, err.Error())
		return err
	}
	m.settings = settings
	return nil
}

func (m *clusterInstMetrics) GetType() string {
	return CLUSTER
}

func (m *clusterInstMetrics) GetRegion() string {
	return m.Region
}

func (m *clusterInstMetrics) GetGroupFields() string {
	return ClusterInstGroupFields
}

func (m *clusterInstMetrics) GetObjCount() int {
	return len(m.ClusterInsts)
}

func (m *clusterInstMetrics) GetDbNames() []string {
	return []string{cloudcommon.DeveloperMetricsDbName}
}

func (m *clusterInstMetrics) GetMetricsCommon() *ormapi.MetricsCommon {
	return &m.MetricsCommon
}

func (m *clusterInstMetrics) GetSelectors() []string {
	if m.Selector == "*" {
		return ormapi.ClusterSelectors
	}
	return strings.Split(m.Selector, ",")
}

func (m *clusterInstMetrics) GetMeasurementString(selector string) string {
	return getMeasurementString(selector, m.GetType())
}

func (m *clusterInstMetrics) ValidateObjects() error {
	for _, cluster := range m.ClusterInsts {
		org := cluster.Organization
		// Developer name has to be specified
		if org == "" {
			return fmt.Errorf("Cluster org must be present")
		}
		// validate input
		if err := util.ValidateNames(cluster.GetTags()); err != nil {
			return err
		}
	}
	return nil
}

func (m *clusterInstMetrics) ValidateSelector() error {
	return validateSelectorString(m.Selector, m.GetType())
}

func (m *clusterInstMetrics) CheckPermissionsAndGetCloudletList(ctx context.Context, username string) ([]string, error) {
	orgsToCheck := []string{}
	cloudletsToCheck := []edgeproto.CloudletKey{}
	for _, cluster := range m.ClusterInsts {
		org := cluster.Organization
		orgsToCheck = append(orgsToCheck, org)
		cloudletsToCheck = append(cloudletsToCheck, cluster.CloudletKey)
	}
	cloudletList, err := checkPermissionsAndGetCloudletList(ctx, username, m.GetRegion(), orgsToCheck,
		ResourceClusterAnalytics, cloudletsToCheck)
	if err != nil {
		return nil, err
	}
	return cloudletList, nil

}

// Combine clusterInst definitions into a filter string in influxDB
// Example: cluster1/cluster1-org/cloudlet1/cloudlet1-org,cluster2-org/cloudlet1
// string:
// 	("clusterorg"='cluster1-org' AND "cluster"='cluster1' AND "cloudlet"='cloudlet1' AND "cloudlet-org"="cloudlet1-org") OR
//	("clusterorg"='cluster2-org' AND "cloudlet"='cloudlet1')
func (m *clusterInstMetrics) GetQueryFilter(cloudletList []string) string {
	filterStr := ``
	for ii, cluster := range m.ClusterInsts {
		filterStr += `("clusterorg"='` + cluster.Organization + `'`
		if cluster.ClusterKey.Name != "" {
			filterStr += ` AND "cluster"='` + cluster.ClusterKey.Name + `'`
		}
		if cluster.CloudletKey.Name != "" {
			filterStr += ` AND "cloudlet"='` + cluster.CloudletKey.Name + `'`
		}
		if cluster.CloudletKey.Organization != "" {
			filterStr += ` AND "cloudletorg"='` + cluster.CloudletKey.Organization + `'`
		}

		filterStr += `)`
		// last element
		if len(m.ClusterInsts) != ii+1 {
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

func (m *clusterInstMetrics) GetGroupQuery(cloudletList []string) string {
	return GetDeveloperGroupQuery(m, cloudletList, m.settings)
}

type cloudletMetrics struct {
	*ormapi.RegionCloudletMetrics
	settings *edgeproto.Settings
}

func (m *cloudletMetrics) InitObject(ctx context.Context, rc *InfluxDBContext) error {
	settings, err := getSettings(ctx, rc.region)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelMetrics, "Unable to get metrics settings for region %v - error is %s", rc.region, err.Error())
		return err
	}
	m.settings = settings
	return nil
}

func (m *cloudletMetrics) GetType() string {
	return CLOUDLET
}

func (m *cloudletMetrics) GetSelectors() []string {
	if m.Selector == "*" {
		return ormapi.CloudletSelectors
	}
	return strings.Split(m.Selector, ",")
}

func (m *cloudletMetrics) GetMeasurementString(selector string) string {
	return getMeasurementString(selector, m.GetType())
}

func (m *cloudletMetrics) GetRegion() string {
	return m.Region
}

func (m *cloudletMetrics) GetGroupFields() string {
	return CloudletGroupFields
}

func (m *cloudletMetrics) GetObjCount() int {
	return len(m.Cloudlets)
}

func (m *cloudletMetrics) GetDbNames() []string {
	return []string{cloudcommon.DeveloperMetricsDbName}
}

func (m *cloudletMetrics) GetMetricsCommon() *ormapi.MetricsCommon {
	return &m.MetricsCommon
}

func (m *cloudletMetrics) ValidateSelector() error {
	return validateSelectorString(m.Selector, m.GetType())
}

func (m *cloudletMetrics) ValidateObjects() error {
	for _, cloudlet := range m.Cloudlets {
		org := cloudlet.Organization
		// operator name has to be specified
		if org == "" {
			return fmt.Errorf("Cloudlet org must be present")
		}
		// validate input
		if err := util.ValidateNames(cloudlet.GetTags()); err != nil {
			return err
		}
	}
	return nil
}

// For cloudlet metrics cloudlet list is always nil
func (m *cloudletMetrics) CheckPermissionsAndGetCloudletList(ctx context.Context, username string) ([]string, error) {
	for _, cloudlet := range m.Cloudlets {
		// Check the operator against who is logged in
		if err := authorized(ctx, username, cloudlet.Organization, ResourceCloudletAnalytics, ActionView); err != nil {
			return nil, err
		}
	}
	return nil, nil
}

// Combine cloudlet definitions into a filter string in influxDB
// Example: cloudlet1/cloudletOrg1,cloudlet2/cloudletOrg1
// string:
// 		("cloudletorg"='cloudletOrg1' AND "cloudlet"='cloudlet1') OR
//		("cloudletorg"='cloudletOrg1' AND "cloudlet"='cloudlet2')
func (m *cloudletMetrics) GetQueryFilter(cloudletList []string) string {
	filterStr := ``
	for ii, cloudlet := range m.Cloudlets {
		filterStr += `("cloudletorg"='` + cloudlet.Organization + `'`
		if cloudlet.Name != "" {
			filterStr += ` AND "cloudlet"='` + cloudlet.Name + `'`
		}
		filterStr += `)`
		// last element
		if len(m.Cloudlets) != ii+1 {
			filterStr += ` OR `
		}
	}
	return filterStr
}

func (m *cloudletMetrics) GetGroupQuery(cloudletList []string) string {
	return GetDeveloperGroupQuery(m, cloudletList, m.settings)
}

// "inherit" from cloudletMetrics - most of the validation, getters are the same
type cloudletUsageMetrics struct {
	cloudletMetrics
	platformTypes map[string]struct{}
}

func (m *cloudletUsageMetrics) InitObject(ctx context.Context, rc *InfluxDBContext) error {
	err := m.cloudletMetrics.InitObject(ctx, rc)
	if err != nil {
		return err
	}
	// Platform type is required for cloudlet resource usage, but for consistency check for all selectors
	m.platformTypes, err = getCloudletPlatformTypes(ctx, rc.claims.Username, m.Region, m.Cloudlets)
	if err != nil {
		return err
	}
	return m.cloudletMetrics.InitObject(ctx, rc)
}

func (m *cloudletUsageMetrics) ValidateSelector() error {
	return validateSelectorString(m.Selector, m.GetType())
}

func (m *cloudletUsageMetrics) GetType() string {
	return CLOUDLETUSAGE
}

func (m *cloudletUsageMetrics) GetSelectors() []string {
	if m.Selector == "*" {
		return ormapi.CloudletUsageSelectors
	}
	return strings.Split(m.Selector, ",")
}

func (m *cloudletUsageMetrics) GetGroupQuery(cloudletList []string) string {
	return GetDeveloperGroupQuery(m, cloudletList, m.settings)
}

func (m *cloudletUsageMetrics) GetMeasurementString(selector string) string {
	measurements := []string{}
	if selector == "resourceusage" {
		for platformType := range m.platformTypes {
			measurements = append(measurements, fmt.Sprintf("%s-resource-usage", platformType))
		}
	} else if m.Selector == "flavorusage" {
		measurements = append(measurements, "cloudlet-flavor-usage")
	} else {
		measurements = append(measurements, selector)
	}
	return strings.Join(measurements, ",")
}

func (m *cloudletUsageMetrics) GetDbNames() []string {
	return []string{cloudcommon.CloudletResourceUsageDbName}
}

func init() {
	metricsGroupQueryTemplate = template.Must(template.New("influxquery").Parse(MetricsGroupQueryT))
}

func ShowMetricsCommon(c echo.Context, in MetricsObject) error {
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

	// At least one obj org has to be specified
	if in.GetObjCount() == 0 {
		return fmt.Errorf("At least one %s org has to be specified", in.GetType())
	}

	// Validate objects
	if err := in.ValidateObjects(); err != nil {
		return err
	}

	rc.region = in.GetRegion()
	if err = in.ValidateSelector(); err != nil {
		return err
	}
	cloudletList, err := in.CheckPermissionsAndGetCloudletList(ctx, claims.Username)
	if err != nil {
		return err
	}
	if err := in.InitObject(ctx, rc); err != nil {
		return err
	}
	cmd := in.GetGroupQuery(cloudletList)
	err = influxStream(ctx, rc, in.GetDbNames(), cmd, func(res interface{}) error {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		return WriteStream(c, &payload)
	})
	if err != nil {
		return err
	}
	return nil
}

// handle cloudlet usage metrics
func GetCloudletUsageMetrics(c echo.Context, in *ormapi.RegionCloudletMetrics) error {
	return ShowMetricsCommon(c, &cloudletUsageMetrics{cloudletMetrics{RegionCloudletMetrics: in}, nil})
}

// handle cloudlet metrics
func GetCloudletMetrics(c echo.Context, in *ormapi.RegionCloudletMetrics) error {
	return ShowMetricsCommon(c, &cloudletMetrics{RegionCloudletMetrics: in})
}

// handle cluster metrics
func GetClusterMetrics(c echo.Context, in *ormapi.RegionClusterInstMetrics) error {
	return ShowMetricsCommon(c, &clusterInstMetrics{RegionClusterInstMetrics: in})
}

// handle app metrics
func GetAppMetrics(c echo.Context, in *ormapi.RegionAppInstMetrics) error {
	return ShowMetricsCommon(c, &appInstMetrics{RegionAppInstMetrics: in})
}

func getMetricsTemplateArgs(obj MetricsObject, timeDef string, selector string, cloudletList []string) influxQueryArgs {
	selectorFunction := getFuncForSelector(selector, timeDef)
	args := influxQueryArgs{
		Selector:    getSelectorForMeasurement(selector, selectorFunction, obj.GetType()),
		Measurement: obj.GetMeasurementString(selector),
		QueryFilter: obj.GetQueryFilter(cloudletList),
		GroupFields: obj.GetGroupFields(),
	}
	return args
}

func GetDeveloperGroupQuery(obj MetricsObject, cloudletList []string, settings *edgeproto.Settings) string {
	// get time definition
	minTimeDef := DefaultAppInstTimeWindow
	if settings != nil {
		minTimeDef = time.Duration(settings.DmeApiMetricsCollectionInterval)
	}
	timeDef := getTimeDefinition(obj.GetMetricsCommon(), minTimeDef)
	dbQueries := []string{}
	for _, selector := range obj.GetSelectors() {
		args := getMetricsTemplateArgs(obj, timeDef, selector, cloudletList)
		fillMetricsCommonQueryArgs(&args.metricsCommonQueryArgs, obj.GetMetricsCommon(), timeDef, minTimeDef)
		dbQueries = append(dbQueries, getInfluxMetricsQueryCmd(&args, metricsGroupQueryTemplate))
	}
	return strings.Join(dbQueries, ";")
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
	case "tcp":
		fallthrough
	case "udp":
		fallthrough
	case "utilization":
		fallthrough
	case "resourceusage":
		fallthrough
	case "flavorusage":
		fallthrough
	case "ipusage":
		return "last"
	default:
		return ""
	}
}

func getSelectorForMeasurement(selector, function, metricType string) string {
	var fields []string
	// TODO - this should be consolidated with getFieldsSlice()
	switch selector {
	case "cpu":
		fields = CpuFields
	case "disk":
		fields = DiskFields
	case "mem":
		fields = MemFields
	case "network":
		if metricType == CLOUDLET {
			fields = CloudletNetworkFields
		} else {
			fields = NetworkFields
		}
	case "connections":
		fields = ConnectionsFields
	case "udp":
		if metricType == APPINST {
			fields = appUdpFields
		} else {
			fields = UdpFields
		}
	case "tcp":
		fields = TcpFields
	case "utilization":
		fields = UtilizationFields
	case "ipusage":
		fields = IpUsageFields
	case "resourceusage":
		fields = ResourceUsageFields
	case "flavorusage":
		fields = FlavorUsageFields
	default:
		// if it's one of the unsupported selectors just return it back
		return selector
	}
	if function == "" {
		return strings.Join(fields, ",")
	}

	// cycle through fields and create the following: "cpu, mean" -> "mean(cpu) as cpu"
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
