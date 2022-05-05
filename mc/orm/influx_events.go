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
	"fmt"
	"strings"

	"github.com/labstack/echo"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud-infra/mc/ormutil"
	"github.com/edgexr/edge-cloud/cloud-resource-manager/k8smgmt"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/util"
)

var clusterEventFields = []string{
	"reservedBy",
	"flavor",
	"vcpu",
	"ram",
	"disk",
	"nodecount",
	"other",
}

var eventLogSelectors = []string{
	"event",
	"status",
}

const (
	EVENT_APPINST     = "appinst"
	EVENT_CLUSTERINST = "clusterinst"
	EVENT_CLOUDLET    = "cloudlet"
)

func getEventFields(eventType string) string {
	var selectors []string
	switch eventType {
	case EVENT_APPINST:
		selectors = AppFields
	case EVENT_CLUSTERINST:
		selectors = append(ClusterFields, clusterEventFields...)
	case EVENT_CLOUDLET:
		selectors = CloudletFields
	default:
		return "*"
	}
	return strings.Join(append(selectors, eventLogSelectors...), ",")
}

// Query is a template with a specific set of if/else
func AppInstEventsQuery(obj *ormapi.RegionAppInstEvents, cloudletList []string) string {
	arg := influxQueryArgs{
		Selector:     getEventFields(EVENT_APPINST),
		Measurement:  EVENT_APPINST,
		AppInstName:  k8smgmt.NormalizeName(obj.AppInst.AppKey.Name),
		ClusterName:  obj.AppInst.ClusterInstKey.ClusterKey.Name,
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
func ClusterEventsQuery(obj *ormapi.RegionClusterInstEvents, cloudletList []string) string {
	arg := influxQueryArgs{
		Selector:     getEventFields(EVENT_CLUSTERINST),
		Measurement:  EVENT_CLUSTERINST,
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
func CloudletEventsQuery(obj *ormapi.RegionCloudletEvents) string {
	arg := influxQueryArgs{
		Selector:     getEventFields(EVENT_CLOUDLET),
		Measurement:  EVENT_CLOUDLET,
		OrgField:     "cloudletorg",
		ApiCallerOrg: obj.Cloudlet.Organization,
		CloudletName: obj.Cloudlet.Name,
		CloudletOrg:  obj.Cloudlet.Organization,
	}
	fillMetricsCommonQueryArgs(&arg.metricsCommonQueryArgs, &obj.MetricsCommon, "", 0)
	return getInfluxMetricsQueryCmd(&arg, operatorInfluxDBTemplate)
}

// Common method to handle both app and cluster metrics
func GetEventsCommon(c echo.Context) error {
	var cmd, org string

	rc := &InfluxDBContext{}
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc.claims = claims
	ctx := ormutil.GetContext(c)

	if strings.HasSuffix(c.Path(), "events/app") {
		in := ormapi.RegionAppInstEvents{}
		_, err := ReadConn(c, &in)
		if err != nil {
			return err
		}
		cloudletList, err := checkPermissionsAndGetCloudletList(ctx, claims.Username, in.Region, []string{in.AppInst.AppKey.Organization},
			ResourceAppAnalytics, []edgeproto.CloudletKey{in.AppInst.ClusterInstKey.CloudletKey})
		if err != nil {
			return err
		}
		// validate all the passed in arguments
		if err = util.ValidateNames(in.AppInst.GetTags()); err != nil {
			return err
		}

		rc.region = in.Region

		cmd = AppInstEventsQuery(&in, cloudletList)
	} else if strings.HasSuffix(c.Path(), "events/cluster") {
		in := ormapi.RegionClusterInstEvents{}
		_, err := ReadConn(c, &in)
		if err != nil {
			return err
		}
		// validate all the passed in arguments
		if err = util.ValidateNames(in.ClusterInst.GetTags()); err != nil {
			return err
		}

		cloudletList, err := checkPermissionsAndGetCloudletList(ctx, claims.Username, in.Region, []string{in.ClusterInst.Organization},
			ResourceClusterAnalytics, []edgeproto.CloudletKey{in.ClusterInst.CloudletKey})
		if err != nil {
			return err
		}
		rc.region = in.Region

		cmd = ClusterEventsQuery(&in, cloudletList)
	} else if strings.HasSuffix(c.Path(), "events/cloudlet") {
		in := ormapi.RegionCloudletEvents{}
		_, err := ReadConn(c, &in)
		if err != nil {
			return err
		}
		// Operator name has to be specified
		if in.Cloudlet.Organization == "" {
			return fmt.Errorf("Cloudlet details must be present")
		}
		// validate all the passed in arguments
		if err = util.ValidateNames(in.Cloudlet.GetTags()); err != nil {
			return err
		}

		rc.region = in.Region
		org = in.Cloudlet.Organization

		cmd = CloudletEventsQuery(&in)

		// Check the operator against who is logged in
		if err := authorized(ctx, rc.claims.Username, org, ResourceCloudletAnalytics, ActionView); err != nil {
			return err
		}
	} else {
		return echo.ErrNotFound
	}

	err = influxStream(ctx, rc, []string{cloudcommon.EventsDbName}, cmd, func(res interface{}) error {
		payload := ormapi.StreamPayload{}
		payload.Data = res
		return WriteStream(c, &payload)
	})
	if err != nil {
		return err
	}
	return nil
}
