// Copyright 2024 EdgeXR, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nbictl

import (
	"context"

	"github.com/edgexr/edge-cloud-platform/api/nbi"
)

func GetAll(ctx context.Context, client *nbi.ClientWithResponses) (*GetData, []APIErr) {
	data := &GetData{}
	apiErrors := []APIErr{}

	// get apps
	apps, apierr := GetApps(ctx, client)
	if apierr != nil {
		apiErrors = append(apiErrors, *apierr)
	} else {
		data.Apps = apps
	}

	// get zones
	zones, apierr := GetZones(ctx, client)
	if apierr != nil {
		apiErrors = append(apiErrors, *apierr)
	} else {
		data.Zones = zones
	}

	zonesByID := toZonesByID(zones)

	// get clusters
	clusters, nbiClusters, apierr := GetClusters(ctx, client, zonesByID)
	if apierr != nil {
		apiErrors = append(apiErrors, *apierr)
	} else {
		data.Clusters = clusters
	}

	appsByID := toAppsByID(apps)
	clustersByID := toClustersByID(nbiClusters)

	// get app instances
	appinsts, apierr := GetAppInsts(ctx, client, appsByID, zonesByID, clustersByID)
	if apierr != nil {
		apiErrors = append(apiErrors, *apierr)
	} else {
		data.AppInsts = appinsts
	}

	return data, apiErrors
}

func GetApps(ctx context.Context, client *nbi.ClientWithResponses) ([]nbi.AppManifest, *APIErr) {
	desc := "getapps"
	resp, err := client.GetAppsWithResponse(ctx, &nbi.GetAppsParams{})
	if err != nil {
		return nil, wrapAPIErr(desc, 0, err)
	}
	if resp.JSON200 != nil {
		return *resp.JSON200, nil
	}
	return nil, readAPIErr(desc, resp.StatusCode(), resp.Body)
}

func GetZones(ctx context.Context, client *nbi.ClientWithResponses) ([]nbi.EdgeCloudZone, *APIErr) {
	desc := "getzones"
	resp, err := client.GetEdgeCloudZonesWithResponse(ctx, &nbi.GetEdgeCloudZonesParams{})
	if err != nil {
		return nil, wrapAPIErr(desc, 0, err)
	}
	if resp.JSON200 != nil {
		return *resp.JSON200, nil
	}
	return nil, readAPIErr(desc, resp.StatusCode(), resp.Body)
}

func GetClusters(ctx context.Context, client *nbi.ClientWithResponses, zonesByID ZonesByID) ([]GetClusterInfo, []nbi.ClusterInfo, *APIErr) {
	desc := "getclusters"
	resp, err := client.GetClustersWithResponse(ctx, &nbi.GetClustersParams{})
	if err != nil {
		return nil, nil, wrapAPIErr(desc, 0, err)
	}
	clusters := []GetClusterInfo{}
	if resp.JSON200 != nil {
		for _, clust := range *resp.JSON200 {
			ci := GetClusterInfo{}
			ci.ClusterInfo = clust
			if zone, ok := zonesByID[clust.EdgeCloudZoneId]; ok {
				ci.EdgeCloudProvider = zone.EdgeCloudProvider
				ci.EdgeCloudZoneName = zone.EdgeCloudZoneName
			}
			clusters = append(clusters, ci)
		}
		return clusters, *resp.JSON200, nil
	}
	return nil, nil, readAPIErr(desc, resp.StatusCode(), resp.Body)
}

func GetAppInsts(ctx context.Context, client *nbi.ClientWithResponses, appsByID AppsByID, zonesByID ZonesByID, clustersByID ClustersByID) ([]GetAppInstanceInfo, *APIErr) {
	desc := "getappinstances"
	resp, err := client.GetAppInstanceWithResponse(ctx, &nbi.GetAppInstanceParams{})
	if err != nil {
		return nil, wrapAPIErr(desc, 0, err)
	}
	appInsts := []GetAppInstanceInfo{}
	if resp.JSON200 != nil {
		for _, inst := range *resp.JSON200 {
			ai := GetAppInstanceInfo{}
			ai.AppInstanceInfo = inst
			if zone, ok := zonesByID[inst.EdgeCloudZoneId]; ok {
				ai.EdgeCloudProvider = zone.EdgeCloudProvider
				ai.EdgeCloudZoneName = zone.EdgeCloudZoneName
			}
			if app, ok := appsByID[inst.AppId]; ok {
				ai.AppName = app.Name
			}
			if inst.KubernetesClusterRef != nil {
				if cluster, ok := clustersByID[*inst.KubernetesClusterRef]; ok {
					ai.ClusterName = cluster.Name
					ai.ClusterProvider = cluster.Provider
				}
			}
			appInsts = append(appInsts, ai)
		}
		return appInsts, nil
	}
	return nil, readAPIErr(desc, resp.StatusCode(), resp.Body)
}
