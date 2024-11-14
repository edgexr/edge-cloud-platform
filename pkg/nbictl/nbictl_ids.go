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
	"fmt"
	"net/http"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/api/nbi"
)

type AppsByKey map[edgeproto.AppKey]*nbi.AppManifest
type ZonesByKey map[edgeproto.ZoneKey]*nbi.EdgeCloudZone
type AppInstsByKey map[edgeproto.AppInstKey]*nbi.AppInstanceInfo
type ClustersByKey map[edgeproto.ClusterKey]*nbi.ClusterInfo

type AppsByID map[string]*nbi.AppManifest
type ZonesByID map[string]*nbi.EdgeCloudZone
type ClustersByID map[string]*nbi.ClusterInfo

func getAppsByKey(ctx context.Context, client *nbi.ClientWithResponses) (AppsByKey, *APIErr) {
	desc := "getAppsByKey"
	resp, err := client.GetAppsWithResponse(ctx, &nbi.GetAppsParams{})
	apiErr := checkForAPIErr(desc, resp, err, http.StatusOK)
	if apiErr != nil {
		return nil, apiErr
	}
	appsByKey := AppsByKey{}
	apps := *resp.JSON200
	for ii, app := range apps {
		key := edgeproto.AppKey{
			Name:         app.Name,
			Organization: app.AppProvider,
			Version:      app.Version,
		}
		appsByKey[key] = &apps[ii]
	}
	return appsByKey, nil
}

func getZonesByKey(ctx context.Context, client *nbi.ClientWithResponses) (ZonesByKey, *APIErr) {
	desc := "getZonesByKey"
	resp, err := client.GetEdgeCloudZonesWithResponse(ctx, &nbi.GetEdgeCloudZonesParams{})
	apiErr := checkForAPIErr(desc, resp, err, http.StatusOK)
	if apiErr != nil {
		return nil, apiErr
	}
	zonesByKey := ZonesByKey{}
	zones := *resp.JSON200
	for ii, zone := range zones {
		key := edgeproto.ZoneKey{
			Name:         zone.EdgeCloudZoneName,
			Organization: zone.EdgeCloudProvider,
		}
		zonesByKey[key] = &zones[ii]
	}
	return zonesByKey, nil
}

func getAppInstsByKey(ctx context.Context, client *nbi.ClientWithResponses) (AppInstsByKey, *APIErr) {
	instsByKey := AppInstsByKey{}

	desc := "getAppInstsByKey"
	params := nbi.GetAppInstanceParams{}
	resp, err := client.GetAppInstanceWithResponse(ctx, &params)
	apiErr := checkForAPIErr(desc, resp, err, http.StatusOK)
	if apiErr != nil {
		return nil, apiErr
	}
	insts := *resp.JSON200
	for ii, inst := range insts {
		key := edgeproto.AppInstKey{
			Name:         inst.Name,
			Organization: inst.AppProvider,
		}
		instsByKey[key] = &insts[ii]
	}
	return instsByKey, nil
}

func getClustersByKey(ctx context.Context, client *nbi.ClientWithResponses) (ClustersByKey, *APIErr) {
	desc := "getClustersByKey"
	params := nbi.GetClustersParams{}
	resp, err := client.GetClustersWithResponse(ctx, &params)
	apiErr := checkForAPIErr(desc, resp, err, http.StatusOK)
	if apiErr != nil {
		return nil, apiErr
	}
	clustersByKey := ClustersByKey{}
	clusters := *resp.JSON200
	for ii, inst := range clusters {
		key := edgeproto.ClusterKey{
			Name:         inst.Name,
			Organization: inst.Provider,
		}
		clustersByKey[key] = &clusters[ii]
	}
	return clustersByKey, nil
}

func (s AppsByKey) getIDFromName(appName, appProvider, appVersion string) (string, error) {
	key := edgeproto.AppKey{
		Name:         appName,
		Organization: appProvider,
		Version:      appVersion,
	}
	app, ok := s[key]
	if !ok {
		return "", fmt.Errorf("no app found for %s", key.GetKeyString())
	}
	if app.AppId == nil || *app.AppId == "" {
		return "", fmt.Errorf("app missing ID, %s", key.GetKeyString())
	}
	return *app.AppId, nil
}

func (s ZonesByKey) getIDFromName(zoneName, provider string) (string, error) {
	key := edgeproto.ZoneKey{
		Name:         zoneName,
		Organization: provider,
	}
	zone, ok := s[key]
	if !ok {
		return "", fmt.Errorf("no zone found for %v", key.GetKeyString())
	}
	if zone.EdgeCloudZoneId == "" {
		return "", fmt.Errorf("zone missing ID, %v", key.GetKeyString())
	}
	return zone.EdgeCloudZoneId, nil
}

func (s AppInstsByKey) getIDFromName(name, provider string) (string, error) {
	key := edgeproto.AppInstKey{
		Name:         name,
		Organization: provider,
	}
	ai, ok := s[key]
	if !ok {
		return "", fmt.Errorf("no appInst found for %v", key.GetKeyString())
	}
	if ai.AppInstanceId == "" {
		return "", fmt.Errorf("appInst missing ID, %v", key.GetKeyString())
	}
	return ai.AppInstanceId, nil
}

func (s ClustersByKey) getIDFromName(name, provider string) (string, error) {
	key := edgeproto.ClusterKey{
		Name:         name,
		Organization: provider,
	}
	cluster, ok := s[key]
	if !ok {
		return "", fmt.Errorf("no cluster found for %v", key.GetKeyString())
	}
	if cluster.ClusterRef == "" {
		return "", fmt.Errorf("cluster missing clusterRef, %v", key.GetKeyString())
	}
	return cluster.ClusterRef, nil
}

func toAppsByID(apps []nbi.AppManifest) AppsByID {
	appsByID := AppsByID{}
	for ii, app := range apps {
		appsByID[*app.AppId] = &apps[ii]
	}
	return appsByID
}

func toZonesByID(zones []nbi.EdgeCloudZone) ZonesByID {
	zonesByID := ZonesByID{}
	for ii, zone := range zones {
		zonesByID[zone.EdgeCloudZoneId] = &zones[ii]
	}
	return zonesByID
}

func toClustersByID(clusters []nbi.ClusterInfo) ClustersByID {
	clustersByID := ClustersByID{}
	for ii, clust := range clusters {
		clustersByID[clust.ClusterRef] = &clusters[ii]
	}
	return clustersByID
}
