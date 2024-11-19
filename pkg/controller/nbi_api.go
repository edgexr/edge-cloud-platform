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

package controller

import (
	"context"
	"fmt"
	"net/http"
	"slices"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/api/nbi"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"google.golang.org/grpc"
)

// NBIAPI implements nbi.ServerInterface
type NBIAPI struct {
	allApis *AllApis
}

func NewNBIAPI(allApis *AllApis) *NBIAPI {
	return &NBIAPI{
		allApis: allApis,
	}
}

func (s *NBIAPI) GetApps(ctx context.Context, request nbi.GetAppsRequestObject) (nbi.GetAppsResponseObject, error) {
	apps := nbi.GetApps200JSONResponse{}
	err := s.allApis.appApi.cache.Show(&edgeproto.App{}, func(obj *edgeproto.App) error {
		app, err := NBIApp(obj)
		if err != nil {
			return nbi.NewErrorInfo(http.StatusBadRequest, err.Error())
		}
		apps.Body = append(apps.Body, *app)
		return nil
	})
	if err != nil {
		return nil, nbi.NewErrorInfo(http.StatusInternalServerError, err.Error())
	}
	slices.SortStableFunc(apps.Body, NBIAppSort)
	return apps, nil
}

func (s *NBIAPI) SubmitApp(ctx context.Context, request nbi.SubmitAppRequestObject) (nbi.SubmitAppResponseObject, error) {
	ecApp, err := ProtoApp(request.Body)
	if err != nil {
		return nil, nbi.NewErrorInfo(http.StatusBadRequest, err.Error())
	}
	_, err = s.allApis.appApi.CreateApp(ctx, ecApp)
	if err != nil {
		return nil, nbi.NewErrorInfo(http.StatusBadRequest, err.Error())
	}
	resp := nbi.SubmitApp201JSONResponse{}
	resp.Body.AppId = &ecApp.ObjId
	return resp, nil
}

func (s *NBIAPI) DeleteApp(ctx context.Context, request nbi.DeleteAppRequestObject) (nbi.DeleteAppResponseObject, error) {
	// find app from id
	app, err := s.allApis.appApi.getAppByID(ctx, request.AppId)
	if err != nil {
		return nil, nbi.NewErrorInfo(http.StatusBadRequest, err.Error())
	}
	if app == nil {
		return nil, nbi.NewErrorInfo(http.StatusNotFound, "app not found")
	}
	_, err = s.allApis.appApi.DeleteApp(ctx, app)
	if err != nil {
		return nil, nbi.NewErrorInfo(http.StatusBadRequest, err.Error())
	}
	resp := nbi.DeleteApp202Response{}
	return resp, nil
}

func (s *NBIAPI) GetApp(ctx context.Context, request nbi.GetAppRequestObject) (nbi.GetAppResponseObject, error) {
	app, err := s.allApis.appApi.getAppByID(ctx, request.AppId)
	if err != nil {
		return nil, nbi.NewErrorInfo(http.StatusBadRequest, err.Error())
	}
	if app == nil {
		return nil, nbi.NewErrorInfo(http.StatusNotFound, "app not found")
	}
	nbiApp, err := NBIApp(app)
	if err != nil {
		return nil, nbi.NewErrorInfo(http.StatusInternalServerError, err.Error())
	}
	resp := nbi.GetApp200JSONResponse{}
	resp.Body.AppManifest = nbiApp
	return resp, nil
}

func (s *NBIAPI) GetAppInstance(ctx context.Context, request nbi.GetAppInstanceRequestObject) (nbi.GetAppInstanceResponseObject, error) {
	filter := edgeproto.AppInst{}
	if request.Params.AppId != nil {
		app, err := s.allApis.appApi.getAppByID(ctx, *request.Params.AppId)
		if err != nil {
			return nil, nbi.NewErrorInfo(http.StatusBadRequest, fmt.Sprintf("app ID %s not found", *request.Params.AppId))
		}
		filter.AppKey = app.Key
	}
	if request.Params.AppInstanceId != nil {
		filter.ObjId = *request.Params.AppInstanceId
	}
	insts := []nbi.AppInstanceInfo{}
	err := s.allApis.appInstApi.cache.Show(&filter, func(obj *edgeproto.AppInst) error {
		inst, err := s.NBIAppInst(obj)
		if err != nil {
			return err
		}
		insts = append(insts, *inst)
		return nil
	})
	if err != nil {
		return nil, nbi.NewErrorInfo(http.StatusInternalServerError, err.Error())
	}
	slices.SortStableFunc(insts, NBIAppInstSort)
	resp := nbi.GetAppInstance200JSONResponse{}
	resp.Body = insts
	return resp, nil
}

func (s *NBIAPI) CreateAppInstance(ctx context.Context, request nbi.CreateAppInstanceRequestObject) (nbi.CreateAppInstanceResponseObject, error) {
	req := request.Body
	appInst := edgeproto.AppInst{}
	appInst.Key.Name = req.Name
	// look up App
	app, err := s.allApis.appApi.getAppByID(ctx, req.AppId)
	if err != nil {
		return nil, nbi.NewErrorInfo(http.StatusBadRequest, err.Error())
	}
	if app == nil {
		return nil, nbi.NewErrorInfo(http.StatusBadRequest, fmt.Sprintf("app ID %s not found", req.AppId))
	}
	appInst.AppKey = app.Key
	appInst.Key.Organization = appInst.AppKey.Organization

	// look up Zone
	zone, err := s.allApis.zoneApi.getZoneByID(ctx, req.EdgeCloudZoneId)
	if err != nil {
		return nil, nbi.NewErrorInfo(http.StatusBadRequest, err.Error())
	}
	if zone == nil {
		return nil, nbi.NewErrorInfo(http.StatusBadRequest, fmt.Sprintf("zone ID %s not found", req.EdgeCloudZoneId))
	}
	appInst.ZoneKey = zone.Key

	// look up cluster if specified
	if req.KubernetesClusterRef != nil {
		clusterID := *req.KubernetesClusterRef
		ci, err := s.allApis.clusterInstApi.getClusterInstByID(ctx, clusterID)
		if err != nil {
			return nil, nbi.NewErrorInfo(http.StatusBadRequest, err.Error())
		}
		if ci == nil {
			return nil, nbi.NewErrorInfo(http.StatusBadRequest, fmt.Sprintf("clusterID %s not found", clusterID))
		}
		appInst.ClusterKey = ci.Key
	}
	err = s.allApis.appInstApi.CreateAppInst(&appInst, NewStreamoutAppInst(ctx))
	if err != nil {
		return nil, nbi.NewErrorInfo(http.StatusBadRequest, err.Error())
	}
	instOut, err := s.NBIAppInst(&appInst)
	if err != nil {
		return nil, nbi.NewErrorInfo(http.StatusInternalServerError, err.Error())
	}
	resp := nbi.CreateAppInstance202JSONResponse{}
	resp.Body = *instOut
	return resp, nil
}

func (s *NBIAPI) DeleteAppInstance(ctx context.Context, request nbi.DeleteAppInstanceRequestObject) (nbi.DeleteAppInstanceResponseObject, error) {
	appInst, err := s.allApis.appInstApi.getAppInstByID(ctx, request.AppInstanceId)
	if err != nil {
		return nil, nbi.NewErrorInfo(http.StatusBadRequest, err.Error())
	}
	if appInst == nil {
		return nil, nbi.NewErrorInfo(http.StatusNotFound, "app instance not found")
	}
	err = s.allApis.appInstApi.DeleteAppInst(appInst, NewStreamoutAppInst(ctx))
	if err != nil {
		return nil, nbi.NewErrorInfo(http.StatusBadRequest, err.Error())
	}
	resp := nbi.DeleteAppInstance202Response{}
	return resp, nil
}

type StreamoutAppInst struct {
	grpc.ServerStream
	ctx context.Context
}

func NewStreamoutAppInst(ctx context.Context) *StreamoutAppInst {
	return &StreamoutAppInst{
		ctx: ctx,
	}
}

func (s *StreamoutAppInst) Send(res *edgeproto.Result) error {
	log.SpanLog(s.ctx, log.DebugLevelApi, res.Message)
	return nil
}

func (s *StreamoutAppInst) Context() context.Context {
	return s.ctx
}

func (s *NBIAPI) GetClusters(ctx context.Context, request nbi.GetClustersRequestObject) (nbi.GetClustersResponseObject, error) {
	filter := &edgeproto.ClusterInst{}
	if request.Params.ClusterRef != nil {
		filter.ObjId = *request.Params.ClusterRef
	}
	insts := []nbi.ClusterInfo{}
	err := s.allApis.clusterInstApi.cache.Show(filter, func(obj *edgeproto.ClusterInst) error {
		insts = append(insts, *s.NBICluster(obj))
		return nil
	})
	if err != nil {
		return nil, nbi.NewErrorInfo(http.StatusInternalServerError, err.Error())
	}
	resp := nbi.GetClusters200JSONResponse{}
	resp.Body = insts
	slices.SortStableFunc(resp.Body, NBIClusterSort)
	return nbi.GetClustersResponseObject(resp), nil
}

func (s *NBIAPI) GetEdgeCloudZones(ctx context.Context, request nbi.GetEdgeCloudZonesRequestObject) (nbi.GetEdgeCloudZonesResponseObject, error) {
	filter := &edgeproto.Zone{}
	resp := nbi.GetEdgeCloudZones200JSONResponse{}
	err := s.allApis.zoneApi.cache.Show(filter, func(obj *edgeproto.Zone) error {
		resp.Body = append(resp.Body, *NBIZone(obj, *region))
		return nil
	})
	if err != nil {
		return nil, nbi.NewErrorInfo(http.StatusInternalServerError, err.Error())
	}
	slices.SortStableFunc(resp.Body, NBIZoneSort)
	return nbi.GetEdgeCloudZonesResponseObject(resp), nil
}
