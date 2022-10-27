package federation

import (
	"fmt"
	"net/http"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/fedewapi"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ctrlclient"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormutil"
	"github.com/labstack/echo/v4"
)

// Remote partner federator sends this request to us to onboard an application
func (p *PartnerApi) OnboardApplication(c echo.Context, fedCtxId FederationContextId) error {
	ctx := ormutil.GetContext(c)
	// lookup federation provider based on claims
	provider, err := p.lookupProvider(c, fedCtxId)
	if err != nil {
		return err
	}

	req := fedewapi.OnboardApplicationRequest{}
	if err := c.Bind(&req); err != nil {
		return err
	}

	log.SpanLog(ctx, log.DebugLevelApi, "Federation app onboarding", "request", req)
	if req.AppId == "" {
		return fmt.Errorf("Missing application ID")
	}
	if req.AppProviderId == "" {
		return fmt.Errorf("Missing provider ID")
	}
	if req.AppMetaData.AppName == "" {
		return fmt.Errorf("Missing app name")
	}
	if req.AppMetaData.Version == "" {
		return fmt.Errorf("Missing app version")
	}
	if len(req.AppComponentSpecs) == 0 {
		return fmt.Errorf("Missing component details")
	}

	if len(req.AppComponentSpecs) > 1 {
		return fmt.Errorf("Only one component detail is supported, more than one specified")
	}
	for ii, spec := range req.AppComponentSpecs {
		if spec.ComponentName == nil || *spec.ComponentName == "" {
			return fmt.Errorf("Missing component name for AppComponentSpec[%d]", ii)
		}
		if spec.ArtefactId != "" {
			// TODO: verify that artefact exists
		}
	}

	// create app in provider regions
	for _, region := range provider.Regions {
		rc := ormutil.RegionContext{
			Region:    region,
			SkipAuthz: true,
			Database:  p.database,
		}
		// Create App
		appIn := edgeproto.App{
			Key: edgeproto.AppKey{
				Organization: provider.FederationContextId,
				Name:         req.AppId,
				Version:      AllAppsVersion,
			},
			ImagePath:   "",                                    // TODO: based on Artefact?
			ImageType:   edgeproto.ImageType_IMAGE_TYPE_DOCKER, // TODO: based on Artefect?
			Deployment:  cloudcommon.DeploymentTypeKubernetes,  // TODO: based on Artefact?
			AccessPorts: "",                                    // TODO: no ports in spec?
			Annotations: getAppAnnotation(req.AppId),
		}
		log.SpanLog(ctx, log.DebugLevelApi, "Federation creating app", "app", appIn)
		_, err = ctrlclient.CreateAppObj(ctx, &rc, &appIn, p.connCache)
		if err != nil {
			return err
		}
		/* TODO: likely remove
		// Create ClusterInst
		clusterInstIn := edgeproto.ClusterInst{
			Key: edgeproto.ClusterInstKey{
				ClusterKey: edgeproto.ClusterKey{
					Name: req.AppId,
				},
				CloudletKey: edgeproto.CloudletKey{
					Name:         req.Regions[0].Zone,
					Organization: req.Regions[0].Operator,
				},
				Organization: "", // TODO
			},
			Flavor: edgeproto.FlavorKey{
				Name: resRequirements.ResourceProfileId,
			},
			IpAccess:   edgeproto.IpAccess_IP_ACCESS_SHARED,
			Deployment: cloudcommon.DeploymentTypeKubernetes,
			NumNodes:   1, // Not specified, hence default to 1
		}
		log.SpanLog(ctx, log.DebugLevelApi, "Federation creating clusterinst", "clusterinst", clusterInstIn)
		err = ctrlclient.CreateClusterInstStream(
			ctx, &rc, &clusterInstIn, p.connCache,
			func(res *edgeproto.Result) error {
				log.SpanLog(ctx, log.DebugLevelApi, "Federation clusterinst creation status", "clusterinst key", clusterInstIn.Key, "result", res)
				return nil
			},
		)
		if err != nil {
			return err
		}
		*/
	}
	c.Response().WriteHeader(http.StatusAccepted)
	return nil
}

func getAppAnnotation(appId string) string {
	return fmt.Sprintf("id=%s", appId)
}

// ViewApplication gets onboarded app
func (p *PartnerApi) ViewApplication(c echo.Context, fedCtxId FederationContextId, appId AppIdentifier) error {
	ctx := ormutil.GetContext(c)
	// lookup federation provider based on claims
	provider, err := p.lookupProvider(c, fedCtxId)
	if err != nil {
		return err
	}

	// only need to get from one region
	region := provider.Regions[0]
	rc := ormutil.RegionContext{
		Region:    region,
		SkipAuthz: true,
		Database:  p.database,
	}

	log.SpanLog(ctx, log.DebugLevelApi, "Federation show app", "app", appId, "fedctxid", fedCtxId)
	filter := edgeproto.App{
		Key: edgeproto.AppKey{
			Organization: provider.FederationContextId,
			Name:         string(appId),
			Version:      AllAppsVersion,
		},
	}
	appFound := false
	err = ctrlclient.ShowAppStream(ctx, &rc, &filter, p.connCache, nil,
		func(app *edgeproto.App) error {
			if app != nil {
				log.SpanLog(ctx, log.DebugLevelApi, "Federation show app found", "app", app)
				appFound = true
			}
			return nil
		},
	)
	if err != nil {
		return err
	}
	if !appFound {
		return fmt.Errorf("App not found")
	}
	/* TODO: likely remove
	log.SpanLog(ctx, log.DebugLevelApi, "Federation show clusterInst", "clusterInst", appObStatusReq.AppId)
	clusterInstKey := edgeproto.ClusterInstKey{
		ClusterKey: edgeproto.ClusterKey{
			Name: appObStatusReq.AppId,
		},
		Organization: "", // TODO
	}
	clusterInstFound := false
	err = ctrlclient.ShowClusterInstStream(
		ctx, &rc, &edgeproto.ClusterInst{Key: clusterInstKey}, p.connCache, nil,
		func(clusterInst *edgeproto.ClusterInst) error {
			if clusterInst != nil {
				clusterInstFound = true
				log.SpanLog(ctx, log.DebugLevelApi, "Federation show clusterInst found", "clusterInst", clusterInst)
			}
			return nil
		},
	)
	if err != nil {
		return err
	}
	*/
	out := fedewapi.ViewApplication200Response{
		AppId: string(appId),
	}
	return c.JSON(http.StatusOK, &out)
}

// Remote partner federator sends this request to us to deboard application
func (p *PartnerApi) DeboardApplication(c echo.Context, fedCtxId FederationContextId, appId AppIdentifier, zoneId ZoneIdentifier) error {
	ctx := ormutil.GetContext(c)
	// lookup federation provider based on claims
	provider, err := p.lookupProvider(c, fedCtxId)
	if err != nil {
		return err
	}

	app := edgeproto.App{
		Key: edgeproto.AppKey{
			Organization: provider.FederationContextId,
			Name:         string(appId),
			Version:      AllAppsVersion,
		},
	}

	for _, region := range provider.Regions {
		rc := ormutil.RegionContext{
			Region:    region,
			SkipAuthz: true,
			Database:  p.database,
		}
		/* TODO: likely remove
		// Fetch zone details
		lookup := ormapi.FederatorZone{
			ZoneId: appDeboardReq.Zone,
		}
		zoneInfo := ormapi.FederatorZone{}
		res := db.Where(&lookup).First(&zoneInfo)
		if !res.RecordNotFound() && err != nil {
			return ormutil.DbErr(err)
		}

		// Delete ClusterInst
		clusterInstKey := edgeproto.ClusterInstKey{
			ClusterKey: edgeproto.ClusterKey{
				Name: appDeboardReq.AppId,
			},
			CloudletKey: edgeproto.CloudletKey{
				Name:         appDeboardReq.Zone,
				Organization: zoneInfo.OperatorId,
			},
			Organization: "", // TODO
		}
		log.SpanLog(ctx, log.DebugLevelApi, "Federation delete clusterInst", "clusterInst", clusterInstKey)
		err = ctrlclient.DeleteClusterInstStream(
			ctx, &rc, &edgeproto.ClusterInst{Key: clusterInstKey}, p.connCache,
			func(res *edgeproto.Result) error {
				return nil
			},
		)
		if err != nil {
			return err
		}
		*/
		// Delete App
		log.SpanLog(ctx, log.DebugLevelApi, "Federation delete app", "app", app)
		_, err = ctrlclient.DeleteAppObj(ctx, &rc, &app, p.connCache)
		if err != nil {
			return err
		}
	}
	return nil
}

func (p *PartnerApi) UpdateApplication(c echo.Context, fedCtxId FederationContextId, appId AppIdentifier) error {
	return fmt.Errorf("not implemented yet")
}

func (p *PartnerApi) OnboardExistingAppNewZones(c echo.Context, fedCtxId FederationContextId, appId AppIdentifier) error {
	return fmt.Errorf("not supported")
}

func (p *PartnerApi) LockUnlockApplicationZone(c echo.Context, fedCtxId FederationContextId, appId AppIdentifier) error {
	return fmt.Errorf("not supported")
}
