package orm

import (
	fmt "fmt"
	"net/http"

	edgeproto "github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/federationmgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/fedewapi"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ctrlclient"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormutil"
	"github.com/labstack/echo/v4"
)

func federationGetPartner(c echo.Context, consumerName, reqPath string, respObj interface{}) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	consumer, err := lookupFederationConsumer(ctx, 0, consumerName)
	if err != nil {
		return err
	}
	if err := fedAuthorized(ctx, claims.Username, consumer.OperatorId); err != nil {
		return err
	}
	apiPath := fmt.Sprintf("/%s/%s/%s", federationmgmt.ApiRoot, consumer.FederationContextId, reqPath)
	fedClient, err := partnerApi.ConsumerPartnerClient(ctx, consumer)
	_, _, err = fedClient.SendRequest(ctx, "GET", apiPath, nil, respObj, nil)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, respObj)
}

func FederationGetPartner(c echo.Context) error {
	in := ormapi.FederationConsumer{}
	if err := c.Bind(&in); err != nil {
		return ormutil.BindErr(err)
	}
	reqPath := "partner"
	resp := fedewapi.GetFederationDetails200Response{}
	return federationGetPartner(c, in.Name, reqPath, &resp)
}

func FederationGetZone(c echo.Context) error {
	in := ormapi.ConsumerZone{}
	if err := c.Bind(&in); err != nil {
		return ormutil.BindErr(err)
	}
	reqPath := "zones/" + in.ZoneId
	resp := fedewapi.ZoneRegisteredData{}
	return federationGetPartner(c, in.ConsumerName, reqPath, &resp)
}

func FederationGetArtefact(c echo.Context) error {
	in := ormapi.ConsumerApp{}
	if err := c.Bind(&in); err != nil {
		return ormutil.BindErr(err)
	}
	reqPath := "artefact/" + in.ID
	resp := fedewapi.GetArtefact200Response{}
	return federationGetPartner(c, in.FederationName, reqPath, &resp)
}

func FederationGetFile(c echo.Context) error {
	in := ormapi.ConsumerImage{}
	if err := c.Bind(&in); err != nil {
		return ormutil.BindErr(err)
	}
	reqPath := "files/" + in.ID
	resp := fedewapi.ViewFile200Response{}
	return federationGetPartner(c, in.FederationName, reqPath, &resp)
}

func FederationGetApp(c echo.Context) error {
	in := ormapi.ConsumerApp{}
	if err := c.Bind(&in); err != nil {
		return ormutil.BindErr(err)
	}
	reqPath := "application/onboarding/app/" + in.ID
	resp := fedewapi.ViewApplication200Response{}
	return federationGetPartner(c, in.FederationName, reqPath, &resp)
}

func FederationGetAppInst(c echo.Context) error {
	in := ormapi.RegionAppInst{}
	if err := c.Bind(&in); err != nil {
		return ormutil.BindErr(err)
	}
	// TODO: need to change appinst get path to only require appinst id,
	// then we can just take a edgeproto.FedAppInstKey as input
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	rc := &ormutil.RegionContext{
		Region:   in.Region,
		Database: database,
	}
	authz, err := newShowAppInstAuthz(ctx, rc.Region, claims.Username, ResourceAppInsts, ActionView)
	if err != nil {
		return err
	}
	insts := []*edgeproto.AppInst{}
	err = ctrlclient.ShowAppInstStream(ctx, rc, &in.AppInst, connCache, authz, func(ai *edgeproto.AppInst) error {
		if ai.FedKey.FederationName == "" {
			return nil
		}
		insts = append(insts, ai)
		return nil
	})
	if len(insts) == 0 {
		return fmt.Errorf("No federated AppInsts found")
	}
	log.SpanLog(ctx, log.DebugLevelApi, "Direct fed query", "appinst", in.AppInst)
	log.SpanLog(ctx, log.DebugLevelApi, "Direct fed insts", "len", len(insts), "insts", insts)
	apps := make(map[edgeproto.AppKey]*edgeproto.App)
	err = ctrlclient.ShowAppStream(ctx, rc, &edgeproto.App{}, connCache, nil, func(app *edgeproto.App) error {
		apps[app.Key] = app
		return nil
	})
	outInsts := []fedewapi.GetAppInstanceDetails200Response{}
	for _, ai := range insts {
		consumer, err := lookupFederationConsumer(ctx, 0, ai.FedKey.FederationName)
		if err != nil {
			return err
		}
		app, ok := apps[ai.Key.AppKey]
		if !ok {
			log.SpanLog(ctx, log.DebugLevelApi, "No app found for instance", "inst", ai.Key)
			continue
		}
		apiPath := fmt.Sprintf("/%s/%s/application/lcm/app/%s/instance/%s/zone/%s", federationmgmt.ApiRoot, consumer.FederationContextId, app.GlobalId, ai.FedKey.AppInstId, ai.Key.ClusterInstKey.CloudletKey.Name)
		out := fedewapi.GetAppInstanceDetails200Response{}
		fedClient, err := partnerApi.ConsumerPartnerClient(ctx, consumer)
		_, _, err = fedClient.SendRequest(ctx, "GET", apiPath, nil, &out, nil)
		if err != nil {
			return err
		}
		outInsts = append(outInsts, out)
	}
	return c.JSON(http.StatusOK, outInsts)
}
