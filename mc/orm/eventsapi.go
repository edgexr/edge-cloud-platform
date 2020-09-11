package orm

import (
	"context"
	"net/http"
	"time"

	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud/cloudcommon/node"
)

func ShowEvents(c echo.Context) error {
	return searchEvents(c, nodeMgr.ShowEvents)
}

func FindEvents(c echo.Context) error {
	return searchEvents(c, nodeMgr.FindEvents)
}

func searchEvents(c echo.Context, searchFunc func(context.Context, *node.EventSearch) ([]node.EventData, error)) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := GetContext(c)

	search := node.EventSearch{}
	if err := c.Bind(&search); err != nil {
		return bindErr(c, err)
	}
	if err := search.TimeRange.Resolve(48 * time.Hour); err != nil {
		return c.JSON(http.StatusBadRequest, MsgErr(err))
	}

	// get all orgs user can view
	allowedOrgs, err := enforcer.GetAuthorizedOrgs(ctx, claims.Username, ResourceUsers, ActionView)
	if err != nil {
		return err
	}
	if _, found := allowedOrgs[""]; !found {
		// non-admin, enforce allowed orgs in search
		for k, _ := range allowedOrgs {
			if k == "" {
				continue
			}
			search.AllowedOrgs = append(search.AllowedOrgs, k)
		}
	}

	events, err := searchFunc(ctx, &search)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, MsgErr(err))
	}
	return c.JSON(http.StatusOK, events)
}

func EventTerms(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := GetContext(c)

	search := node.EventSearch{}
	if err := c.Bind(&search); err != nil {
		return bindErr(c, err)
	}
	if err := search.TimeRange.Resolve(node.DefaultTimeDuration); err != nil {
		return c.JSON(http.StatusBadRequest, MsgErr(err))
	}

	// get all orgs user can view
	allowedOrgs, err := enforcer.GetAuthorizedOrgs(ctx, claims.Username, ResourceUsers, ActionView)
	if err != nil {
		return err
	}
	if _, found := allowedOrgs[""]; !found {
		// non-admin, enforce allowed orgs in search
		for k, _ := range allowedOrgs {
			if k == "" {
				continue
			}
			search.AllowedOrgs = append(search.AllowedOrgs, k)
		}
	}

	terms, err := nodeMgr.EventTerms(ctx, &search)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, MsgErr(err))
	}
	return c.JSON(http.StatusOK, *terms)
}
