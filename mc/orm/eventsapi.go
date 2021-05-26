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
		return bindErr(err)
	}
	if err := search.TimeRange.Resolve(48 * time.Hour); err != nil {
		return err
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
		return newHTTPError(http.StatusInternalServerError, err.Error())
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
		return bindErr(err)
	}
	if err := search.TimeRange.Resolve(node.DefaultTimeDuration); err != nil {
		return err
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
		return newHTTPError(http.StatusInternalServerError, err.Error())
	}
	return c.JSON(http.StatusOK, *terms)
}

func SpanTerms(c echo.Context) error {
	params, err := getSpanSearchParams(c)
	if err != nil {
		return err
	}
	out, err := nodeMgr.SpanTerms(GetContext(c), params)
	if err != nil {
		return newHTTPError(http.StatusInternalServerError, err.Error())
	}
	return c.JSON(http.StatusOK, out)
}

func ShowSpans(c echo.Context) error {
	params, err := getSpanSearchParams(c)
	if err != nil {
		return err
	}
	out, err := nodeMgr.ShowSpansCondensed(GetContext(c), params)
	if err != nil {
		return newHTTPError(http.StatusInternalServerError, err.Error())
	}
	return c.JSON(http.StatusOK, out)
}

func ShowSpansVerbose(c echo.Context) error {
	params, err := getSpanSearchParams(c)
	if err != nil {
		return err
	}
	out, err := nodeMgr.ShowSpans(GetContext(c), params)
	if err != nil {
		return newHTTPError(http.StatusInternalServerError, err.Error())
	}
	return c.JSON(http.StatusOK, out)
}

func getSpanSearchParams(c echo.Context) (*node.SpanSearch, error) {
	claims, err := getClaims(c)
	if err != nil {
		return nil, err
	}
	ctx := GetContext(c)

	search := node.SpanSearch{}
	if err := c.Bind(&search); err != nil {
		return nil, bindErr(err)
	}
	if err := search.TimeRange.Resolve(48 * time.Hour); err != nil {
		return nil, err
	}
	// admin only
	if err := authorized(ctx, claims.Username, "", ResourceControllers, ActionManage); err != nil {
		return nil, err
	}
	return &search, nil
}
