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
	"context"
	"net/http"
	"time"

	"github.com/labstack/echo"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud-infra/mc/ormutil"
	"github.com/edgexr/edge-cloud/cloudcommon/node"
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
	ctx := ormutil.GetContext(c)

	search := node.EventSearch{}
	if err := c.Bind(&search); err != nil {
		return ormutil.BindErr(err)
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
	if len(allowedOrgs) == 0 {
		return echo.ErrForbidden
	}

	events, err := searchFunc(ctx, &search)
	if err != nil {
		return ormutil.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	isAdmin, err := isUserAdmin(ctx, claims.Username)
	if err != nil {
		return err
	}
	if !isAdmin {
		orgs, err := GetAllOrgs(ctx)
		if err != nil {
			return err
		}
		events = filterEvents(events, orgs)
	}
	return c.JSON(http.StatusOK, events)
}

// Filter out events from before the org was created.
// This prevents seeing events from a previous org of the same name.
func filterEvents(events []node.EventData, orgs map[string]*ormapi.Organization) []node.EventData {
	filteredEvents := []node.EventData{}
	for _, event := range events {
		var createdAt time.Time
		for _, orgName := range event.Org {
			org, ok := orgs[orgName]
			if !ok {
				continue
			}
			if createdAt.IsZero() || org.CreatedAt.Before(createdAt) {
				createdAt = org.CreatedAt
			}
		}
		if createdAt.IsZero() || event.Timestamp.Before(createdAt) {
			continue
		}
		filteredEvents = append(filteredEvents, event)
	}
	return filteredEvents
}

func EventTerms(c echo.Context) error {
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	ctx := ormutil.GetContext(c)

	search := node.EventSearch{}
	if err := c.Bind(&search); err != nil {
		return ormutil.BindErr(err)
	}
	if err := search.TimeRange.Resolve(node.DefaultTimeDuration); err != nil {
		return err
	}

	// get all orgs user can view
	allowedOrgs, err := enforcer.GetAuthorizedOrgs(ctx, claims.Username, ResourceUsers, ActionView)
	if err != nil {
		return err
	}
	if len(allowedOrgs) == 0 {
		return echo.ErrForbidden
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
		return ormutil.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	return c.JSON(http.StatusOK, *terms)
}

func SpanTerms(c echo.Context) error {
	params, err := getSpanSearchParams(c)
	if err != nil {
		return err
	}
	out, err := nodeMgr.SpanTerms(ormutil.GetContext(c), params)
	if err != nil {
		return ormutil.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	return c.JSON(http.StatusOK, out)
}

func ShowSpans(c echo.Context) error {
	params, err := getSpanSearchParams(c)
	if err != nil {
		return err
	}
	out, err := nodeMgr.ShowSpansCondensed(ormutil.GetContext(c), params)
	if err != nil {
		return ormutil.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	return c.JSON(http.StatusOK, out)
}

func ShowSpansVerbose(c echo.Context) error {
	params, err := getSpanSearchParams(c)
	if err != nil {
		return err
	}
	out, err := nodeMgr.ShowSpans(ormutil.GetContext(c), params)
	if err != nil {
		return ormutil.NewHTTPError(http.StatusInternalServerError, err.Error())
	}
	return c.JSON(http.StatusOK, out)
}

func getSpanSearchParams(c echo.Context) (*node.SpanSearch, error) {
	claims, err := getClaims(c)
	if err != nil {
		return nil, err
	}
	ctx := ormutil.GetContext(c)

	search := node.SpanSearch{}
	if err := c.Bind(&search); err != nil {
		return nil, ormutil.BindErr(err)
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
