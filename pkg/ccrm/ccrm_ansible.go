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

package ccrm

import (
	"context"
	"crypto/md5"
	_ "embed"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/echoutil"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/passhash"
	"github.com/edgexr/edge-cloud-platform/pkg/platform/common/confignode"
	"github.com/labstack/echo/v4"
)

const RouteNode = "confignode"
const ecNode = "node"

//go:embed ansible.tar.gz
var ansibleArchive []byte

var ansibleArchiveChecksum string
var badAuthDelay = 3 * time.Second

func init() {
	// get checksum of archive
	ansibleArchiveChecksum = fmt.Sprintf("%x", md5.Sum(ansibleArchive))
}

func (s *CCRM) initAnsibleServer(ctx context.Context) *echo.Echo {
	e := echo.New()
	e.HideBanner = true

	log.SpanLog(ctx, log.DebugLevelInfo, "init ansible server", "archive-checksum", ansibleArchiveChecksum)

	e.GET("/", func(c echo.Context) error {
		return c.String(http.StatusOK, "OK")
	})

	// Handle requests from VMs or Machines to configure and
	// provision themselves via the included ansible scripts.

	// Node routes
	node := e.Group(RouteNode)
	node.Use(s.authRequest)
	node.GET("/ansible.tar.gz.md5", s.getAnsibleChecksum)
	node.GET("/ansible.tar.gz", s.getAnsibleArchive)
	node.GET("/vars.yaml.md5", s.getNodeVarsChecksum)
	node.GET("/vars.yaml", s.getNodeVarsFile)
	return e
}

func (s *CCRM) startAnsibleServer(ctx context.Context, e *echo.Echo) {
	s.echoServ = e
	go func() {
		// TLS to be handled externally
		err := s.echoServ.Start(s.flags.AnsibleListenAddr)
		if err != nil && err != http.ErrServerClosed {
			log.FatalLog("failed to serve webserv", "err", err)
		}
	}()
}

func (s *CCRM) stopAnsibleServer() {
	if s.echoServ != nil {
		s.echoServ.Close()
	}
	s.echoServ = nil
}

func (s *CCRM) authRequest(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) (reterr error) {
		req := c.Request()
		// set up span
		span := log.StartSpan(log.DebugLevelApi, req.URL.Path)
		span.SetTag("remote-ip", c.RealIP())
		span.SetTag("method", req.Method)
		span.SetTag("uri", req.RequestURI)
		defer span.Finish()
		defer func() {
			span.SetTag("status", c.Response().Status)
			span.SetTag("err", reterr)
		}()
		ctx := log.ContextWithSpan(req.Context(), span)
		ec := echoutil.NewEchoContext(c, ctx, time.Now())

		// expect basic auth
		username, password, ok := req.BasicAuth()
		if !ok {
			return &echo.HTTPError{
				Code:     http.StatusUnauthorized,
				Message:  "no basic auth found",
				Internal: fmt.Errorf("basic auth missing"),
			}
		}
		// cloudlet key info in headers
		cloudletName := req.Header.Get(confignode.CloudletNameHeader)
		if cloudletName == "" {
			return &echo.HTTPError{
				Code:    http.StatusBadRequest,
				Message: confignode.CloudletNameHeader + " header missing",
			}
		}
		cloudletOrg := req.Header.Get(confignode.CloudletOrgHeader)
		if cloudletOrg == "" {
			return &echo.HTTPError{
				Code:    http.StatusBadRequest,
				Message: confignode.CloudletOrgHeader + " header missing",
			}
		}
		cloudletNode := edgeproto.CloudletNode{}
		cloudletNode.Key.Name = username
		cloudletNode.Key.CloudletKey.Name = cloudletName
		cloudletNode.Key.CloudletKey.Organization = cloudletOrg
		log.SetTags(span, cloudletNode.Key.GetTags())

		if !s.caches.CloudletNodeCache.Get(&cloudletNode.Key, &cloudletNode) {
			time.Sleep(badAuthDelay)
			return &echo.HTTPError{
				Code:     http.StatusUnauthorized,
				Message:  "Invalid username or password",
				Internal: cloudletNode.Key.NotFoundError(),
			}
		}
		// validate password
		matches, err := passhash.PasswordMatches(password, cloudletNode.PasswordHash, cloudletNode.Salt, int(cloudletNode.Iter))
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "password matches func error", "err", err)
		}
		if !matches || err != nil {
			time.Sleep(badAuthDelay)
			return &echo.HTTPError{
				Code:     http.StatusUnauthorized,
				Message:  "Invalid username or password",
				Internal: errors.New("password mismatch"),
			}
		}
		ec.Set(ecNode, &cloudletNode)
		return next(ec)
	}
}

func getCloudletNode(c echo.Context) *edgeproto.CloudletNode {
	val := c.Get(ecNode)
	ctx := echoutil.GetContext(c)
	node, ok := val.(*edgeproto.CloudletNode)
	if !ok {
		log.SpanLog(ctx, log.DebugLevelApi, "no cloudlet node in context")
		return &edgeproto.CloudletNode{}
	}
	return node
}

func (s *CCRM) getAnsibleChecksum(c echo.Context) error {
	fileContents := fmt.Sprintf("%s  ansible.tar.gz\n", ansibleArchiveChecksum)
	return c.Blob(http.StatusOK, "text/plain", []byte(fileContents))
}

func (s *CCRM) getAnsibleArchive(c echo.Context) error {
	return c.Blob(http.StatusOK, "application/gzip", ansibleArchive)
}

func (s *CCRM) getNodeVarsChecksum(c echo.Context) error {
	node := getCloudletNode(c)
	data, ok := s.handler.nodeAttributesCache.Get(node.Key)
	if !ok {
		return c.HTML(http.StatusNotFound, "")
	}
	fileContents := fmt.Sprintf("%s  vars.yaml\n", data.checksum)
	return c.Blob(http.StatusOK, "text/plain", []byte(fileContents))
}

func (s *CCRM) getNodeVarsFile(c echo.Context) error {
	node := getCloudletNode(c)
	data, ok := s.handler.nodeAttributesCache.Get(node.Key)
	if !ok {
		return c.HTML(http.StatusNotFound, "")
	}
	return c.Blob(http.StatusOK, "text/plain", data.yamlData)
}
