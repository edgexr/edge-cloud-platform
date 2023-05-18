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

package federationmgmt

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/edgexr/edge-cloud-platform/pkg/fedewapi"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormclient"
	pkgtls "github.com/edgexr/edge-cloud-platform/pkg/tls"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

type Client struct {
	addr        string
	tokenSource oauth2.TokenSource
	fedKey      *FedKey
	auditLogCb  AuditLogCb
}

type AuditLogCb func(ctx context.Context, eventName string, fedKey *FedKey, data *ormclient.AuditLogData)

var ClientSecretFieldClearer = util.NewJsonFieldClearer("clientSecret")

// For callers who connect to multiple federations
// TODO: need a periodic thread to remove stale sources
type TokenSourceCache struct {
	apiKeyHandler ApiKeyHandler
	sources       map[FedKey]oauth2.TokenSource
	sync.Mutex
}

// Abstract way to lookup key, allows for either direct vault lookup
// or lookup from Controller via accessapi.
type ApiKeyHandler interface {
	GetFederationAPIKey(ctx context.Context, keyId *FedKey) (*ApiKey, error)
}

func NewTokenSource(ctx context.Context, apiKey *ApiKey) oauth2.TokenSource {
	config := clientcredentials.Config{
		ClientID:     apiKey.Id,
		ClientSecret: apiKey.Key,
		TokenURL:     apiKey.TokenUrl,
		Scopes:       []string{"fed-mgmt"},
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if pkgtls.IsTestTls() {
		// skip verification for e2e-test self-signed certs
		log.SpanLog(ctx, log.DebugLevelApi, "NewTokenSource using insecure skip verify")
		tlsConfig.InsecureSkipVerify = true
	}
	httpClient := &http.Client{
		Transport: &http.Transport{
			// settings from http.DefaultTransport
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
			TLSClientConfig:       tlsConfig,
		},
	}
	ctx = context.WithValue(context.Background(), oauth2.HTTPClient, httpClient)
	return config.TokenSource(ctx)
}

func NewTokenSourceCache(apiKeyHandler ApiKeyHandler) *TokenSourceCache {
	return &TokenSourceCache{
		apiKeyHandler: apiKeyHandler,
		sources:       make(map[FedKey]oauth2.TokenSource),
	}
}

func (s *TokenSourceCache) Get(ctx context.Context, fedKey *FedKey) (oauth2.TokenSource, error) {
	s.Lock()
	tokenSource, ok := s.sources[*fedKey]
	s.Unlock()
	if !ok {
		// don't hold lock during network call
		apiKey, err := s.apiKeyHandler.GetFederationAPIKey(ctx, fedKey)
		if err != nil {
			return nil, fmt.Errorf("failed to get apikey: %s", err)
		}
		tokenSource = NewTokenSource(ctx, apiKey)
		s.Lock()
		// recheck in case another thread added it
		if ts, ok := s.sources[*fedKey]; ok {
			tokenSource = ts
		} else {
			s.sources[*fedKey] = tokenSource
		}
		s.Unlock()
	}
	return tokenSource, nil
}

// Clear will remove the cached token source. This is needed
// if the credentials have been changed.
func (s *TokenSourceCache) Clear(ctx context.Context, fedKey *FedKey) {
	s.Lock()
	defer s.Unlock()
	delete(s.sources, *fedKey)
}

func (s *TokenSourceCache) Client(ctx context.Context, addr string, fedKey *FedKey, auditLogCb AuditLogCb) (*Client, error) {
	tokenSource, err := s.Get(ctx, fedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to get token source: %s", err)
	}
	return NewClient(addr, tokenSource, fedKey, auditLogCb), nil
}

// Create a new client for federation requests.
// Client caches auth creds and token, and is meant to be reused.
func NewClient(addr string, tokenSource oauth2.TokenSource, fedKey *FedKey, auditLogCb AuditLogCb) *Client {
	if !strings.HasPrefix(addr, "http") {
		addr = "https://" + addr
	}
	addr = strings.TrimSuffix(addr, "/")
	return &Client{
		addr:        addr,
		tokenSource: tokenSource,
		fedKey:      fedKey,
		auditLogCb:  auditLogCb,
	}
}

var okStatuses = map[int]struct{}{
	http.StatusOK:       struct{}{},
	http.StatusCreated:  struct{}{},
	http.StatusAccepted: struct{}{},
}

func (c *Client) SendRequest(ctx context.Context, eventName, method, endpoint string, reqData, replyData interface{}, headerVals http.Header) (int, http.Header, error) {
	if c.addr == "" {
		return 0, nil, fmt.Errorf("Missing federation address")
	}

	token, err := c.tokenSource.Token()
	if err != nil {
		return 0, nil, fmt.Errorf("failed to get federation token for %s: %s", c.addr, err)
	}

	restClient := &ormclient.Client{
		TokenType: token.TokenType,
		Timeout:   60 * time.Minute,
		AuditLogFunc: func(data *ormclient.AuditLogData) {
			c.audit(ctx, eventName, c.fedKey, data)
		},
		ParseErrorFunc: c.parseFedError,
	}
	if pkgtls.IsTestTls() {
		restClient.SkipVerify = true
	}
	requestUrl := fmt.Sprintf("%s%s", c.addr, endpoint)
	log.SpanLog(ctx, log.DebugLevelApi, "federation send request", "method", method, "remoteurl", requestUrl)
	status, respHeader, err := restClient.HttpJsonSend(method, requestUrl, token.AccessToken, reqData, replyData, headerVals, nil, okStatuses)
	if err != nil {
		return status, nil, fmt.Errorf("%s %s failed: %s", method, requestUrl, err)
	}
	if _, ok := okStatuses[status]; !ok {
		return status, nil, fmt.Errorf("Bad response for %s request to URL %s, status=%s", method, requestUrl, http.StatusText(status))
	}
	return status, respHeader, nil
}

func (c *Client) audit(ctx context.Context, eventName string, fedKey *FedKey, data *ormclient.AuditLogData) {
	data.RespBody = ClientSecretFieldClearer.Clear(data.RespBody)

	log.SpanLog(ctx, log.DebugLevelApi, eventName, "method", data.Method, "remoteurl", data.Url.String(), "reqContentType", data.ReqContentType, "req", string(data.ReqBody), "reqheaders", util.GetHeadersString(data.ReqHeader), "status", data.Status, "respContentType", data.RespContentType, "respheaders", util.GetHeadersString(data.RespHeader), "resp", string(data.RespBody), "err", data.Err, "took", data.End.Sub(data.Start).String())
	if c.auditLogCb != nil {
		c.auditLogCb(ctx, eventName, fedKey, data)
	}
}

func (c *Client) parseFedError(body []byte) error {
	problem := fedewapi.ProblemDetails{}
	err := json.Unmarshal(body, &problem)
	if err != nil || problem.Title == nil && problem.Detail == nil && problem.Cause == nil {
		// unknown format, return string instead
		return fmt.Errorf("%s", string(body))
	}
	msgs := []string{}
	if problem.Title != nil {
		msgs = append(msgs, *problem.Title)
	}
	if problem.Detail != nil {
		msgs = append(msgs, *problem.Detail)
	}
	if problem.Cause != nil {
		msgs = append(msgs, *problem.Cause)
	}
	invalidParams := []string{}
	for _, param := range problem.InvalidParams {
		str := param.Param
		if param.Reason != nil {
			str += "(" + *param.Reason + ")"
		}
		invalidParams = append(invalidParams, str)
	}
	if len(invalidParams) > 0 {
		msgs = append(msgs, "invalid params: %s", strings.Join(invalidParams, ","))
	}
	return errors.New(strings.Join(msgs, ", "))
}
