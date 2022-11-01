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
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormclient"
	pkgtls "github.com/edgexr/edge-cloud-platform/pkg/tls"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

type Client struct {
	addr        string
	tokenSource oauth2.TokenSource
}

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
	ctx = context.WithValue(ctx, oauth2.HTTPClient, httpClient)
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
			return nil, err
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

func (s *TokenSourceCache) Client(ctx context.Context, addr string, fedKey *FedKey) (*Client, error) {
	tokenSource, err := s.Get(ctx, fedKey)
	if err != nil {
		return nil, err
	}
	return NewClient(addr, tokenSource), nil
}

// Create a new client for federation requests.
// Client caches auth creds and token, and is meant to be reused.
func NewClient(addr string, tokenSource oauth2.TokenSource) *Client {
	if !strings.HasPrefix(addr, "http") {
		addr = "https://" + addr
	}
	addr = strings.TrimSuffix(addr, "/")
	return &Client{
		addr:        addr,
		tokenSource: tokenSource,
	}
}

func (c *Client) SendRequest(ctx context.Context, method, endpoint string, reqData, replyData interface{}, headerVals http.Header) (http.Header, error) {
	if c.addr == "" {
		return nil, fmt.Errorf("Missing federation address")
	}
	token, err := c.tokenSource.Token()
	if err != nil {
		return nil, err
	}

	restClient := &ormclient.Client{
		TokenType: token.TokenType,
	}
	if pkgtls.IsTestTls() {
		restClient.SkipVerify = true
	}
	requestUrl := fmt.Sprintf("%s%s", c.addr, endpoint)
	log.SpanLog(ctx, log.DebugLevelApi, "federation send request", "method", method, "url", requestUrl)
	status, respHeader, err := restClient.HttpJsonSend(method, requestUrl, token.AccessToken, reqData, replyData, headerVals)
	if err != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "Federation API failed", "method", method, "url", requestUrl, "error", err)
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("Failed to get response for %s request to URL %s, status=%s", method, requestUrl, http.StatusText(status))
	}
	return respHeader, nil
}
