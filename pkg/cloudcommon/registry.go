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

package cloudcommon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
	"github.com/edgexr/edge-cloud-platform/pkg/vault"
)

const (
	NoAuth              = "noauth"
	BasicAuth           = "basic"
	TokenAuth           = "token"
	ApiKeyAuth          = "apikey"
	DockerHub           = "docker.io"
	DockerHubRegistry   = "registry-1.docker.io"
	MaxOvfVmVersion     = 14
	AllOrgs             = ""
	AuthRespToken       = "token"
	AuthRespAccessToken = "access_token"
)

type RegistryAuth struct {
	AuthType string
	Username string `json:"username"`
	Password string `json:"password"`
	Token    string `json:"token"`
	ApiKey   string `json:"apikey"`
	Hostname string `json:"hostname"`
	Port     string `json:"port"`
}

type RegistryTags struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

type RequestConfig struct {
	Timeout               time.Duration
	ResponseHeaderTimeout time.Duration
	Headers               map[string]string
}

type AuthTokenResp struct {
	Scope       string `json:"scope"`
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

type OauthTokenResp struct {
	TokenType   string `json:"token_type"`
	AccessToken string `json:"access_token"`
}

type RegistryAuthMgr struct {
	vaultConfig  *vault.Config
	validDomains []string
}

func NewRegistryAuthMgr(vaultConfig *vault.Config, validDomains string) *RegistryAuthMgr {
	return &RegistryAuthMgr{
		vaultConfig:  vaultConfig,
		validDomains: strings.Split(validDomains, ","),
	}
}

func getVaultAccountPath(name string) string {
	return fmt.Sprintf("/secret/data/accounts/%s", name)
}

func (s *RegistryAuthMgr) getVaultRegistryPath(registry, org string) string {
	for _, domain := range s.validDomains {
		// When supporting multiple domains, we don't want to have to
		// duplicate the same credentials for our internal docker/vm
		// registries under multiple domains. So we map those domains
		// to a common name.
		if registry == "docker."+domain {
			registry = InternalDockerRegistry
			break
		} else if registry == "console."+domain {
			registry = InternalVMRegistry
			break
		}
	}
	return s.getVaultRegistryPathUnfiltered(registry, org)
}

func (s *RegistryAuthMgr) getVaultRegistryPathUnfiltered(registry, org string) string {
	// NOTE: we do not store credentials for external registries
	// provided by the user. Images should always be copied into
	// internal registries at the time of App creation,
	// therefore any user-provided credentials are used only
	// once during App creation and are not needed afterwards.
	// Note: registry and org are extracted from image path URL
	// when seeding secrets, and are case-insensitive, so we
	// keep them lower case.
	registry = strings.ToLower(registry)
	org = strings.ToLower(org)
	if org == AllOrgs {
		// registry key granting access to all orgs
		// these are admin keys for internal use and should not
		// be exposed externally.
		return fmt.Sprintf("/secret/data/registry/%s", registry)
	} else {
		// keys for internally managed registries for
		// image pull access by org. These keys are passed
		// to the CRM and should have limited access as much
		// as possible.
		return fmt.Sprintf("/secret/data/registry/%s-orgs/%s", registry, org)
	}
}

type RegistryAuthApi interface {
	// Get registry auth for an image, based on registry URL
	GetRegistryAuth(ctx context.Context, imgUrl string) (*RegistryAuth, error)
	// Get registry auth for an app, based on app key or registry URL
	GetAppRegistryAuth(ctx context.Context, imgUrl string, appKey edgeproto.AppKey) (*RegistryAuth, error)
}

// return host and org (only valid for internal repositories)
func parseImageUrl(imgUrl string) (string, string, error) {
	urlObj, err := util.ImagePathParse(imgUrl)
	if err != nil {
		return "", "", err
	}
	hostname := strings.Split(urlObj.Host, ":")
	if len(hostname) < 1 {
		return "", "", fmt.Errorf("empty hostname")
	}
	path := urlObj.Path
	path = strings.TrimPrefix(path, VmRegPath) // remove vm-registry path before org if present
	path = strings.TrimPrefix(path, "/")
	pathParts := strings.Split(path, "/")
	if len(pathParts) < 2 {
		return "", "", fmt.Errorf("parseImageUrl expects a path with org/image, but was %s", path)
	}
	return hostname[0], pathParts[0], nil
}

// return hostname and port from hostOrURL string.
func ParseHost(hostOrURL string) (string, string, error) {
	if !strings.Contains(hostOrURL, "://") {
		// add scheme for url.Parse
		hostOrURL = "https://" + hostOrURL
	}
	u, err := url.Parse(hostOrURL)
	if err != nil {
		return "", "", err
	}
	hostport := strings.Split(u.Host, ":")
	hostname := hostport[0]
	port := ""
	if len(hostport) > 1 {
		port = hostport[1]
	}
	return hostname, port, nil
}

// Same as registry auth, but is always the user/password of an admin
// or other user account.
func GetAccountAuth(ctx context.Context, name string, vaultConfig *vault.Config) (*RegistryAuth, error) {
	if vaultConfig == nil || vaultConfig.Addr == "" {
		return nil, fmt.Errorf("no vault specified")
	}
	vaultPath := getVaultAccountPath(name)
	log.SpanLog(ctx, log.DebugLevelApi, "get account auth", "vault-path", vaultPath)
	auth := &RegistryAuth{}
	err := vault.GetData(vaultConfig, vaultPath, 0, auth)
	if err != nil && strings.Contains(err.Error(), "no secrets") {
		return nil, fmt.Errorf("no account credentials found for %s in Vault", name)
	} else if err != nil {
		return nil, fmt.Errorf("failed to get account credentials for %s: %s", name, err)
	}
	return auth, nil
}

// GetRegistryImageAuth gets the credentials for pulling the image.
func (s *RegistryAuthMgr) GetRegistryImageAuth(ctx context.Context, imgUrl string) (*RegistryAuth, error) {
	host, org, err := parseImageUrl(imgUrl)
	if err != nil {
		return nil, err
	}
	return s.GetRegistryOrgAuth(ctx, host, org)
}

func (s *RegistryAuthMgr) GetAppRegistryImageAuth(ctx context.Context, imgUrl string, region string, appKey edgeproto.AppKey) (*RegistryAuth, error) {
	host, org, err := parseImageUrl(imgUrl)
	if err != nil {
		return nil, err
	}
	return s.GetAppRegistryOrgAuth(ctx, host, org, region, appKey)
}

// GetAppRegistryOrgAuth gets the credentials for accessing the
// image registry for an app. If no creds are found for the app,
// fallback to look up by org with GetRegistryOrgAuth.
func (s *RegistryAuthMgr) GetAppRegistryOrgAuth(ctx context.Context, hostOrURL, org, region string, appKey edgeproto.AppKey) (*RegistryAuth, error) {
	// look up app-specific registry auth. If not found, fallback to org auth
	if s.vaultConfig == nil || s.vaultConfig.Addr == "" {
		return nil, fmt.Errorf("no vault specified")
	}
	appAuth, err := GetAppRegistryAuth(ctx, region, appKey, s.vaultConfig)
	if err == nil {
		hostname, port, err := ParseHost(hostOrURL)
		if err != nil {
			return nil, fmt.Errorf("failed to parse %q, %s", hostOrURL, err)
		}
		// We require that the hostname and port match between the
		// target URL and the stored credentials. This is because
		// these credentials may be used for manifests, which may
		// or may not be hosted in the same registry as the image.
		// We do not want to send the image's registry credentials
		// to a different registry.
		if appAuth.Hostname != hostname || appAuth.Port != port {
			log.SpanLog(ctx, log.DebugLevelApi, "app registry credentials hostname/port mismatch, ignoring", "target", hostOrURL, "creds-hostname", appAuth.Hostname, "creds-port", appAuth.Port)
		} else {
			return appAuth, nil
		}
	} else if !vault.IsErrNoSecretsAtPath(err) {
		return nil, err
	}
	// fallback to GetRegistryOrgAuth().
	return s.GetRegistryOrgAuth(ctx, hostOrURL, org)
}

// GetRegistryOrgAuth gets the credentials for accessing the
// image registry. If org is AllOrgs, then admin credentials
// are returned. Otherwise, credentials are scoped to the org.
func (s *RegistryAuthMgr) GetRegistryOrgAuth(ctx context.Context, hostOrURL, org string) (*RegistryAuth, error) {
	if s.vaultConfig == nil || s.vaultConfig.Addr == "" {
		return nil, fmt.Errorf("no vault specified")
	}
	hostname, port, err := ParseHost(hostOrURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %q, %s", hostOrURL, err)
	}
	vaultPath := s.getVaultRegistryPath(hostname, org)
	log.SpanLog(ctx, log.DebugLevelApi, "get registry auth", "hostname", hostname, "org", org, "vault-path", vaultPath)
	auth := &RegistryAuth{}
	err = vault.GetData(s.vaultConfig, vaultPath, 0, auth)
	if err != nil && strings.Contains(err.Error(), "no secrets") {
		// no secrets found, assume public registry
		log.SpanLog(ctx, log.DebugLevelApi, "warning, no registry credentials in vault, assume public registry", "err", err)
		auth.AuthType = NoAuth
		err = nil
	}
	if err != nil {
		return nil, err
	}
	auth.Hostname = hostname
	if auth.Port == "" {
		auth.Port = port
	}
	if auth.Username != "" && auth.Password != "" {
		auth.AuthType = BasicAuth
	} else if auth.Token != "" {
		auth.AuthType = TokenAuth
	} else if auth.ApiKey != "" {
		auth.AuthType = ApiKeyAuth
	}
	return auth, nil
}

func (s *RegistryAuthMgr) PutRegistryAuth(ctx context.Context, host, org string, auth *RegistryAuth, checkAndSet int) error {
	if s.vaultConfig == nil || s.vaultConfig.Addr == "" {
		return fmt.Errorf("no vault specified")
	}
	hostname, port, err := ParseHost(host)
	if err != nil {
		return err
	}
	auth.Hostname = hostname
	auth.Port = port
	vaultPath := s.getVaultRegistryPath(hostname, org)
	log.SpanLog(ctx, log.DebugLevelApi, "put auth secret", "vault-path", vaultPath)
	err = vault.PutDataCAS(s.vaultConfig, vaultPath, auth, checkAndSet)
	if err != nil {
		return err
	}
	return nil
}

func (s *RegistryAuthMgr) DeleteRegistryAuth(ctx context.Context, host, org string) error {
	if s.vaultConfig == nil || s.vaultConfig.Addr == "" {
		return fmt.Errorf("no vault specified")
	}
	hostname, _, err := ParseHost(host)
	if err != nil {
		return err
	}
	vaultPath := s.getVaultRegistryPath(hostname, org)
	log.SpanLog(ctx, log.DebugLevelApi, "delete auth secret", "vault-path", vaultPath)
	return vault.DeleteData(s.vaultConfig, vaultPath)
}

// UpgradeDockerRegistryAuth copies docker credentials from hostname-specific
// vault path to common internal vault path. This is an upgrade function and
// can be removed once all existing deployments have been upgraded.
func (s *RegistryAuthMgr) UpgradeRegistryAuth(ctx context.Context, internalRegistry, org string) error {
	log.SpanLog(ctx, log.DebugLevelApi, "upgrade registry auth", "internalRegistry", internalRegistry, "org", org)
	if s.vaultConfig == nil || s.vaultConfig.Addr == "" {
		return fmt.Errorf("no vault specified")
	}
	prefix := "docker."
	if internalRegistry == InternalVMRegistry {
		prefix = "console."
	}
	auth := &RegistryAuth{}
	commonVaultPath := s.getVaultRegistryPathUnfiltered(internalRegistry, org)
	err := vault.GetData(s.vaultConfig, commonVaultPath, 0, auth)
	if err == nil {
		// no upgrade needed
		return nil
	}
	if err != nil && !strings.Contains(err.Error(), "no secrets") {
		log.SpanLog(ctx, log.DebugLevelApi, "upgrade registry auth read failed", "vaultPath", commonVaultPath, "err", err)
		return err
	}
	// no secrets at common path
	for _, domain := range s.validDomains {
		hostname := prefix + domain
		vaultPath := s.getVaultRegistryPathUnfiltered(hostname, org)
		err := vault.GetData(s.vaultConfig, vaultPath, 0, auth)
		if err != nil && strings.Contains(err.Error(), "no secrets") {
			continue
		}
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "upgrade registry auth read failed", "vaultPath", vaultPath, "err", err)
			return err
		}
		log.SpanLog(ctx, log.DebugLevelApi, "upgrade registry auth", "from-vaultPath", vaultPath, "to-vaultPath", commonVaultPath)
		checkAndSet := 0
		err = vault.PutDataCAS(s.vaultConfig, commonVaultPath, auth, checkAndSet)
		if err != nil && strings.Contains(err.Error(), "check-and-set parameter did not match") {
			log.SpanLog(ctx, log.DebugLevelApi, "upgrade registry write failed via check-and-set, ignoring", "err", err)
			// another MC wrote before us
			return nil
		}
		if err != nil {
			return err
		}
		break
	}
	return nil
}

func GetRegistryAuthToken(ctx context.Context, host string, authApi RegistryAuthApi) (string, error) {
	log.SpanLog(ctx, log.DebugLevelApi, "GetRegistryAuthToken", "host", host)
	if authApi == nil {
		return "", fmt.Errorf("missing registry credentials")
	}
	auth, err := authApi.GetRegistryAuth(ctx, host)
	if err != nil {
		return "", err
	}
	if auth.AuthType != BasicAuth {
		return "", fmt.Errorf("expected Basic Auth credentials for GetRegistryAuthToken, but was %s", auth.AuthType)
	}

	scheme := "https"
	if os.Getenv("E2ETEST_TLS") != "" {
		scheme = "http"
	}
	url := fmt.Sprintf("%s://%s/oauth2/token", scheme, host)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return "", err
	}
	q := req.URL.Query()
	q.Add("grant_type", "client_credentials")
	req.URL.RawQuery = q.Encode()
	req.SetBasicAuth(auth.Username, auth.Password)

	client := http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return "", fmt.Errorf("error reading token response: %v", err)
	}
	tokenResp := &OauthTokenResp{}
	err = json.Unmarshal(body, &tokenResp)
	if err != nil {
		return "", fmt.Errorf("Fail to unmarshal response - %v", err)
	}
	return tokenResp.AccessToken, nil
}

func GetAuthToken(ctx context.Context, host string, authApi RegistryAuthApi, userName string) (string, error) {
	log.SpanLog(ctx, log.DebugLevelApi, "GetAuthToken", "host", host, "userName", userName)

	url := fmt.Sprintf("https://%s/artifactory/api/security/token", host)
	reqConfig := RequestConfig{}
	reqConfig.Headers = make(map[string]string)
	reqConfig.Headers["Content-Type"] = "application/x-www-form-urlencoded"

	resp, err := SendHTTPReq(ctx, "POST", url, nil, authApi, NoCreds, &reqConfig, strings.NewReader("username="+userName+"&scope=member-of-groups:readers"))
	if err != nil {
		return "", err
	}
	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()
	if err != nil {
		return "", fmt.Errorf("error reading gettoken response: %v", err)
	}
	var tokResp AuthTokenResp
	err = json.Unmarshal(body, &tokResp)
	if err != nil {
		return "", fmt.Errorf("Fail to unmarshal response - %v", err)
	}
	return tokResp.AccessToken, nil
}

func GetQueryArgsFromObj(obj interface{}) (string, error) {
	out, err := json.Marshal(&obj)
	if err != nil {
		return "", fmt.Errorf("Failed to get query args from obj %v, marshal error: %v", obj, err)
	}
	kv := make(map[string]string)
	err = json.Unmarshal(out, &kv)
	if err != nil {
		return "", fmt.Errorf("Failed to get query args from obj %v, unmarshal error: %v", string(out), err)
	}
	val := url.Values{}
	for k, v := range kv {
		val.Set(k, v)
	}
	return val.Encode(), nil
}

func SendHTTPReqAuth(ctx context.Context, method, regUrl string, auth *RegistryAuth, reqConfig *RequestConfig, body io.Reader) (*http.Response, error) {
	log.SpanLog(ctx, log.DebugLevelApi, "send http request", "method", method, "url", regUrl, "reqConfig", reqConfig)

	respHeaderTimeout := 5 * time.Second
	if reqConfig != nil && reqConfig.ResponseHeaderTimeout != 0 {
		respHeaderTimeout = reqConfig.ResponseHeaderTimeout
	}
	dialTimeout := 10 * time.Second
	if os.Getenv("E2ETEST_SKIPREGISTRY") != "" {
		dialTimeout = 10 * time.Millisecond
	}
	client := &http.Client{
		Transport: &http.Transport{
			// Connection Timeout
			DialContext: (&net.Dialer{
				Timeout:   dialTimeout,
				KeepAlive: 10 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout: dialTimeout,

			// Response Header Timeout
			ExpectContinueTimeout: 5 * time.Second,
			ResponseHeaderTimeout: respHeaderTimeout,
			// use proxy if env vars set
			Proxy: http.ProxyFromEnvironment,
		},
		// Prevent endless redirects
		Timeout: 10 * time.Minute,
	}
	if reqConfig != nil && reqConfig.Timeout > 10*time.Minute {
		client.Timeout = reqConfig.Timeout
	}
	req, err := http.NewRequest(method, regUrl, body)
	if err != nil {
		return nil, fmt.Errorf("failed sending request %v", err)
	}
	if reqConfig != nil {
		for k, v := range reqConfig.Headers {
			req.Header.Add(k, v)
		}
	}
	if auth != nil {
		switch auth.AuthType {
		case BasicAuth:
			req.SetBasicAuth(auth.Username, auth.Password)
		case TokenAuth:
			req.Header.Set("Authorization", "Bearer "+auth.Token)
		case ApiKeyAuth:
			req.Header.Set("X-JFrog-Art-Api", auth.ApiKey)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func handleWWWAuth(ctx context.Context, method, regUrl, authHeader string, auth *RegistryAuth, body io.Reader) (*http.Response, error) {
	log.SpanLog(ctx,
		log.DebugLevelApi, "handling www-auth for Docker Registry v2 Authentication",
		"regUrl", regUrl,
		"authHeader", authHeader,
	)
	authURL := ""
	if strings.HasPrefix(authHeader, "Bearer") {
		parts := strings.Split(strings.TrimPrefix(authHeader, "Bearer "), ",")

		m := map[string]string{}
		for _, part := range parts {
			if splits := strings.Split(part, "="); len(splits) == 2 {
				m[splits[0]] = strings.Replace(splits[1], "\"", "", 2)
			}
		}
		if _, ok := m["realm"]; !ok {
			return nil, fmt.Errorf("unable to find realm")
		}

		authURL = m["realm"]
		if v, ok := m["service"]; ok {
			authURL += "?service=" + v
		}
		if v, ok := m["scope"]; ok {
			authURL += "&scope=" + v
		}
		resp, err := SendHTTPReqAuth(ctx, "GET", authURL, auth, nil, body)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			authTok := RegistryAuth{}
			authResp := map[string]string{}
			decErr := json.NewDecoder(resp.Body).Decode(&authResp)
			if authResp[AuthRespToken] != "" {
				authTok.Token = authResp[AuthRespToken]
			} else if authResp[AuthRespAccessToken] != "" {
				// Azure returns "access_token" instead of "token"
				authTok.Token = authResp[AuthRespAccessToken]
			} else {
				log.SpanLog(ctx, log.DebugLevelApi, "no token found in www-auth request", "resp", authResp, "decodeErr", decErr)
				return nil, fmt.Errorf("no token found in auth response for URL %s", authURL)
			}
			authTok.AuthType = TokenAuth

			log.SpanLog(ctx, log.DebugLevelApi, "retrying request with auth-token")
			resp, err = SendHTTPReqAuth(ctx, method, regUrl, &authTok, nil, body)
			if err != nil {
				return nil, err
			}
			if resp.StatusCode != http.StatusOK {
				if resp != nil {
					resp.Body.Close()
				}
				return nil, errors.New(http.StatusText(resp.StatusCode))
			}
			return resp, nil
		}
		if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
			if auth == nil {
				return nil, fmt.Errorf("Unable to find hostname in Vault")
			}
		}
		return nil, errors.New(http.StatusText(resp.StatusCode))
	}
	return nil, fmt.Errorf("unable to find bearer token")
}

/*
 * Sends HTTP request to regUrl
 * Checks if any Auth Credentials is needed by doing a lookup to Vault path
 *  - If it finds auth details, then HTTP request is sent with auth details set in HTTP Header
 *  - else, we assume it to be a public registry which requires no authentication
 * Following is the flow for Docker Registry v2 authentication:
 * - Send HTTP request to regUrl with auth (if found in Vault) or else without auth
 * - If the registry requires authorization, it will return a 401 Unauthorized response with a
 *   WWW-Authenticate header detailing how to authenticate to this registry
 * - We then make a request to the authorization service for a Bearer token
 * - The authorization service returns an opaque Bearer token representing the client’s authorized access
 * - Retry the original request with the Bearer token embedded in the request’s Authorization header
 * - The Registry authorizes the client by validating the Bearer token and the claim set embedded within
 *   it and begins the session as usual
 */
func SendHTTPReq(ctx context.Context, method, regUrl string, appKey *edgeproto.AppKey, authApi RegistryAuthApi, urlCreds string, reqConfig *RequestConfig, body io.Reader) (*http.Response, error) {
	var auth *RegistryAuth
	var err error

	// if authApi is nil, this is a public registry
	if authApi != nil {
		if appKey != nil {
			auth, err = authApi.GetAppRegistryAuth(ctx, regUrl, *appKey)
		} else {
			auth, err = authApi.GetRegistryAuth(ctx, regUrl)
		}
		if err != nil {
			return nil, err
		}
	} else {
		auth = nil
		log.SpanLog(ctx, log.DebugLevelApi, "warning, cannot get registry credentials from vault - assume public registry", "err", err)
	}
	if urlCreds != "" {
		out := strings.Split(urlCreds, ":")
		if len(out) != 2 {
			return nil, fmt.Errorf("Invalid URL credentials %s, valid format is 'username:password'", urlCreds)
		}
		log.SpanLog(ctx, log.DebugLevelApi, "using user defined registry credentials")
		auth.AuthType = BasicAuth
		auth.Username = out[0]
		auth.Password = out[1]
	}
	resp, err := SendHTTPReqAuth(ctx, method, regUrl, auth, reqConfig, body)
	if err != nil {
		return nil, err
	}
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		// Following is valid only for Docker Registry v2 Authentication
		// close response body as we will retry with authtoken
		resp.Body.Close()
		authHeader := resp.Header.Get("Www-Authenticate")
		if authHeader != "" {
			// fetch authorization token to access tags
			resp, err = handleWWWAuth(ctx, method, regUrl, authHeader, auth, body)
			if err == nil {
				return resp, nil
			}
			log.SpanLog(ctx, log.DebugLevelApi, "unable to handle www-auth", "err", err)
			if err.Error() == http.StatusText(http.StatusNotFound) {
				return nil, fmt.Errorf("Image at %s not found, please confirm it has been uploaded to the registry", regUrl)
			}
		}
		return nil, fmt.Errorf("Access denied to registry path")
	case http.StatusForbidden:
		resp.Body.Close()
		return nil, fmt.Errorf("Invalid credentials to access URL: %s", regUrl)
	case http.StatusCreated:
		fallthrough
	case http.StatusOK:
		return resp, nil
	default:
		resp.Body.Close()
		return nil, fmt.Errorf("Invalid URL: %s, %s", regUrl, http.StatusText(resp.StatusCode))
	}
}

// ValidateDockerRegistryPath checks that we have permission to
// access the registry path specified by regUrl.
// The appKey is optional, and should be specified if the
// credentials for regUrl are stored under the appKey instead of
// the registry domain.
func ValidateDockerRegistryPath(ctx context.Context, regUrl string, appKey *edgeproto.AppKey, authApi RegistryAuthApi) error {
	log.SpanLog(ctx, log.DebugLevelApi, "validate registry path", "path", regUrl)

	if regUrl == "" {
		return fmt.Errorf("registry path is empty")
	}

	version := "v2"
	matchTag := "latest"
	regPath := ""

	urlObj, err := util.ImagePathParse(regUrl)
	if err != nil {
		return err
	}
	out := strings.Split(urlObj.Path, ":")
	if len(out) == 1 {
		regPath = urlObj.Path
	} else if len(out) == 2 {
		regPath = out[0]
		matchTag = out[1]
	} else {
		return fmt.Errorf("Invalid tag in registry path")
	}
	if urlObj.Host == DockerHub {
		// Even though public images are typically pulled from docker.io, the API v2 calls must be made to registry-1.docker.io
		urlObj.Host = DockerHubRegistry
		log.SpanLog(ctx, log.DebugLevelApi, "substituting docker hub registry for docker hub", "host", urlObj.Host)
	}
	regUrl = fmt.Sprintf("%s://%s/%s%s/tags/list", urlObj.Scheme, urlObj.Host, version, regPath)
	log.SpanLog(ctx, log.DebugLevelApi, "registry api url", "url", regUrl)

	resp, err := SendHTTPReq(ctx, "GET", regUrl, appKey, authApi, NoCreds, nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		tagsList := RegistryTags{}
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("Failed to read response body, %v", err)
		}
		log.SpanLog(ctx, log.DebugLevelApi, "list tags", "resp", string(body))
		err = json.Unmarshal(body, &tagsList)
		if err != nil {
			return err
		}
		for _, tag := range tagsList.Tags {
			if tag == matchTag {
				return nil
			}
		}
		return fmt.Errorf("Invalid registry tag: %s does not exist", matchTag)
	}
	return fmt.Errorf("Invalid registry path: %s", http.StatusText(resp.StatusCode))
}

func ValidateVMRegistryPath(ctx context.Context, imgUrl string, appKey *edgeproto.AppKey, authApi RegistryAuthApi) error {
	log.SpanLog(ctx, log.DebugLevelApi, "validate vm-image path", "path", imgUrl)
	if imgUrl == "" {
		return fmt.Errorf("image path is empty")
	}

	resp, err := SendHTTPReq(ctx, "GET", imgUrl, appKey, authApi, NoCreds, nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return nil
	}
	return fmt.Errorf("Invalid image path: %s", http.StatusText(resp.StatusCode))
}

func ValidateOvfRegistryPath(ctx context.Context, imgUrl string, appKey *edgeproto.AppKey, authApi RegistryAuthApi) error {
	log.SpanLog(ctx, log.DebugLevelApi, "validate ovf path", "path", imgUrl)
	if imgUrl == "" {
		return fmt.Errorf("image path is empty")
	}
	parsedUrl, err := url.Parse(imgUrl)
	if err != nil {
		return fmt.Errorf("cannot parse url %s - %v", imgUrl, err)
	}
	urlMinusFile := strings.Replace(imgUrl, path.Base(parsedUrl.Path), "", 1)
	resp, err := SendHTTPReq(ctx, "GET", imgUrl, appKey, authApi, NoCreds, nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Error getting OVF - code %d", resp.StatusCode)
	}

	// get the OVF and find other files referenced in it
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("Unable to read ovf body - %v", err)
	}
	vmVersionPattern := "VirtualSystemType>vmx-(\\d+)</vssd:VirtualSystemType>"
	vreg := regexp.MustCompile(vmVersionPattern)
	versMatch := vreg.FindAllStringSubmatch(string(bodyBytes), -1)
	for _, s := range versMatch {
		if len(s) == 2 {
			version := s[1]
			log.SpanLog(ctx, log.DebugLevelApi, "Found VM Version in OVF", "version", version)
			versionInt, err := strconv.Atoi(version)
			if err != nil {
				return fmt.Errorf("Unable to parse VM Version in OVF: %s, %v", version, err)
			}
			if versionInt > MaxOvfVmVersion {
				return fmt.Errorf("Invalid VM version in OVF: %d, max value: %d", versionInt, MaxOvfVmVersion)
			}
		}
	}
	filePattern := "File ovf:href=\"(\\S+)\""
	freg := regexp.MustCompile(filePattern)

	fileMatch := freg.FindAllStringSubmatch(string(bodyBytes), -1)
	filesToCheck := []string{}
	for _, s := range fileMatch {
		if len(s) == 2 {
			file := s[1]
			fileToCheck := urlMinusFile + file
			log.SpanLog(ctx, log.DebugLevelApi, "Found file referenced in OVF", "file", file, "fileToCheck", fileToCheck)
			filesToCheck = append(filesToCheck, fileToCheck)

		}
	}
	// check that all referenced files are available
	for _, f := range filesToCheck {
		fresp, err := SendHTTPReq(ctx, "HEAD", f, appKey, authApi, NoCreds, nil, nil)
		if err != nil {
			return fmt.Errorf("unable to get referenced file: %s - %v", f, err)
		}
		defer fresp.Body.Close()
		if fresp.StatusCode != http.StatusOK {
			return fmt.Errorf("Error getting OVF - code %d", resp.StatusCode)
		}
	}
	return nil
}

// GetSecretAuth returns secretName, dockerServer, auth, error
func GetSecretAuth(ctx context.Context, imagePath string, appKey edgeproto.AppKey, authApi RegistryAuthApi, existingCreds *RegistryAuth) (string, string, *RegistryAuth, error) {
	var err error
	var auth *RegistryAuth
	if existingCreds == nil {
		auth, err = authApi.GetAppRegistryAuth(ctx, imagePath, appKey)
		if err != nil {
			return "", "", nil, err
		}
	} else {
		auth = existingCreds
		if auth.Username == "" || auth.Password == "" {
			// no creds found, assume public registry
			log.SpanLog(ctx, log.DebugLevelApi, "warning, no credentials found, assume public registry")
			auth.AuthType = NoAuth
		}
	}
	if auth == nil || auth.AuthType == NoAuth {
		log.SpanLog(ctx, log.DebugLevelInfra, "warning, cannot get docker registry secret from vault - assume public registry")
		return "", "", nil, nil
	}
	if auth.AuthType != BasicAuth {
		// This can be ignored as it'll only happen for internally
		// used non-docker registry hostnames like artifactory.edgecloud.net
		log.SpanLog(ctx, log.DebugLevelInfra, "warning, auth type is not basic auth type - assume internal registry", "hostname", auth.Hostname, "authType", auth.AuthType)
		return "", "", nil, nil
	}
	// Note: docker-server must contain port if imagepath contains port,
	// otherwise imagepullsecrets won't work.
	// Also secret name includes port in case multiple docker registries
	// are running on different ports on the same host.
	secretName := auth.Hostname
	dockerServer := auth.Hostname
	if auth.Port != "" {
		secretName = auth.Hostname + "-" + auth.Port
		dockerServer = auth.Hostname + ":" + auth.Port
	}
	return secretName, dockerServer, auth, nil
}

type VaultRegistryAuthApi struct {
	region     string
	RegAuthMgr *RegistryAuthMgr
}

func NewVaultRegistryAuthApi(region string, regAuthMgr *RegistryAuthMgr) *VaultRegistryAuthApi {
	return &VaultRegistryAuthApi{
		region:     region,
		RegAuthMgr: regAuthMgr,
	}
}

func (s *VaultRegistryAuthApi) GetRegistryAuth(ctx context.Context, imgUrl string) (*RegistryAuth, error) {
	return s.RegAuthMgr.GetRegistryOrgAuth(ctx, imgUrl, AllOrgs)
}

func (s *VaultRegistryAuthApi) GetAppRegistryAuth(ctx context.Context, imgUrl string, appKey edgeproto.AppKey) (*RegistryAuth, error) {
	return s.RegAuthMgr.GetAppRegistryOrgAuth(ctx, imgUrl, AllOrgs, s.region, appKey)
}

// For unit tests
type DummyRegistryAuthApi struct {
	DummyAuth RegistryAuth
}

func (s *DummyRegistryAuthApi) GetRegistryAuth(ctx context.Context, imgUrl string) (*RegistryAuth, error) {
	return &s.DummyAuth, nil
}

func (s *DummyRegistryAuthApi) GetAppRegistryAuth(ctx context.Context, imgUrl string, appKey edgeproto.AppKey) (*RegistryAuth, error) {
	return &s.DummyAuth, nil
}
