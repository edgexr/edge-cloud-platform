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

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"

	"github.com/edgexr/edge-cloud-infra/crm-platforms/vcd"
)

var currTokenNum uint32 = 1

var (
	port      = flag.Int("port", 8443, "listen port")
	expiresin = flag.Int("expiresin", 28800, "expires in seconds")
	certdir   = flag.String("certdir", "", "cert directory")
	certname  = flag.String("certname", "mex-server", "cert name")
	caname    = flag.String("caname", "mex-ca", "CA cert name")
	vaultaddr = flag.String("vaultaddr", "", "vault addr for vcd creds, e.g. https://vault-dev.mobiledgex.net")
	region    = flag.String("region", "", "region (US or EU)")
	physname  = flag.String("physname", "", "cloudlet physical name")
	org       = flag.String("org", "", "cloudlet org")
	errorcode = flag.Int("errorcode", 0, "error code")

	getTokenPath = flag.String("gettokenpath", "/openid/connect/auth/oauth/v2/t3/org/token", "path to gettoken")
	indexpath    = "/"
	vcdVars      map[string]string
	vcdPlatform  = vcd.VcdPlatform{} // used for creds
	vcdUri       *url.URL
)

type TokenErrorResponse struct {
	Error     string `json:"error"`
	ErrorDesc string `json:"error_description"`
}

func showIndex(w http.ResponseWriter, r *http.Request) {
	log.Printf("doing showIndex for request: %v\n", r)
	rc := *getTokenPath + " -- token auth\n"
	w.Write([]byte(rc))
}

func printUsage() {
	fmt.Println("\nUsage: \nvcd-sgw-sim [options]\n\noptions:")
	flag.PrintDefaults()
}

func validateRequest(r *http.Request) int {

	log.Printf("validateRequest")

	contentType := r.Header.Get("Content-Type")
	if contentType != vcd.ContentFormUrlEncoded {
		log.Printf("Bad Content-Type: " + contentType)
		return http.StatusBadRequest
	}

	err := r.ParseForm()
	if err != nil {
		log.Printf("Bad form data %v", r.Form)
		return http.StatusBadRequest
	}

	log.Printf("=====> Received oauth form: %v\n", r.Form)

	clientId := r.Form.Get(vcd.ClientId)
	clientSecret := r.Form.Get(vcd.ClientSecret)
	grantType := r.Form.Get(vcd.GrantType)
	scope := r.Form.Get(vcd.Scope)

	if grantType != vcd.GrantTypeCert {
		log.Printf("Bad grant type: %s", grantType)
		return http.StatusBadRequest
	}
	if scope != vcd.ScopeOpenId {
		log.Printf("Bad scope: %s", scope)
		return http.StatusBadRequest
	}
	if clientId != vcdPlatform.GetVcdOauthClientId() {
		log.Printf("wrong client id: %s", clientId)
		return http.StatusUnauthorized
	}
	if clientSecret != vcdPlatform.GetVcdOauthClientSecret() {
		log.Printf("wrong client secret: %s", clientSecret)
		return http.StatusUnauthorized
	}
	if *errorcode != 0 {
		log.Printf("returning error code: %d", *errorcode)
		return *errorcode
	}
	return http.StatusOK
}

func getToken(w http.ResponseWriter, r *http.Request) {
	log.Println("doing getToken")
	code := validateRequest(r)
	if code != http.StatusOK {
		errResponse := TokenErrorResponse{
			Error:     "Client Authentication Error",
			ErrorDesc: "Client authentication failed!",
		}
		byt, _ := json.Marshal(errResponse)
		log.Printf("request validation failed - code: %d", code)
		w.WriteHeader(code)
		w.Write(byt)
		return
	}
	tokenResponse := vcd.TokenResponse{
		AccessToken: fmt.Sprintf("simulatoraccesstoken-%d", currTokenNum),
		TokenType:   "Bearer",
		ExpiresIn:   *expiresin,
		Scope:       "openid account.read customer.read customer.accounts.read",
		IdToken:     "aaaaaaaa.bbbbbbbb.cccccccc",
	}
	currTokenNum++
	byt, _ := json.Marshal(tokenResponse)
	log.Printf("<===== Sent response: %v\n", tokenResponse)
	w.Write(byt)
}

func run() {
	http.HandleFunc(indexpath, showIndex)
	http.HandleFunc(*getTokenPath, getToken)

	if *certdir == "" {
		panic("--certdir is empty")
	}
	if *caname == "" {
		panic("--caname is empty")
	}
	if *physname == "" {
		panic("--physname is empty")
	}
	if *org == "" {
		panic("--org is empty")
	}
	if *region == "" {
		panic("--region is empty")
	}
	if *vaultaddr == "" {
		panic("--vaultaddr is empty")
	}
	err := vcdPlatform.PopulateCredsForSimulator(context.TODO(), *region, *org, *physname, *vaultaddr)
	if err != nil {
		panic(err.Error())
	}

	vcdUri, err = url.ParseRequestURI(vcdPlatform.Creds.VcdApiUrl)
	if err != nil {
		panic(fmt.Errorf("Unable to parse vcd uri %s err: %s", vcdPlatform.Creds.VcdApiUrl, err))
	}
	certfile := fmt.Sprintf("%s/%s.crt", *certdir, *certname)
	keyfile := fmt.Sprintf("%s/%s.key", *certdir, *certname)
	cafile := fmt.Sprintf("%s/%s.crt", *certdir, *caname)
	// Create a CA certificate pool and add cert.pem to it
	caCert, err := ioutil.ReadFile(cafile)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", *port),
		TLSConfig: tlsConfig,
	}

	log.Printf("listening on port %d\n", *port)
	err = server.ListenAndServeTLS(certfile, keyfile)
	if err != nil {
		panic(fmt.Sprintf("Error in ListenAndServeTLS: %v", err))
	}
}

func validateArgs() {
	flag.Parse()
}

func main() {
	validateArgs()
	run()
}
