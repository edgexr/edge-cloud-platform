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
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"

    "github.com/edgexr/edge-cloud-infra/operator-api-gw/operalpha/operalpha-loc/util"
)

var (
	port       = flag.Int("port", 8080, "listen port")
	fixedToken = flag.String("token", "", "fixed token")

	indexpath = "/"

	getTokenPath        = "/its"
	getExpiredTokenPath = "/itsexpired"
)

func printUsage() {
	fmt.Println("\nUsage: \token-server-sim [options]\n\noptions:")
	flag.PrintDefaults()
}

func showIndex(w http.ResponseWriter, r *http.Request) {
	log.Printf("doing showIndex for request: %v\n", r)
	rc := "/its -- Identity Token Server Get Token\n"
	w.Write([]byte(rc))
}

func getToken(w http.ResponseWriter, r *http.Request) {
	log.Println("doing getToken")

	f := r.URL.Query().Get("followURL")
	remoteAddr := r.RemoteAddr

	//requests using "localhost" may yield the IPv6 equivalent, force it to IPv4
	remoteAddr = strings.Replace(remoteAddr, "[::1]", "127.0.0.1", -1)
	remoteIp := strings.Split(remoteAddr, ":")[0]

	//the encoding of token for now is just a base64 version of the ip address plus some
	//expiry time.  We will decode this within the token server simulator and use the IP to derive
	//a location, or reject if the expiry time is passed
	tokenresult := ""

	// if a token is specified as an argument, we just use this value.  This is for integration with
	// OPERALPHA's location verification mockup
	if *fixedToken != "" {
		tokenresult = *fixedToken
	} else {
		if strings.Contains(r.URL.Path, getExpiredTokenPath) {
			log.Println("getting an expired token")
			//this is to test the case where we have an expired token. Ask for a token which expired 10 seconds ago.
			tokenresult = util.GenerateToken(remoteIp, -10)
		} else {
			tokenresult = util.GenerateToken(remoteIp, util.DefaultTokenValidSeconds)
		}
	}
	log.Printf("followurl: %s remoteIp: %s token: %s\n", f, remoteIp, tokenresult)

	http.Redirect(w, r, f+"?dt-id="+tokenresult, 303)
}

func run() {
	http.HandleFunc(indexpath, showIndex)
	http.HandleFunc(getTokenPath, getToken)
	http.HandleFunc(getExpiredTokenPath, getToken)

	portstr := fmt.Sprintf(":%d", *port)

	log.Printf("Listening on http://127.0.0.1:%d", *port)
	if err := http.ListenAndServe(portstr, nil); err != nil {
		panic(err)
	}
}

func validateArgs() {
	flag.Parse()
	//nothing to check yet
}

func main() {
	validateArgs()
	run()
}
