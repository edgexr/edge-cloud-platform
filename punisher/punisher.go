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
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/edgexr/edge-cloud-infra/mc/mcctl/mccli"
	"github.com/edgexr/edge-cloud-infra/mc/mcctl/mctestclient"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud-infra/mc/ormclient"
)

var numThreads = flag.Int("numthreads", 2, "number of threads")
var numTries = flag.Int("numtries", 20, "number of tries")
var addr = flag.String("addr", "https://127.0.0.1:9900", "MC address")
var skipVerify = flag.Bool("skipverify", false, "skip TLS cert verification")
var token = flag.String("token", "", "JWT Token, default uses mcctl token")
var region = flag.String("region", "local", "region Controller to target")

func main() {
	flag.Parse()
	if *token == "" {
		*token = os.Getenv("TOKEN")
	}
	if *token == "" {
		tok, err := ioutil.ReadFile(mccli.GetTokenFile())
		if err != nil {
			log.Fatal(err)
		}
		*token = strings.TrimSpace(string(tok))
	}
	if *token == "" {
		log.Fatal("please login via mcctl, or specify --token, or set TOKEN env var")
	}
	log.Printf("Punishing MC with %d threads of %d tries each...\n", *numThreads, *numTries)
	wg := sync.WaitGroup{}
	for tid := 0; tid < *numThreads; tid++ {
		wg.Add(1)
		go run(tid, &wg)
	}
	wg.Wait()
}

func run(threadID int, wg *sync.WaitGroup) {
	restClient := ormclient.Client{}
	restClient.SkipVerify = *skipVerify
	client := mctestclient.NewClient(&restClient)

	start := time.Now()
	filter := &ormapi.RegionFlavor{}
	filter.Region = *region
	ii := 0
	for ii = 0; ii < *numTries; ii++ {
		_, status, err := client.ShowFlavor(*addr+"/api/v1", *token, filter)
		if err != nil || status != http.StatusOK {
			log.Printf("thread %d try %d failed: status %d, %s\n", threadID, ii, status, err)
			if strings.Contains(err.Error(), "Invalid or expired jwt") {
				sv := ""
				if *skipVerify {
					sv = " --skipverify"
				}
				log.Printf("please use: mcctl --addr=%s%s login username=<x>", *addr, sv)
			}
			break
		}

	}
	log.Printf("thread %d finished %d tries after %s\n", threadID, ii, time.Since(start).String())
	wg.Done()
}
