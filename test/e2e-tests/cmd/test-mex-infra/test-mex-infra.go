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
	"encoding/json"
	"flag"
	"fmt"
	"os"

	log "github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/test/e2e-tests/pkg/e2e"
)

var (
	commandName    = "test-mex-infra"
	configStr      *string
	specStr        *string
	modsStr        *string
	stopOnFail     *bool
	sharedDataPath = "/tmp/e2e_test_out/shared_data.json"
)

//re-init the flags because otherwise we inherit a bunch of flags from the testing
//package which get inserted into the usage.
func init() {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	configStr = flag.String("testConfig", "", "json formatted TestConfig")
	specStr = flag.String("testSpec", "", "json formatted TestSpec")
	modsStr = flag.String("mods", "", "json formatted mods")
	stopOnFail = flag.Bool("stop", false, "stop on failures")
}

func main() {
	flag.Parse()
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())
	e2e.SetLogFormat()

	config := e2e.TestConfig{}
	spec := e2e.TestSpec{}
	mods := []string{}

	err := json.Unmarshal([]byte(*configStr), &config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: unmarshaling TestConfig: %v", err)
		os.Exit(1)
	}
	err = json.Unmarshal([]byte(*specStr), &spec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: unmarshaling TestSpec: %v", err)
		os.Exit(1)
	}
	err = json.Unmarshal([]byte(*modsStr), &mods)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: unmarshaling mods: %v", err)
		os.Exit(1)
	}
	if err := e2e.RunTestSpec(ctx, &config, &spec, mods, *stopOnFail); err != nil {
		fmt.Fprintf(os.Stderr, "%s", err)
		os.Exit(1)
	}
	os.Exit(0)
}
