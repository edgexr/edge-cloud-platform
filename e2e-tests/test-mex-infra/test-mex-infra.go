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
	"io/ioutil"
	"os"
	"strings"

	e2esetup "github.com/edgexr/edge-cloud-infra/e2e-tests/e2e-setup"
	log "github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/setup-env/e2e-tests/e2eapi"
	setupmex "github.com/edgexr/edge-cloud/setup-env/setup-mex"
	"github.com/edgexr/edge-cloud/setup-env/util"
)

var (
	commandName    = "test-mex-infra"
	configStr      *string
	specStr        *string
	modsStr        *string
	outputDir      string
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
	util.SetLogFormat()

	config := e2eapi.TestConfig{}
	spec := e2esetup.TestSpec{}
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

	errors := []string{}
	outputDir = config.Vars["outputdir"]
	if outputDir != "" {
		outputDir = util.CreateOutputDir(false, outputDir, commandName+".log")
	}

	if config.SetupFile != "" {
		if !setupmex.ReadSetupFile(config.SetupFile, &e2esetup.Deployment, config.Vars) {
			os.Exit(1)
		}
		util.Deployment = e2esetup.Deployment.DeploymentData
		util.DeploymentReplacementVars = config.Vars
	}

	retry := setupmex.NewRetry(spec.RetryCount, spec.RetryIntervalSec, len(spec.Actions))
	ranTest := false

	// Load from file
	sharedData := make(map[string]string)
	plan, err := ioutil.ReadFile(sharedDataPath)
	if err != nil {
		// ignore
		fmt.Printf("error reading shared data file, err: %v\n", err)
	} else {
		err = json.Unmarshal(plan, &sharedData)
		if err != nil {
			// ignore
			fmt.Printf("failed to marshal shared data, err: %v\n", err)
		}
	}

	for {
		tryErrs := []string{}
		for ii, a := range spec.Actions {
			if !retry.ShouldRunAction(ii) {
				continue
			}
			util.PrintStepBanner("name: " + spec.Name)
			util.PrintStepBanner("running action: " + a + retry.Tries())
			actionretry := false
			errs := e2esetup.RunAction(ctx, a, outputDir, &config, &spec, *specStr, mods, config.Vars, sharedData, &actionretry)
			ranTest = true
			if len(errs) > 0 {
				if actionretry {
					// potential errors that may be ignored after retry
					tryErrs = append(tryErrs, errs...)
				} else {
					// no retry for action, so register errs as final errors
					errors = append(errors, errs...)
					if *stopOnFail {
						break
					}
				}
			}
			retry.SetActionRetry(ii, actionretry)
		}
		if *stopOnFail && len(errors) > 0 {
			// stopOnFail case
			break
		}
		if spec.CompareYaml.Yaml1 != "" && spec.CompareYaml.Yaml2 != "" {
			pass := e2esetup.CompareYamlFiles(spec.Name, spec.Actions, &spec.CompareYaml)
			if !pass {
				tryErrs = append(tryErrs, "compare yaml failed")
			}
			ranTest = true
		}
		if len(tryErrs) == 0 || retry.Done() {
			errors = append(errors, tryErrs...)
			break
		}
		fmt.Printf("encountered failures, will retry:\n")
		for _, e := range tryErrs {
			fmt.Printf("- %s\n", e)
		}
		fmt.Printf("")
	}
	if !ranTest {
		errors = append(errors, "no test content")
	}

	if len(sharedData) > 0 {
		dataStr, err := json.Marshal(sharedData)
		if err != nil {
			// ignore
			fmt.Printf("error in json marshal of shared data, err: %v\n", err)
		} else {
			err = ioutil.WriteFile(sharedDataPath, []byte(dataStr), 0644)
			if err != nil {
				// ignore
				fmt.Printf("error writing shared data file, err: %v\n", err)
			}
		}
	}

	fmt.Printf("\nNum Errors found: %d, Results in: %s\n", len(errors), outputDir)
	if len(errors) > 0 {
		errstring := strings.Join(errors, ",")
		fmt.Fprint(os.Stderr, errstring)
		os.Exit(len(errors))
	}
	os.Exit(0)
}
