package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	e2esetup "github.com/mobiledgex/edge-cloud-infra/e2e-tests/e2e-setup"
	"github.com/mobiledgex/edge-cloud/setup-env/e2e-tests/e2eapi"
	setupmex "github.com/mobiledgex/edge-cloud/setup-env/setup-mex"
	"github.com/mobiledgex/edge-cloud/setup-env/util"
)

var (
	commandName = "test-mex-infra"
	configStr   *string
	specStr     *string
	outputDir   string
)

//re-init the flags because otherwise we inherit a bunch of flags from the testing
//package which get inserted into the usage.
func init() {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	configStr = flag.String("testConfig", "", "json formatted TestConfig")
	specStr = flag.String("testSpec", "", "json formatted TestSpec")
}

func main() {
	flag.Parse()

	config := e2eapi.TestConfig{}
	spec := e2esetup.TestSpec{}

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

	for _, a := range spec.Actions {
		util.PrintStepBanner("running action: " + a)
		errs := e2esetup.RunAction(a, outputDir, &config, &spec, *specStr)
		errors = append(errors, errs...)
	}
	if spec.CompareYaml.Yaml1 != "" && spec.CompareYaml.Yaml2 != "" {
		if !util.CompareYamlFiles(spec.CompareYaml.Yaml1,
			spec.CompareYaml.Yaml2, spec.CompareYaml.FileType) {
			errors = append(errors, "compare yaml failed")
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
