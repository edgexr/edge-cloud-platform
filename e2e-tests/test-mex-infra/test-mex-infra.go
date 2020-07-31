package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	e2esetup "github.com/mobiledgex/edge-cloud-infra/e2e-tests/e2e-setup"
	log "github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/setup-env/e2e-tests/e2eapi"
	setupmex "github.com/mobiledgex/edge-cloud/setup-env/setup-mex"
	"github.com/mobiledgex/edge-cloud/setup-env/util"
)

var (
	commandName = "test-mex-infra"
	configStr   *string
	specStr     *string
	modsStr     *string
	outputDir   string
)

//re-init the flags because otherwise we inherit a bunch of flags from the testing
//package which get inserted into the usage.
func init() {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	configStr = flag.String("testConfig", "", "json formatted TestConfig")
	specStr = flag.String("testSpec", "", "json formatted TestSpec")
	modsStr = flag.String("mods", "", "json formatted mods")
}

func main() {
	flag.Parse()
	log.InitTracer("")
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

	retry := setupmex.NewRetry(spec.RetryCount, spec.RetryIntervalSec)
	ranTest := false
	for {
		tryErrs := []string{}
		for ii, a := range spec.Actions {
			util.PrintStepBanner("running action: " + a + retry.Tries())
			actionretry := false
			tryErrs = e2esetup.RunAction(ctx, a, outputDir, &config, &spec, *specStr, mods, config.Vars, &actionretry)
			ranTest = true
			if ii == 0 && actionretry {
				// only allow the action to retry for the first
				// action. This avoids rerunning creates when
				// followed by shows.
				retry.ActionEnable()
			}
		}
		if spec.CompareYaml.Yaml1 != "" && spec.CompareYaml.Yaml2 != "" {
			pass := e2esetup.CompareYamlFiles(spec.CompareYaml.Yaml1,
				spec.CompareYaml.Yaml2, spec.CompareYaml.FileType)
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

	fmt.Printf("\nNum Errors found: %d, Results in: %s\n", len(errors), outputDir)
	if len(errors) > 0 {
		errstring := strings.Join(errors, ",")
		fmt.Fprint(os.Stderr, errstring)
		os.Exit(len(errors))
	}
	os.Exit(0)
}
