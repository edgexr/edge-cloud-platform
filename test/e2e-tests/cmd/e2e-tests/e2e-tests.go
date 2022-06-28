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

// executes end-to-end MEX tests by calling test-mex multiple times as directed by the input test file.

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"
	"strconv"
	"strings"
	"time"

	edgelog "github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/test/e2e-tests/pkg/e2e"
)

var (
	commandName = "e2e-tests"
	testFile    *string
	outputDir   *string
	setupFile   *string
	varsFile    *string
	stopOnFail  *bool
	verbose     *bool
	notimestamp *bool
	runextra    *bool
	failedTests = make(map[string]int)
)

//re-init the flags because otherwise we inherit a bunch of flags from the testing
//package which get inserted into the usage.
func init() {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	testFile = flag.String("testfile", "", "input file with tests")
	outputDir = flag.String("outputdir", "/tmp/e2e_test_out", "output directory, timestamp will be appended")
	setupFile = flag.String("setupfile", "", "network config setup file")
	varsFile = flag.String("varsfile", "", "yaml file containing vars, key: value definitions")
	stopOnFail = flag.Bool("stop", false, "stop on failures")
	verbose = flag.Bool("verbose", false, "prints full output screen")
	notimestamp = flag.Bool("notimestamp", false, "no timestamp on outputdir, logs will be appended to by subsequent runs")
	runextra = flag.Bool("runextra", false, "run extra tests (may take much longer)")
}

// a list of tests, which may include another file which has tests.  Looping can
//be done at either test level or the included file level.
type e2e_test struct {
	Name        string   `yaml:"name"`
	IncludeFile string   `yaml:"includefile"`
	Mods        []string `yaml:"mods"`
	Loops       int      `yaml:"loops"`
	ExtraTest   bool     `yaml:"extratest"`
}

type e2e_tests struct {
	Description string                   `yaml:"description"`
	Program     string                   `yaml:"program"`
	Tests       []map[string]interface{} `yaml:"tests"`
}

var testsToRun e2e_tests
var e2eHome string
var configStr string
var testConfig e2e.TestConfig
var defaultProgram string
var logFile *os.File
var stdout *os.File
var stderr *os.File

func printUsage() {
	fmt.Println("\nUsage: \n" + commandName + " [options]\n\noptions:")
	flag.PrintDefaults()
}

func validateArgs() {
	//re-init the flags so we don't get a bunch of test flags in the usage
	flag.Parse()
	testConfig.Vars = make(map[string]string)

	errorFound := false

	if *testFile == "" {
		fmt.Println("Argument -testfile <file> is required")
		errorFound = true
	}
	if *outputDir == "" {
		fmt.Println("Argument -outputdir <dir> is required")
		errorFound = true
	}
	if *setupFile == "" {
		fmt.Println("Argument -setupfile <file> is required")
		errorFound = true
	}
	if err := e2e.ReadVarsFile(*varsFile, testConfig.Vars); err != nil {
		fmt.Fprintf(stdout, "failed to read yaml vars file %s, %v\n", *varsFile, err)
		errorFound = true
	}
	testConfig.SetupFile = *setupFile
	*outputDir, logFile = e2e.CreateOutputDir(!*notimestamp, *outputDir, commandName+".log")
	testConfig.Vars["outputdir"] = *outputDir
	dataDir, found := testConfig.Vars["datadir"]
	if !found {
		dataDir = "$GOPATH/src/github.com/edgexr/edge-cloud-platform/setup-env/e2e-tests/data"
		testConfig.Vars["datadir"] = dataDir
	}

	// expand any environment variables in path (like $GOPATH)
	for key, val := range testConfig.Vars {
		testConfig.Vars[key] = os.ExpandEnv(val)
	}

	defaultProgram = testConfig.Vars["default-program"]

	configBytes, err := json.Marshal(&testConfig)
	if err != nil {
		fmt.Fprintf(stdout, "failed to marshal TestConfig, %v\n", err)
		errorFound = true
	}
	configStr = string(configBytes)

	if errorFound {
		printUsage()
		os.Exit(1)
	}
}

func readYamlFile(fileName string, tests interface{}) bool {
	err := e2e.ReadYamlFile(fileName, tests, e2e.WithVars(testConfig.Vars), e2e.ValidateReplacedVars())
	if err != nil {
		log.Fatalf("*** Error in reading test file: %v - err: %v\n", *testFile, err)
	}
	return true
}

func parseTest(testinfo map[string]interface{}, test *e2e_test) error {
	// we could use mapstructure here but it's easy to just
	// convert map to json and then unmarshal json.
	spec, err := json.Marshal(testinfo)
	if err != nil {
		return err
	}
	return json.Unmarshal(spec, test)
}

func parseTestSpec(testinfo map[string]interface{}, s *e2e.TestSpec) error {
	// we could use mapstructure here but it's easy to just
	// convert map to json and then unmarshal json.
	spec, err := json.Marshal(testinfo)
	if err != nil {
		return err
	}
	return json.Unmarshal(spec, s)
}

func runTests(ctx context.Context, dirName, fileName, progName string, depth int, mods []string) (int, int, int) {
	numPassed := 0
	numFailed := 0
	numTestsRun := 0

	runStart := time.Now()

	if fileName[0] == '/' {
		// absolute path
		dirName = path.Dir(fileName)
		fileName = path.Base(fileName)
	}

	indentstr := ""
	for i := 0; i < depth; i++ {
		indentstr = indentstr + " - "
	}
	defer func() {
		f := indentstr + fileName
		fmt.Fprintf(stdout, "%-30s %-66s %s\n", f, "done", time.Since(runStart))
	}()
	var testsToRun e2e_tests
	if !readYamlFile(dirName+"/"+fileName, &testsToRun) {
		fmt.Fprintf(stdout, "\n** unable to read yaml file %s\n", fileName)
		return 0, 0, 0
	}
	if testsToRun.Program != "" {
		progName = testsToRun.Program
	}

	//if no loop count specified, run once

	for _, testinfo := range testsToRun.Tests {
		t := e2e_test{}
		err := parseTest(testinfo, &t)
		if err != nil {
			fmt.Fprintf(stdout, "\nfailed to parse test %v, %v\n", testinfo, err)
			numTestsRun++
			numFailed++
			if *stopOnFail {
				return numTestsRun, numPassed, numFailed
			}
			continue
		}
		loopCount := 1
		loopStr := ""

		if t.Loops > loopCount {
			loopCount = t.Loops
		}
		for i := 1; i <= loopCount; i++ {
			if i > 1 {
				loopStr = fmt.Sprintf("(loop %d)", i)
			}
			namestr := t.Name
			if namestr == "" && t.IncludeFile != "" {
				if len(t.IncludeFile) > 58 {
					ilen := len(t.IncludeFile)
					namestr = "include: ..." +
						t.IncludeFile[ilen-58:ilen]
				} else {
					namestr = "include: " + t.IncludeFile
				}
			}
			f := indentstr + fileName
			if len(mods) > 0 {
				f += " " + strings.Join(mods, ",")
			}
			if len(f) > 30 {
				f = f[0:27] + "..."
			}
			fmt.Fprintf(stdout, "%-30s %-60s ", f, namestr+loopStr)
			if t.IncludeFile != "" {
				if t.ExtraTest && !*runextra {
					fmt.Fprintln(stdout)
					continue
				}
				if depth >= 10 {
					//avoid an infinite recusive loop in which a testfile contains itself
					log.Fatalf("excessive include depth %d, possible loop: %s", depth, fileName)
				}
				fmt.Fprintln(stdout)
				nr, np, nf := runTests(ctx, dirName, t.IncludeFile, progName, depth+1, append(mods, t.Mods...))
				numTestsRun += nr
				numPassed += np
				numFailed += nf
				if *stopOnFail && nf > 0 {
					return numTestsRun, numPassed, numFailed
				}
				continue
			}
			startT := time.Now()
			var runerr error
			if progName != "" {
				testSpec, err := json.Marshal(testinfo)
				if err != nil {
					fmt.Fprintf(stdout, "FAIL: cannot marshal test info %v, %v\n", err, testinfo)
					numTestsRun++
					numFailed++
					if *stopOnFail {
						return numTestsRun, numPassed, numFailed
					}
					continue
				}
				modsSpec, err := json.Marshal(mods)
				if err != nil {
					fmt.Fprintf(stdout, "FAIL: cannot marshal mods %v, %v\n", err, mods)
					numTestsRun++
					numFailed++
					if *stopOnFail {
						return numTestsRun, numPassed, numFailed
					}
					continue
				}
				args := []string{
					"-testConfig", configStr,
					"-testSpec", string(testSpec),
					"-mods", string(modsSpec),
				}
				if *stopOnFail {
					args = append(args, "-stop")
				}
				cmd := exec.Command(progName, args...)
				var out bytes.Buffer
				var stderr bytes.Buffer
				cmd.Stdout = &out
				cmd.Stderr = &stderr
				runerr = cmd.Run()
				if *verbose {
					fmt.Fprintln(stdout, out.String())
				}
				if stderr.Len() > 0 {
					ioutil.WriteFile("/tmp/fail-output"+strconv.Itoa(cmd.Process.Pid), stderr.Bytes(), 0666)
					runerr = fmt.Errorf("%s\n%s", stderr.String(), runerr)
				}
			} else {
				testSpec := &e2e.TestSpec{}
				if err := parseTestSpec(testinfo, testSpec); err != nil {
					fmt.Fprintf(stdout, "FAIL: %s\n", err)
					continue
				}
				runerr = e2e.RunTestSpec(ctx, &testConfig, testSpec, mods, *stopOnFail)
			}
			took := time.Since(startT).String()
			if runerr == nil {
				fmt.Fprintf(stdout, "PASS  %s\n", took)
				numPassed += 1
			} else {
				fmt.Fprintf(stdout, "FAIL: %s %s\n", took, runerr)
				numFailed += 1
				_, ok := failedTests[fileName+":"+t.Name]
				if !ok {
					failedTests[fileName+":"+t.Name] = 0
				}
				failedTests[fileName+":"+t.Name] += 1

				if *stopOnFail {
					fmt.Fprintf(stdout, "*** STOPPING ON FAILURE due to --stop option\n")
					return numTestsRun, numPassed, numFailed
				}
			}
			numTestsRun++
		}
	}
	if *verbose {
		fmt.Fprintf(stdout, "\n\n*** Summary of testfile %s Tests Run: %d Passed: %d Failed: %d -- Logs in %s\n", fileName, numTestsRun, numPassed, numFailed, *outputDir)
	}
	return numTestsRun, numPassed, numFailed

}

func main() {
	validateArgs()
	defer logFile.Close()

	stdout = os.Stdout
	stderr = os.Stderr
	os.Stdout = logFile
	os.Stderr = logFile

	fmt.Fprintf(stdout, "\n%-30s %-60s Result\n", "Testfile", "Test")
	fmt.Fprintf(stdout, "-----------------------------------------------------------------------------------------------------\n")
	if *testFile != "" {
		edgelog.SetupLoggers(logFile.Name())
		edgelog.InitTracer(nil)
		defer edgelog.FinishTracer()
		ctx := edgelog.StartTestSpan(context.Background())
		e2e.SetLogFormat()

		dirName := path.Dir(*testFile)
		fileName := path.Base(*testFile)
		start := time.Now()
		totalRun, totalPassed, totalFailed := runTests(ctx, dirName, fileName, defaultProgram, 0, []string{})
		fmt.Fprintf(stdout, "\nTotal Run: %d, passed: %d, failed: %d, took: %s\n", totalRun, totalPassed, totalFailed, time.Since(start).String())
		if totalFailed > 0 {
			fmt.Fprintf(stdout, "Failed Tests: ")
			for t, f := range failedTests {
				fmt.Fprintf(stdout, "  %s: failures %d\n", t, f)
			}
			fmt.Fprintf(stdout, "Logs in %s\n", *outputDir)
			os.Exit(1)
		}
	}

}
