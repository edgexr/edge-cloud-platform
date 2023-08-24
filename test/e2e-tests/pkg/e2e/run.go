// Package e2e is for end-to-end local testing
package e2e

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path"
	"strings"
	"time"

	edgelog "github.com/edgexr/edge-cloud-platform/pkg/log"
)

type Run struct {
	// command line args
	TestFile    string
	OutputDir   string
	VarsFile    string
	StopOnFail  bool
	Verbose     bool
	Notimestamp bool
	Runextra    bool
	FailedTests map[string]int

	// overriddable data
	TestsToRun E2ETests
	TestRunner TestRunner
	E2EHome    string
	TestConfig TestConfig
	LogFile    *os.File
	Stdout     *os.File
	Stderr     *os.File
}

// TestRunner runs individual tests. It is abstracted as an
// interface to allow for extending the base TestSpecRunner
// to support more testing functions.
type TestRunner interface {
	Init(ctx context.Context, testConfig *TestConfig) error
	RunAction(ctx context.Context, action, actionSubtype, actionParam, outputDir string, testSpec *TestSpec, testSpecRaw map[string]interface{}, mods []string, vars map[string]string, actionRetry *bool) []string
}

var IncludeFileNone = "none"

type E2ETests struct {
	Description string                   `yaml:"description"`
	Program     string                   `yaml:"program"`
	Tests       []map[string]interface{} `yaml:"tests"`
}

// E2ETest is test, which may include another file which has tests.
// Looping can be done at either test level or the included file level.
type E2ETest struct {
	Name        string   `yaml:"name"`
	IncludeFile string   `yaml:"includefile"`
	Mods        []string `yaml:"mods"`
	Loops       int      `yaml:"loops"`
	ExtraTest   bool     `yaml:"extratest"`
}

type arrayFlags []string

func (s *arrayFlags) String() string { return "array flags" }

func (s *arrayFlags) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func NewRun() *Run {
	r := &Run{
		FailedTests: make(map[string]int),
		TestRunner:  &TestSpecRunner{},
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
	}
	return r
}

func (s *Run) InitFlags() {
	//re-init the flags because otherwise we inherit a bunch of flags from the
	//testing package which get inserted into the usage.
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flag.StringVar(&s.TestFile, "testfile", "", "input file with tests")
	flag.StringVar(&s.OutputDir, "outputdir", "/tmp/e2e_test_out", "output directory, timestamp will be appended")
	flag.StringVar(&s.TestConfig.SetupFile, "setupfile", "", "process setup file")
	flag.StringVar(&s.VarsFile, "varsfile", "", "yaml file containing vars, key: value definitions")
	flag.BoolVar(&s.StopOnFail, "stop", false, "stop on failures")
	flag.BoolVar(&s.Verbose, "verbose", false, "prints full output screen")
	flag.BoolVar(&s.Notimestamp, "notimestamp", false, "no timestamp on outputdir, logs will be appended to by subsequent runs")
	flag.BoolVar(&s.Runextra, "runextra", false, "run extra tests (may take much longer)")
}

func PrintUsage() {
	fmt.Println("\nUsage: \n" + os.Args[0] + " [options]\n\noptions:")
	flag.PrintDefaults()
}

func (s *Run) ValidateArgs() {
	flag.Parse()
	s.TestConfig.Vars = make(map[string]string)

	errorFound := false

	if s.TestFile == "" {
		fmt.Println("Argument -testfile <file> is required")
		errorFound = true
	}
	if s.OutputDir == "" {
		fmt.Println("Argument -outputdir <dir> is required")
		errorFound = true
	}
	if s.TestConfig.SetupFile == "" {
		fmt.Println("Argument -setupfile <file> is required")
		errorFound = true
	}
	if err := ReadVarsFile(s.VarsFile, s.TestConfig.Vars); err != nil {
		fmt.Fprintf(s.Stdout, "failed to read yaml vars file %s, %v\n", s.VarsFile, err)
		errorFound = true
	}
	s.OutputDir, s.LogFile = CreateOutputDir(!s.Notimestamp, s.OutputDir, "e2e-test.log")
	s.TestConfig.Vars["outputdir"] = s.OutputDir

	// expand any environment variables in path (like $GOPATH)
	for key, val := range s.TestConfig.Vars {
		s.TestConfig.Vars[key] = os.ExpandEnv(val)
	}

	if errorFound {
		PrintUsage()
		os.Exit(1)
	}
}

func (s *Run) readYamlFile(fileName string, tests interface{}) bool {
	err := ReadYamlFile(fileName, tests, WithVars(s.TestConfig.Vars), ValidateReplacedVars())
	if err != nil {
		log.Fatalf("*** Error in reading test file: %v - err: %v\n", s.TestFile, err)
	}
	return true
}

func parseTest(testinfo map[string]interface{}, test *E2ETest) error {
	// we could use mapstructure here but it's easy to just
	// convert map to json and then unmarshal json.
	spec, err := json.Marshal(testinfo)
	if err != nil {
		return err
	}
	return json.Unmarshal(spec, test)
}

func parseTestSpec(testinfo map[string]interface{}, s *TestSpec) error {
	// we could use mapstructure here but it's easy to just
	// convert map to json and then unmarshal json.
	spec, err := json.Marshal(testinfo)
	if err != nil {
		return err
	}
	return json.Unmarshal(spec, s)
}

func (s *Run) RunTests(ctx context.Context, dirName, fileName string, depth int, mods []string) (int, int, int) {
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
		indentstr = indentstr + "- "
	}
	defer func() {
		f := indentstr + fileName
		fmt.Fprintf(s.Stdout, "%-30s %-66s %s\n", f, "done", time.Since(runStart))
	}()
	var testsToRun E2ETests
	if !s.readYamlFile(dirName+"/"+fileName, &testsToRun) {
		fmt.Fprintf(s.Stdout, "\n** unable to read yaml file %s\n", fileName)
		return 0, 0, 0
	}

	//if no loop count specified, run once

	for _, testinfo := range testsToRun.Tests {
		t := E2ETest{}
		err := parseTest(testinfo, &t)
		if err != nil {
			fmt.Fprintf(s.Stdout, "\nfailed to parse test %v, %v\n", testinfo, err)
			numTestsRun++
			numFailed++
			if s.StopOnFail {
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
				if t.IncludeFile == IncludeFileNone {
					continue
				}
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
			fmt.Fprintf(s.Stdout, "%-30s %-60s ", f, namestr+loopStr)
			if t.IncludeFile != "" {
				if t.ExtraTest && !s.Runextra {
					fmt.Fprintln(s.Stdout)
					continue
				}
				if depth >= 10 {
					//avoid an infinite recusive loop in which a testfile contains itself
					log.Fatalf("excessive include depth %d, possible loop: %s", depth, fileName)
				}
				fmt.Fprintln(s.Stdout)
				nr, np, nf := s.RunTests(ctx, dirName, t.IncludeFile, depth+1, append(mods, t.Mods...))
				numTestsRun += nr
				numPassed += np
				numFailed += nf
				if s.StopOnFail && nf > 0 {
					return numTestsRun, numPassed, numFailed
				}
				continue
			}
			startT := time.Now()
			testSpec := &TestSpec{}
			if err := parseTestSpec(testinfo, testSpec); err != nil {
				fmt.Fprintf(s.Stdout, "FAIL: %s\n", err)
				continue
			}
			runerr := s.RunTestSpec(ctx, s.TestRunner, testSpec, testinfo, mods, s.StopOnFail)
			took := time.Since(startT).String()
			if runerr == nil {
				fmt.Fprintf(s.Stdout, "PASS  %s\n", took)
				numPassed += 1
			} else {
				fmt.Fprintf(s.Stdout, "FAIL: %s %s\n", took, runerr)
				numFailed += 1
				_, ok := s.FailedTests[fileName+":"+t.Name]
				if !ok {
					s.FailedTests[fileName+":"+t.Name] = 0
				}
				s.FailedTests[fileName+":"+t.Name] += 1

				if s.StopOnFail {
					fmt.Fprintf(s.Stdout, "*** STOPPING ON FAILURE due to --stop option\n")
					return numTestsRun, numPassed, numFailed
				}
			}
			numTestsRun++
		}
	}
	if s.Verbose {
		fmt.Fprintf(s.Stdout, "\n\n*** Summary of testfile %s Tests Run: %d Passed: %d Failed: %d -- Logs in %s\n", fileName, numTestsRun, numPassed, numFailed, s.OutputDir)
	}
	return numTestsRun, numPassed, numFailed

}

func (s *Run) Start() {
	s.ValidateArgs()
	defer s.LogFile.Close()

	os.Stdout = s.LogFile
	os.Stderr = s.LogFile

	fmt.Fprintf(s.Stdout, "\n%-30s %-60s Result\n", "Testfile", "Test")
	fmt.Fprintf(s.Stdout, "-----------------------------------------------------------------------------------------------------\n")
	edgelog.SetupLoggers(s.LogFile.Name())
	edgelog.InitTracer(nil)
	defer edgelog.FinishTracer()
	ctx := edgelog.StartTestSpan(context.Background())
	SetLogFormat()
	dirName := path.Dir(s.TestFile)
	fileName := path.Base(s.TestFile)
	start := time.Now()

	err := s.TestRunner.Init(ctx, &s.TestConfig)
	if err != nil {
		fmt.Fprintf(s.Stdout, "Failed test runner init: %s\n", err)
		os.Exit(1)
	}
	totalRun, totalPassed, totalFailed := s.RunTests(ctx, dirName, fileName, 0, []string{})
	fmt.Fprintf(s.Stdout, "\nTotal Run: %d, passed: %d, failed: %d, took: %s\n", totalRun, totalPassed, totalFailed, time.Since(start).String())

	if totalFailed > 0 {
		fmt.Fprintf(s.Stdout, "Failed Tests: ")
		for t, f := range s.FailedTests {
			fmt.Fprintf(s.Stdout, "  %s: failures %d\n", t, f)
		}
		fmt.Fprintf(s.Stdout, "Logs in %s\n", s.OutputDir)
		os.Exit(1)
	}
}
