// Copyright 2024 EdgeXR, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"gopkg.in/yaml.v2"
)

// This serves as a wrapper around kubectl to ensure the
// correct version of kubectl is used for the target cluster.

var (
	BinDir           = "/usr/bin"
	DefaultMajorVers = "1"
	DefaultMinorVers = "18"
)

type VersionOutput struct {
	Client Version `yaml:"clientVersion"`
	Server Version `yaml:"serverVersion"`
}

type Version struct {
	Git   string `yaml:"gitVersion"`
	Major string `yaml:"major"`
	Minor string `yaml:"minor"`
}

func main() {
	if str := os.Getenv("BINDIR"); str != "" {
		BinDir = str
	}
	if str := os.Getenv("DEFAULT_MAJOR_VERS"); str != "" {
		DefaultMajorVers = str
	}
	if str := os.Getenv("DEFAULT_MINOR_VERS"); str != "" {
		DefaultMinorVers = str
	}

	// grab any args that will direct us to a particular cluster
	versArgs := []string{}

	for ii, arg := range os.Args {
		if arg == "--kubeconfig" && len(os.Args) > ii+1 {
			versArgs = append(versArgs, arg, os.Args[ii+1])
		}
		if arg == "--context" && len(os.Args) > ii+1 {
			versArgs = append(versArgs, arg, os.Args[ii+1])
		}
		if arg == "--cluster" && len(os.Args) > ii+1 {
			versArgs = append(versArgs, arg, os.Args[ii+1])
		}
		if strings.HasPrefix(arg, "--kubeconfig=") {
			versArgs = append(versArgs, arg)
		}
		if strings.HasPrefix(arg, "--context=") {
			versArgs = append(versArgs, arg)
		}
		if strings.HasPrefix(arg, "--cluster=") {
			versArgs = append(versArgs, arg)
		}
	}
	defKubectl := kubectlPath(DefaultMajorVers, DefaultMinorVers)
	if _, err := os.Stat(defKubectl); err != nil {
		download(DefaultMajorVers, DefaultMinorVers)
	}
	// run kubectl to get server version
	versArgs = append(versArgs, "version", "--output=yaml")
	out, err := exec.Command(defKubectl, versArgs...).CombinedOutput()
	if err != nil {
		log.Fatalf("%s, %s", string(out), err)
	}
	// parse output to get cluster version
	versOut := VersionOutput{}
	err = yaml.Unmarshal(out, &versOut)
	if err != nil {
		log.Fatal(err.Error())
	}
	// ensure that matching or off by one kubectl version exists
	maj := versOut.Server.Major
	min := versOut.Server.Minor
	minInt, err := strconv.Atoi(versOut.Server.Minor)
	if err != nil {
		log.Fatal(err)
	}
	minLT := strconv.Itoa(minInt - 1)
	minGT := strconv.Itoa(minInt + 1)

	kubectl := ""
	kubectlLT := kubectlPath(maj, minLT)
	kubectlEQ := kubectlPath(maj, min)
	kubectlGT := kubectlPath(maj, minGT)
	if _, err := os.Stat(kubectlEQ); err == nil {
		kubectl = kubectlEQ
	} else if _, err := os.Stat(kubectlLT); err == nil {
		kubectl = kubectlLT
	} else if _, err := os.Stat(kubectlGT); err == nil {
		kubectl = kubectlGT
	} else {
		kubectl = kubectlEQ
		download(maj, min)
	}
	// run original command with compatible kubectl version
	cmd := exec.Command(kubectl, os.Args[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		os.Exit(1)
	}
}

func kubectlPath(maj, min string) string {
	return fmt.Sprintf("%s/kubectl-v%s.%s.0", BinDir, maj, min)
}

func download(maj, min string) {
	kubectl := kubectlPath(maj, min)
	cmd := exec.Command("sudo", "curl", "-sLf", "-o", kubectl,
		"https://dl.k8s.io/release/v"+maj+"."+min+".0/bin/linux/amd64/kubectl")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("%s: %s: %s", cmd.String(), string(out), err)
	}
	chmodCmd := exec.Command("sudo", "chmod", "0755", kubectl)
	out, err = chmodCmd.CombinedOutput()
	if err != nil {
		log.Fatalf("%s: %s: %s", cmd.String(), string(out), err)
	}
}
