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
	cmd := exec.Command("curl", "-sLf", "-o", kubectl,
		"https://dl.k8s.io/release/v"+maj+"."+min+".0/bin/linux/amd64/kubectl")
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("%s: %s: %s", cmd.String(), string(out), err)
	}
	err = os.Chmod(kubectl, 0755)
	if err != nil {
		log.Fatalf("chmod %s: %s", kubectl, err)
	}
}
