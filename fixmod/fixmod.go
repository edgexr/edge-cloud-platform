package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

var srcRepo = flag.String("srcRepo", "", "source repo from which to pull modules dependencies")
var dstRepo = flag.String("dstRepo", ".", "destination repo from which to write modules replace dependencies")
var print = flag.Bool("print", false, "print replace commands for target module only")

// Structs are from
// https://tip.golang.org/cmd/go/#hdr-Edit_go_mod_from_tools_or_scripts

type Module struct {
	Path    string
	Version string
}

type GoMod struct {
	Module  Module
	Go      string
	Require []Require
	Exclude []Module
	Replace []Replace
}

type Require struct {
	Path     string
	Version  string
	Indirect bool
}

type Replace struct {
	Old Module
	New Module
}

func main() {
	flag.Parse()
	if *srcRepo == "" {
		log.Fatal("source repo not specified\n")
	}

	srcCmd := exec.Command("go", "mod", "edit", "-json")
	srcCmd.Dir = *srcRepo
	srcCmd.Env = append(os.Environ(), "GO111MODULE=on")
	out, err := srcCmd.Output()
	if err != nil {
		fmt.Printf("go mod edit -json failed, %v, %s\n", err, out)
		os.Exit(1)
	}
	srcMod := GoMod{}
	err = json.Unmarshal([]byte(out), &srcMod)
	if err != nil {
		fmt.Printf("failed to parse output, %v\n", err)
		os.Exit(1)
	}
	replaces := []string{}

	for _, req := range srcMod.Require {
		replace := fmt.Sprintf("%s=%s@%s", req.Path, req.Path, req.Version)
		replaces = append(replaces, replace)
	}
	for _, rep := range srcMod.Replace {
		replace := fmt.Sprintf("%s=%s", rep.Old, rep.New)
		replaces = append(replaces, replace)
	}
	for _, replace := range replaces {
		args := []string{"mod", "edit", "-replace", replace}
		if *print {
			fmt.Printf("go %s\n", strings.Join(args, " "))
			continue
		}
		cmd := exec.Command("go", args...)
		cmd.Dir = *dstRepo
		cmd.Env = append(os.Environ(), "GO111MODULE=on")
		out, err := cmd.CombinedOutput()
		if err != nil {
			fmt.Printf("run go %s failed, %s, %s\n",
				strings.Join(args, " "), err, out)
			os.Exit(1)
		}
	}
}
