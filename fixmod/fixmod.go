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
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

var keepReplaces = make(mapFlags)

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
	flag.Var(keepReplaces, "keep", "Keep custom replace for path")
	flag.Parse()
	if *srcRepo == "" {
		log.Fatal("source repo not specified\n")
	}

	srcMod, err := getGoMod(*srcRepo)
	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}
	dstMod, err := getGoMod(*dstRepo)
	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}

	dstReplaces := make(map[string]struct{})
	for _, rep := range dstMod.Replace {
		dstReplaces[rep.Old.Path] = struct{}{}
	}

	replaces := []string{}

	for _, req := range srcMod.Require {
		replace := fmt.Sprintf("%s=%s@%s", req.Path, req.Path, req.Version)
		replaces = append(replaces, replace)
		delete(dstReplaces, req.Path)
	}
	for _, rep := range srcMod.Replace {
		replace := fmt.Sprintf("%s=%s", rep.Old.PathVer(), rep.New.PathVer())
		replaces = append(replaces, replace)
		delete(dstReplaces, rep.Old.Path)
	}
	for _, replace := range replaces {
		args := []string{"mod", "edit", "-replace", replace}
		if err := runGo(*dstRepo, args); err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(1)
		}
	}
	for old, _ := range dstReplaces {
		// remove stale replaces
		if _, found := keepReplaces[old]; found {
			continue
		}
		args := []string{"mod", "edit", "-dropreplace", old}
		if err := runGo(*dstRepo, args); err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(1)
		}
	}
}

func getGoMod(dir string) (*GoMod, error) {
	cmd := exec.Command("go", "mod", "edit", "-json")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GO111MODULE=on")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go mod edit -json (%s) failed, %v, %s", dir, err, out)
	}
	mod := GoMod{}
	err = json.Unmarshal([]byte(out), &mod)
	if err != nil {
		return nil, fmt.Errorf("failed to parse output, %v", err)
	}
	return &mod, nil
}

func runGo(dir string, args []string) error {
	if *print {
		fmt.Printf("go %s\n", strings.Join(args, " "))
		return nil
	}
	cmd := exec.Command("go", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GO111MODULE=on")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("run go %s failed, %s, %s\n",
			strings.Join(args, " "), err, out)
	}
	return nil
}

type mapFlags map[string]struct{}

func (m mapFlags) String() string { return "map of strings" }

func (m mapFlags) Set(value string) error {
	m[value] = struct{}{}
	return nil
}

func (m *Module) PathVer() string {
	if m.Version == "" {
		return m.Path
	}
	return m.Path + "@" + m.Version
}
