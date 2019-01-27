package main

import (
	"flag"
	"fmt"
	"os"
	"reflect"

	sh "github.com/codeskyblue/go-sh"
	"github.com/mobiledgex/edge-cloud-infra/mexos"
	"github.com/mobiledgex/edge-cloud/log"
)

var clusterOps = map[string]func(*mexos.Manifest) error{
	"create": mexos.MEXClusterCreateManifest,
	"remove": mexos.MEXClusterRemoveManifest,
}

var platformOps = map[string]func(*mexos.Manifest) error{
	"create": mexos.MEXPlatformInitManifest,
	"remove": mexos.MEXPlatformCleanManifest,
}

var applicationOps = map[string]func(*mexos.Manifest) error{
	"create": mexos.MEXAppCreateAppManifest,
	"remove": mexos.MEXAppDeleteAppManifest,
}

var openstackOps = map[string]func(*mexos.Manifest) error{}
var kubectlOps = map[string]func(*mexos.Manifest) error{}

var categories = map[string]map[string]func(*mexos.Manifest) error{
	"cluster":     clusterOps,
	"platform":    platformOps,
	"application": applicationOps,
	"openstack":   openstackOps,
	"kubectl":     kubectlOps,
}

var mainflag = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

func printUsage() {
	originalUsage()
	fmt.Println("mex -manifest myvals.yaml {platform|cluster|application} {create|remove}")
	fmt.Println("mex -manifest myvals.yaml openstack ...")
}

var originalUsage func()

func main() {
	var err error
	help := mainflag.Bool("help", false, "help")
	debugLevels := mainflag.String("d", "", fmt.Sprintf("comma separated list of %v", log.DebugLevelStrings))
	base := mainflag.String("base", ".", "base containing templates, directory path or URI")
	manifest := mainflag.String("manifest", "", "manifest")
	originalUsage = mainflag.Usage
	mainflag.Usage = printUsage
	if err = mainflag.Parse(os.Args[1:]); err != nil {
		log.InfoLog("parse error", "error", err)
		os.Exit(1)
	}
	if *help {
		printUsage()
		os.Exit(0)
	}
	log.SetDebugLevelStrs(*debugLevels)
	//XXX TODO make log to a remote server / aggregator
	args := mainflag.Args()
	if len(args) < 2 {
		printUsage()
		fmt.Println("insufficient args")
		os.Exit(1)
	}
	_, ok := categories[args[0]]
	if !ok {
		printUsage()
		fmt.Println("valid categories are", "categories", reflect.ValueOf(categories).MapKeys())
		os.Exit(1)
	}
	if *manifest == "" {
		printUsage()
		fmt.Println("missing manifest")
		os.Exit(1)
	}
	if len(args) < 2 {
		printUsage()
		fmt.Println("insufficient args")
		os.Exit(1)
	}
	log.DebugLog(log.DebugLevelMexos, "getting mf from manifest", "file", *manifest, "base", *base)
	mf := &mexos.Manifest{Base: *base}
	if err := mexos.GetVaultEnv(mf, *manifest); err != nil {
		log.InfoLog("cannot get mf", "uri", *manifest, "error", err)
		os.Exit(1)
	}
	kind := args[0]
	if err := mexos.FillManifestValues(mf, kind, *base); err != nil {
		log.InfoLog("cannot fill manifest", "error", err, "kind", kind, "base", *base)
		os.Exit(1)
	}
	if err := mexos.CheckManifest(mf); err != nil {
		log.InfoLog("incorrect manifest", "error", err)
		os.Exit(1)
	}
	if _, err := mexos.NewRootLBManifest(mf); err != nil {
		log.InfoLog("can't get new rootLB", "error", err)
		os.Exit(1)
	}
	if err := mexos.MEXInit(mf); err != nil {
		log.InfoLog("cannot init mex", "error", err)
		os.Exit(1)
	}
	ops := args[1:]
	log.DebugLog(log.DebugLevelMexos, "call", "kind", kind, "ops", ops)
	err = callOps(mf, kind, ops...)
	if err != nil {
		log.InfoLog("ops failure", "kind", kind, "ops", ops, "error", err)
		os.Exit(1)
	}
	os.Exit(0)
}

func callOps(mf *mexos.Manifest, kind string, ops ...string) error {
	if kind == "openstack" {
		vs := make([]interface{}, len(ops))
		for i, v := range ops {
			vs[i] = v
		}
		out, err := sh.Command(kind, vs...).Output()
		if err != nil {
			return fmt.Errorf("error, %s %v, %v, %s", kind, ops, err, out)
		}
		fmt.Println(string(out))
		return nil
	}
	if kind == "kubectl" {
		vs := ""
		for _, v := range ops {
			vs = vs + v + " "
		}
		out, err := mexos.RunKubectl(mf, vs)
		if err != nil {
			return fmt.Errorf("error, %s %v, %v", kind, ops, err)
		}
		fmt.Println(string(*out))
		return nil
	}
	if _, ok := categories[kind]; !ok {
		return fmt.Errorf("invalid category %s", kind)
	}
	op := ops[0]
	if _, ok := categories[kind][op]; !ok {
		return fmt.Errorf("invalid category op %s", op)
	}
	err := categories[kind][op](mf)
	if err != nil {
		return err
	}
	return nil
}
