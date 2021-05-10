package main

import (
	"os"

	"github.com/mobiledgex/edge-cloud-infra/mc/mcctl/mccli"
)

func main() {
	rootCmd := mccli.GetRootCommand()
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
