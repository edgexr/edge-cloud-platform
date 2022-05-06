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

package mccli

import (
	"fmt"

	"github.com/edgexr/edge-cloud/cli"
	"github.com/edgexr/edge-cloud/version"
	"github.com/spf13/cobra"
)

func GetVersionCmd() *cobra.Command {
	cmd := cli.Command{
		Use:   "version",
		Short: "Version of mcctl cli utility",
	}
	cmd.Run = func(c *cli.Command, args []string) error {
		wr := c.CobraCmd.OutOrStdout()
		fmt.Fprintf(wr, "buildmaster: %s\n", version.BuildMaster)
		fmt.Fprintf(wr, "buildhead: %s\n", version.BuildHead)
		if version.BuildAuthor != "" {
			fmt.Fprintf(wr, "buildauthor: %s\n", version.BuildAuthor)
		}
		fmt.Fprintf(wr, "builddate: %s\n", version.BuildDate)
		return nil
	}
	return cmd.GenCmd()
}
