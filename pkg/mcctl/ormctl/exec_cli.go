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

package ormctl

// Copies of exec commands, but with string output because
// mcctl opens the connection to the backend from the ExecRequest and
// returns the data as a string. These should only be used with
// the cliwrapper client.

func init() {
	genCliCmd := func(c *ApiCommand) *ApiCommand {
		cmd := *c
		cmd.Name += "Cli"
		var str string
		cmd.ReplyData = &str
		return &cmd
	}
	AllApis.AddCommand(genCliCmd(RunCommandCmd))
	AllApis.AddCommand(genCliCmd(ShowLogsCmd))
	AllApis.AddCommand(genCliCmd(AccessCloudletCmd))
}
