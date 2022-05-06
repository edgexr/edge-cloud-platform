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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/edgexr/edge-cloud-infra/mc/mcctl/ormctl"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud/cli"
	"github.com/spf13/cobra"
)

func (s *RootCommand) getReportCmdGroup() *cobra.Command {
	apiGroup := ormctl.MustGetGroup("Report")
	cmds := []*cli.Command{}
	for _, c := range apiGroup.Commands {
		cliCmd := s.ConvertCmd(c)
		switch c.Name {
		case "GenerateReport":
			cliCmd.Run = s.runGenerateReport(c.Path)
		case "DownloadReport":
			cliCmd.Run = s.runDownloadReport(c.Path)
		}
		cmds = append(cmds, cliCmd)
	}
	return cli.GenGroup(strings.ToLower(apiGroup.Name), apiGroup.Desc, cmds)
}

func (s *RootCommand) runGenerateReport(path string) func(c *cli.Command, args []string) error {
	return func(c *cli.Command, args []string) error {
		c.CobraCmd.SilenceUsage = true
		in, err := c.ParseInput(args)
		if err != nil {
			if len(args) == 0 {
				// Force print usage since no args specified,
				// but obviously some are required.
				c.CobraCmd.SilenceUsage = false
			}
			return err
		}
		s.client.Debug = cli.Debug

		report, ok := c.ReqData.(*ormapi.GenerateReport)
		if !ok {
			return fmt.Errorf("unable to fetch report args: %v", c.ReqData)
		}

		filename := ormapi.GetReportFileName(report)
		st, err := s.sendReqAndDownloadPDF(path, filename, in.Data)
		return check(c, st, err, nil)
	}
}

func (s *RootCommand) runDownloadReport(path string) func(c *cli.Command, args []string) error {
	return func(c *cli.Command, args []string) error {
		c.CobraCmd.SilenceUsage = true
		in, err := c.ParseInput(args)
		if err != nil {
			if len(args) == 0 {
				// Force print usage since no args specified,
				// but obviously some are required.
				c.CobraCmd.SilenceUsage = false
			}
			return err
		}
		s.client.Debug = cli.Debug
		report, ok := c.ReqData.(*ormapi.DownloadReport)
		if !ok {
			return fmt.Errorf("unable to fetch report args: %v", c.ReqData)
		}

		st, err := s.sendReqAndDownloadPDF(path, report.Filename, in.Data)
		return check(c, st, err, nil)
	}
}

func (s *RootCommand) sendReqAndDownloadPDF(path, filename string, reqData interface{}) (int, error) {
	uri := s.getUri() + path
	resp, err := s.client.PostJsonSend(uri, s.token, reqData)
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("post %s client do failed, %s", uri, err.Error())
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, iErr := ioutil.ReadAll(resp.Body)
		if iErr != nil {
			err = iErr
		} else {
			res := ormapi.Result{}
			err = json.Unmarshal(body, &res)
			if err != nil {
				// string error
				err = fmt.Errorf("%s", body)
			} else {
				err = fmt.Errorf("%s", res.Message)
			}
		}
		return resp.StatusCode, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return http.StatusBadRequest, err
	}
	// Save blob to file
	filename = strings.ReplaceAll(filename, "/", "_")
	err = ioutil.WriteFile(filename, body, 0666)
	if err != nil {
		return http.StatusBadRequest, fmt.Errorf("failed to created file %s, %v", filename, err)
	}
	fmt.Printf("Saved PDF report to %s\n", filename)
	return resp.StatusCode, nil
}
