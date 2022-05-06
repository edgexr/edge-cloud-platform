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

import (
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
)

const ReporterGroup = "Reporter"
const ReportGroup = "Report"
const ReportDataGroup = "ReportData"

func init() {
	cmds := []*ApiCommand{&ApiCommand{
		Name:         "CreateReporter",
		Use:          "create",
		Short:        "Create new reporter",
		RequiredArgs: "name org",
		OptionalArgs: "email schedule startscheduledate timezone",
		ReqData:      &ormapi.Reporter{},
		Comments:     ormapi.ReporterComments,
		Path:         "/auth/reporter/create",
	}, &ApiCommand{
		Name:         "UpdateReporter",
		Use:          "update",
		Short:        "Update reporter",
		RequiredArgs: "name org",
		OptionalArgs: "email schedule startscheduledate timezone",
		ReqData:      &ormapi.Reporter{},
		Comments:     ormapi.ReporterComments,
		Path:         "/auth/reporter/update",
	}, &ApiCommand{
		Name:         "DeleteReporter",
		Use:          "delete",
		Short:        "Delete reporter",
		RequiredArgs: "name org",
		ReqData:      &ormapi.Reporter{},
		Comments:     ormapi.ReporterComments,
		Path:         "/auth/reporter/delete",
	}, &ApiCommand{
		Name:         "ShowReporter",
		Use:          "show",
		Short:        "Show reporters",
		OptionalArgs: "name org",
		ReqData:      &ormapi.Reporter{},
		Comments:     ormapi.ReporterComments,
		ReplyData:    &[]ormapi.Reporter{},
		Path:         "/auth/reporter/show",
	}}
	AllApis.AddGroup(ReporterGroup, "Manage report schedule", cmds)

	cmds = []*ApiCommand{&ApiCommand{
		Name:         "GenerateReport",
		Use:          "generate",
		Short:        "Generate new report for an org of all regions",
		RequiredArgs: "org starttime endtime",
		OptionalArgs: "timezone",
		ReqData:      &ormapi.GenerateReport{},
		Comments:     ormapi.GenerateReportComments,
		Path:         "/auth/report/generate",
	}, &ApiCommand{
		Name:         "ShowReport",
		Use:          "show",
		Short:        "Show already generated reports for an org",
		RequiredArgs: "org",
		OptionalArgs: "reporter",
		ReqData:      &ormapi.DownloadReport{},
		ReplyData:    &[]string{},
		Comments:     ormapi.DownloadReportComments,
		Path:         "/auth/report/show",
	}, &ApiCommand{
		Name:         "DownloadReport",
		Use:          "download",
		Short:        "Download generated report",
		RequiredArgs: "org filename",
		ReqData:      &ormapi.DownloadReport{},
		Comments:     ormapi.DownloadReportComments,
		Path:         "/auth/report/download",
	}}
	AllApis.AddGroup(ReportGroup, "Manage reports", cmds)

	cmds = []*ApiCommand{&ApiCommand{
		Name:         "GenerateReportData",
		Use:          "generate",
		Short:        "Generate report data for an org of all regions",
		RequiredArgs: "org starttime endtime",
		OptionalArgs: "org starttime endtime timezone",
		ReqData:      &ormapi.GenerateReport{},
		ReplyData:    &map[string]interface{}{},
		Comments:     ormapi.GenerateReportComments,
		Path:         "/auth/report/generatedata",
	}}
	AllApis.AddGroup(ReportDataGroup, "Access report data", cmds)
}
