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
	"strings"

	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
)

const RateLimitSettingsMcGroup = "RateLimitSettingsMc"

var RateLimitSettingsMcRequiredArgs = []string{
	"apiname",
	"ratelimittarget",
}

var FlowRateLimitSettingsMcRequiredArgs = []string{
	"flowsettingsname",
	"apiname",
	"ratelimittarget",
}

var CreateFlowRateLimitSettingsMcRequiredArgs = []string{
	"flowalgorithm",
	"reqspersecond",
}

var MaxReqsRateLimitSettingsMcRequiredArgs = []string{
	"maxreqssettingsname",
	"apiname",
	"ratelimittarget",
}

var CreateMaxReqsRateLimitSettingsMcRequiredArgs = []string{
	"maxreqsalgorithm",
	"maxrequests",
	"interval",
}

func init() {
	cmds := []*ApiCommand{&ApiCommand{
		Name:         "ShowRateLimitSettingsMc",
		Use:          "show",
		Short:        "Show master controller ratelimitsettings",
		OptionalArgs: strings.Join(RateLimitSettingsMcRequiredArgs, " "),
		Comments:     RateLimitSettingsComments,
		ReqData:      &ormapi.McRateLimitSettings{},
		ReplyData:    &[]ormapi.McRateLimitSettings{},
		Path:         "/auth/ratelimitsettingsmc/show",
	}, &ApiCommand{
		Name:         "CreateFlowRateLimitSettingsMc",
		Use:          "createflow",
		Short:        "Create master controller flowratelimitsettings",
		RequiredArgs: strings.Join(append(FlowRateLimitSettingsMcRequiredArgs, CreateFlowRateLimitSettingsMcRequiredArgs...), " "),
		OptionalArgs: strings.Join(CreateFlowRateLimitSettingsOptionalArgs, " "),
		Comments:     FlowRateLimitSettingsComments,
		ReqData:      &ormapi.McRateLimitFlowSettings{},
		Path:         "/auth/ratelimitsettingsmc/createflow",
	}, &ApiCommand{
		Name:         "UpdateFlowRateLimitSettingsMc",
		Use:          "updateflow",
		Short:        "Update master controller flowratelimitsettings",
		RequiredArgs: strings.Join(FlowRateLimitSettingsMcRequiredArgs, " "),
		OptionalArgs: strings.Join(FlowRateLimitSettingsOptionalArgs, " "),
		Comments:     FlowRateLimitSettingsComments,
		ReqData:      &ormapi.McRateLimitFlowSettings{},
		Path:         "/auth/ratelimitsettingsmc/updateflow",
	}, &ApiCommand{
		Name:         "DeleteFlowRateLimitSettingsMc",
		Use:          "deleteflow",
		Short:        "Delete master controller flowratelimitsettings",
		RequiredArgs: strings.Join(FlowRateLimitSettingsMcRequiredArgs, " "),
		OptionalArgs: strings.Join(FlowRateLimitSettingsOptionalArgs, " "),
		Comments:     FlowRateLimitSettingsComments,
		ReqData:      &ormapi.McRateLimitFlowSettings{},
		Path:         "/auth/ratelimitsettingsmc/deleteflow",
	}, &ApiCommand{
		Name:         "ShowFlowRateLimitSettingsMc",
		Use:          "showflow",
		Short:        "Show master controller flowratelimitsettings",
		OptionalArgs: strings.Join(append(FlowRateLimitSettingsMcRequiredArgs, FlowRateLimitSettingsOptionalArgs...), " "),
		Comments:     FlowRateLimitSettingsComments,
		ReqData:      &ormapi.McRateLimitFlowSettings{},
		ReplyData:    &[]ormapi.McRateLimitFlowSettings{},
		Path:         "/auth/ratelimitsettingsmc/showflow",
	}, &ApiCommand{
		Name:         "CreateMaxReqsRateLimitSettingsMc",
		Use:          "createmaxreqs",
		Short:        "Create master controller maxreqsratelimitsettings",
		RequiredArgs: strings.Join(append(MaxReqsRateLimitSettingsMcRequiredArgs, CreateMaxReqsRateLimitSettingsMcRequiredArgs...), " "),
		OptionalArgs: strings.Join(CreateMaxReqsRateLimitSettingsOptionalArgs, " "),
		Comments:     MaxReqsRateLimitSettingsComments,
		ReqData:      &ormapi.McRateLimitMaxReqsSettings{},
		Path:         "/auth/ratelimitsettingsmc/createmaxreqs",
	}, &ApiCommand{
		Name:         "UpdateMaxReqsRateLimitSettingsMc",
		Use:          "updatemaxreqs",
		Short:        "Update master controller maxreqsratelimitsettings",
		RequiredArgs: strings.Join(MaxReqsRateLimitSettingsMcRequiredArgs, " "),
		OptionalArgs: strings.Join(MaxReqsRateLimitSettingsOptionalArgs, " "),
		Comments:     MaxReqsRateLimitSettingsComments,
		ReqData:      &ormapi.McRateLimitMaxReqsSettings{},
		Path:         "/auth/ratelimitsettingsmc/updatemaxreqs",
	}, &ApiCommand{
		Name:         "DeleteMaxReqsRateLimitSettingsMc",
		Use:          "deletemaxreqs",
		Short:        "Delete master controller maxreqsratelimitsettings",
		RequiredArgs: strings.Join(MaxReqsRateLimitSettingsMcRequiredArgs, " "),
		OptionalArgs: strings.Join(MaxReqsRateLimitSettingsOptionalArgs, " "),
		Comments:     MaxReqsRateLimitSettingsComments,
		ReqData:      &ormapi.McRateLimitMaxReqsSettings{},
		Path:         "/auth/ratelimitsettingsmc/deletemaxreqs",
	}, &ApiCommand{
		Name:         "ShowMaxReqsRateLimitSettingsMc",
		Use:          "showmaxreqs",
		Short:        "Show master controller maxreqsratelimitsettings",
		OptionalArgs: strings.Join(append(MaxReqsRateLimitSettingsMcRequiredArgs, MaxReqsRateLimitSettingsOptionalArgs...), " "),
		Comments:     MaxReqsRateLimitSettingsComments,
		ReqData:      &ormapi.McRateLimitMaxReqsSettings{},
		ReplyData:    &[]ormapi.McRateLimitMaxReqsSettings{},
		Path:         "/auth/ratelimitsettingsmc/showmaxreqs",
	}}
	AllApis.AddGroup(RateLimitSettingsMcGroup, "Manage global ratelimitsettings", cmds)
}
