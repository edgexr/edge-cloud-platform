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

package mctestclient

import (
	"github.com/edgexr/edge-cloud-infra/billing"
	"github.com/edgexr/edge-cloud-infra/mc/mcctl/ormctl"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud-infra/mc/ormutil"
	"github.com/edgexr/edge-cloud/cli"
	"github.com/edgexr/edge-cloud/cloudcommon/node"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/mobiledgex/jaeger/plugin/storage/es/spanstore/dbmodel"
)

// Auto-generated code: DO NOT EDIT

// Generating group Alert

func (s *Client) ShowAlert(uri string, token string, in *ormapi.RegionAlert) ([]edgeproto.Alert, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.Alert
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowAlert")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

// Generating group AlertPolicy

func (s *Client) CreateAlertPolicy(uri string, token string, in *ormapi.RegionAlertPolicy) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("CreateAlertPolicy")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) DeleteAlertPolicy(uri string, token string, in *ormapi.RegionAlertPolicy) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("DeleteAlertPolicy")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) UpdateAlertPolicy(uri string, token string, in *ormapi.RegionAlertPolicy) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	mm, err := ormutil.GetRegionObjStructMapForUpdate(in)
	if err != nil {
		return nil, 0, err
	}
	rundata.In = mm
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("UpdateAlertPolicy")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowAlertPolicy(uri string, token string, in *ormapi.RegionAlertPolicy) ([]edgeproto.AlertPolicy, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.AlertPolicy
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowAlertPolicy")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

// Generating group AlertReceiver

func (s *Client) CreateAlertReceiver(uri string, token string, in *ormapi.AlertReceiver) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("CreateAlertReceiver")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) DeleteAlertReceiver(uri string, token string, in *ormapi.AlertReceiver) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("DeleteAlertReceiver")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowAlertReceiver(uri string, token string, in *ormapi.AlertReceiver) ([]ormapi.AlertReceiver, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []ormapi.AlertReceiver
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowAlertReceiver")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

// Generating group App

func (s *Client) CreateApp(uri string, token string, in *ormapi.RegionApp) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("CreateApp")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) DeleteApp(uri string, token string, in *ormapi.RegionApp) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("DeleteApp")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) UpdateApp(uri string, token string, in *ormapi.RegionApp) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	mm, err := ormutil.GetRegionObjStructMapForUpdate(in)
	if err != nil {
		return nil, 0, err
	}
	rundata.In = mm
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("UpdateApp")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowApp(uri string, token string, in *ormapi.RegionApp) ([]edgeproto.App, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.App
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowApp")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) AddAppAutoProvPolicy(uri string, token string, in *ormapi.RegionAppAutoProvPolicy) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("AddAppAutoProvPolicy")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) RemoveAppAutoProvPolicy(uri string, token string, in *ormapi.RegionAppAutoProvPolicy) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("RemoveAppAutoProvPolicy")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) AddAppAlertPolicy(uri string, token string, in *ormapi.RegionAppAlertPolicy) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("AddAppAlertPolicy")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) RemoveAppAlertPolicy(uri string, token string, in *ormapi.RegionAppAlertPolicy) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("RemoveAppAlertPolicy")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowCloudletsForAppDeployment(uri string, token string, in *ormapi.RegionDeploymentCloudletRequest) ([]edgeproto.CloudletKey, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.CloudletKey
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowCloudletsForAppDeployment")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

// Generating group AppInst

func (s *Client) CreateAppInst(uri string, token string, in *ormapi.RegionAppInst) ([]edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("CreateAppInst")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) DeleteAppInst(uri string, token string, in *ormapi.RegionAppInst) ([]edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("DeleteAppInst")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) RefreshAppInst(uri string, token string, in *ormapi.RegionAppInst) ([]edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("RefreshAppInst")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) UpdateAppInst(uri string, token string, in *ormapi.RegionAppInst) ([]edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	mm, err := ormutil.GetRegionObjStructMapForUpdate(in)
	if err != nil {
		return nil, 0, err
	}
	rundata.In = mm
	var out []edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("UpdateAppInst")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowAppInst(uri string, token string, in *ormapi.RegionAppInst) ([]edgeproto.AppInst, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.AppInst
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowAppInst")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

// Generating group AppInstClient

func (s *Client) ShowAppInstClient(uri string, token string, in *ormapi.RegionAppInstClientKey) ([]edgeproto.AppInstClient, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.AppInstClient
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowAppInstClient")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

// Generating group AppInstLatency

func (s *Client) RequestAppInstLatency(uri string, token string, in *ormapi.RegionAppInstLatency) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("RequestAppInstLatency")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

// Generating group AppInstRefs

func (s *Client) ShowAppInstRefs(uri string, token string, in *ormapi.RegionAppInstRefs) ([]edgeproto.AppInstRefs, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.AppInstRefs
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowAppInstRefs")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

// Generating group AutoProvPolicy

func (s *Client) CreateAutoProvPolicy(uri string, token string, in *ormapi.RegionAutoProvPolicy) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("CreateAutoProvPolicy")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) DeleteAutoProvPolicy(uri string, token string, in *ormapi.RegionAutoProvPolicy) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("DeleteAutoProvPolicy")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) UpdateAutoProvPolicy(uri string, token string, in *ormapi.RegionAutoProvPolicy) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	mm, err := ormutil.GetRegionObjStructMapForUpdate(in)
	if err != nil {
		return nil, 0, err
	}
	rundata.In = mm
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("UpdateAutoProvPolicy")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowAutoProvPolicy(uri string, token string, in *ormapi.RegionAutoProvPolicy) ([]edgeproto.AutoProvPolicy, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.AutoProvPolicy
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowAutoProvPolicy")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) AddAutoProvPolicyCloudlet(uri string, token string, in *ormapi.RegionAutoProvPolicyCloudlet) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("AddAutoProvPolicyCloudlet")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) RemoveAutoProvPolicyCloudlet(uri string, token string, in *ormapi.RegionAutoProvPolicyCloudlet) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("RemoveAutoProvPolicyCloudlet")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

// Generating group AutoScalePolicy

func (s *Client) CreateAutoScalePolicy(uri string, token string, in *ormapi.RegionAutoScalePolicy) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("CreateAutoScalePolicy")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) DeleteAutoScalePolicy(uri string, token string, in *ormapi.RegionAutoScalePolicy) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("DeleteAutoScalePolicy")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) UpdateAutoScalePolicy(uri string, token string, in *ormapi.RegionAutoScalePolicy) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	mm, err := ormutil.GetRegionObjStructMapForUpdate(in)
	if err != nil {
		return nil, 0, err
	}
	rundata.In = mm
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("UpdateAutoScalePolicy")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowAutoScalePolicy(uri string, token string, in *ormapi.RegionAutoScalePolicy) ([]edgeproto.AutoScalePolicy, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.AutoScalePolicy
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowAutoScalePolicy")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

// Generating group BillingEvents

func (s *Client) ShowAppEvents(uri string, token string, in *ormapi.RegionAppInstEvents) (*ormapi.AllMetrics, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out ormapi.AllMetrics
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowAppEvents")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowClusterEvents(uri string, token string, in *ormapi.RegionClusterInstEvents) (*ormapi.AllMetrics, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out ormapi.AllMetrics
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowClusterEvents")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowCloudletEvents(uri string, token string, in *ormapi.RegionCloudletEvents) (*ormapi.AllMetrics, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out ormapi.AllMetrics
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowCloudletEvents")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

// Generating group BillingOrg

func (s *Client) CreateBillingOrg(uri string, token string, in *ormapi.BillingOrganization) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("CreateBillingOrg")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) UpdateBillingOrg(uri string, token string, in *cli.MapData) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("UpdateBillingOrg")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) AddBillingOrgChild(uri string, token string, in *ormapi.BillingOrganization) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("AddBillingOrgChild")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) RemoveBillingOrgChild(uri string, token string, in *ormapi.BillingOrganization) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("RemoveBillingOrgChild")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) DeleteBillingOrg(uri string, token string, in *ormapi.BillingOrganization) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("DeleteBillingOrg")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowBillingOrg(uri string, token string, in *cli.MapData) ([]ormapi.BillingOrganization, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []ormapi.BillingOrganization
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowBillingOrg")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowAccountInfo(uri string, token string) ([]ormapi.AccountInfo, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	var out []ormapi.AccountInfo
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowAccountInfo")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowPaymentProfiles(uri string, token string, in *ormapi.BillingOrganization) ([]billing.PaymentProfile, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []billing.PaymentProfile
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowPaymentProfiles")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) DeletePaymentProfile(uri string, token string, in *ormapi.PaymentProfileDeletion) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("DeletePaymentProfile")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) GetInvoice(uri string, token string, in *ormapi.InvoiceRequest) ([]billing.InvoiceData, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []billing.InvoiceData
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("GetInvoice")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

// Generating group Cloudlet

func (s *Client) CreateCloudlet(uri string, token string, in *ormapi.RegionCloudlet) ([]edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("CreateCloudlet")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) DeleteCloudlet(uri string, token string, in *ormapi.RegionCloudlet) ([]edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("DeleteCloudlet")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) UpdateCloudlet(uri string, token string, in *ormapi.RegionCloudlet) ([]edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	mm, err := ormutil.GetRegionObjStructMapForUpdate(in)
	if err != nil {
		return nil, 0, err
	}
	rundata.In = mm
	var out []edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("UpdateCloudlet")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowCloudlet(uri string, token string, in *ormapi.RegionCloudlet) ([]edgeproto.Cloudlet, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.Cloudlet
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowCloudlet")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) GetCloudletManifest(uri string, token string, in *ormapi.RegionCloudletKey) (*edgeproto.CloudletManifest, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.CloudletManifest
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("GetCloudletManifest")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) GetCloudletProps(uri string, token string, in *ormapi.RegionCloudletProps) (*edgeproto.CloudletProps, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.CloudletProps
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("GetCloudletProps")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) GetCloudletResourceQuotaProps(uri string, token string, in *ormapi.RegionCloudletResourceQuotaProps) (*edgeproto.CloudletResourceQuotaProps, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.CloudletResourceQuotaProps
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("GetCloudletResourceQuotaProps")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) GetCloudletResourceUsage(uri string, token string, in *ormapi.RegionCloudletResourceUsage) (*edgeproto.CloudletResourceUsage, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.CloudletResourceUsage
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("GetCloudletResourceUsage")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) AddCloudletResMapping(uri string, token string, in *ormapi.RegionCloudletResMap) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("AddCloudletResMapping")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) RemoveCloudletResMapping(uri string, token string, in *ormapi.RegionCloudletResMap) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("RemoveCloudletResMapping")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) AddCloudletAllianceOrg(uri string, token string, in *ormapi.RegionCloudletAllianceOrg) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("AddCloudletAllianceOrg")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) RemoveCloudletAllianceOrg(uri string, token string, in *ormapi.RegionCloudletAllianceOrg) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("RemoveCloudletAllianceOrg")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) FindFlavorMatch(uri string, token string, in *ormapi.RegionFlavorMatch) (*edgeproto.FlavorMatch, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.FlavorMatch
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("FindFlavorMatch")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowFlavorsForCloudlet(uri string, token string, in *ormapi.RegionCloudletKey) ([]edgeproto.FlavorKey, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.FlavorKey
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowFlavorsForCloudlet")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) GetOrganizationsOnCloudlet(uri string, token string, in *ormapi.RegionCloudletKey) ([]edgeproto.Organization, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.Organization
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("GetOrganizationsOnCloudlet")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) RevokeAccessKey(uri string, token string, in *ormapi.RegionCloudletKey) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("RevokeAccessKey")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) GenerateAccessKey(uri string, token string, in *ormapi.RegionCloudletKey) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("GenerateAccessKey")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) GetCloudletGPUDriverLicenseConfig(uri string, token string, in *ormapi.RegionCloudletKey) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("GetCloudletGPUDriverLicenseConfig")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

// Generating group CloudletInfo

func (s *Client) ShowCloudletInfo(uri string, token string, in *ormapi.RegionCloudletInfo) ([]edgeproto.CloudletInfo, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.CloudletInfo
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowCloudletInfo")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) InjectCloudletInfo(uri string, token string, in *ormapi.RegionCloudletInfo) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("InjectCloudletInfo")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) EvictCloudletInfo(uri string, token string, in *ormapi.RegionCloudletInfo) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("EvictCloudletInfo")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

// Generating group CloudletPool

func (s *Client) CreateCloudletPool(uri string, token string, in *ormapi.RegionCloudletPool) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("CreateCloudletPool")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) DeleteCloudletPool(uri string, token string, in *ormapi.RegionCloudletPool) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("DeleteCloudletPool")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) UpdateCloudletPool(uri string, token string, in *ormapi.RegionCloudletPool) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	mm, err := ormutil.GetRegionObjStructMapForUpdate(in)
	if err != nil {
		return nil, 0, err
	}
	rundata.In = mm
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("UpdateCloudletPool")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowCloudletPool(uri string, token string, in *ormapi.RegionCloudletPool) ([]edgeproto.CloudletPool, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.CloudletPool
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowCloudletPool")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) AddCloudletPoolMember(uri string, token string, in *ormapi.RegionCloudletPoolMember) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("AddCloudletPoolMember")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) RemoveCloudletPoolMember(uri string, token string, in *ormapi.RegionCloudletPoolMember) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("RemoveCloudletPoolMember")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

// Generating group CloudletPoolAccess

func (s *Client) ShowCloudletPoolAccessGranted(uri string, token string, in *cli.MapData) ([]ormapi.OrgCloudletPool, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []ormapi.OrgCloudletPool
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowCloudletPoolAccessGranted")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowCloudletPoolAccessPending(uri string, token string, in *cli.MapData) ([]ormapi.OrgCloudletPool, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []ormapi.OrgCloudletPool
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowCloudletPoolAccessPending")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

// Generating group CloudletPoolInvitation

func (s *Client) CreateCloudletPoolAccessInvitation(uri string, token string, in *ormapi.OrgCloudletPool) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("CreateCloudletPoolAccessInvitation")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) DeleteCloudletPoolAccessInvitation(uri string, token string, in *ormapi.OrgCloudletPool) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("DeleteCloudletPoolAccessInvitation")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowCloudletPoolAccessInvitation(uri string, token string, in *cli.MapData) ([]ormapi.OrgCloudletPool, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []ormapi.OrgCloudletPool
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowCloudletPoolAccessInvitation")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

// Generating group CloudletPoolResponse

func (s *Client) CreateCloudletPoolAccessResponse(uri string, token string, in *ormapi.OrgCloudletPool) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("CreateCloudletPoolAccessResponse")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) DeleteCloudletPoolAccessResponse(uri string, token string, in *ormapi.OrgCloudletPool) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("DeleteCloudletPoolAccessResponse")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowCloudletPoolAccessResponse(uri string, token string, in *cli.MapData) ([]ormapi.OrgCloudletPool, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []ormapi.OrgCloudletPool
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowCloudletPoolAccessResponse")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

// Generating group CloudletRefs

func (s *Client) ShowCloudletRefs(uri string, token string, in *ormapi.RegionCloudletRefs) ([]edgeproto.CloudletRefs, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.CloudletRefs
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowCloudletRefs")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

// Generating group ClusterInst

func (s *Client) CreateClusterInst(uri string, token string, in *ormapi.RegionClusterInst) ([]edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("CreateClusterInst")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) DeleteClusterInst(uri string, token string, in *ormapi.RegionClusterInst) ([]edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("DeleteClusterInst")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) UpdateClusterInst(uri string, token string, in *ormapi.RegionClusterInst) ([]edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	mm, err := ormutil.GetRegionObjStructMapForUpdate(in)
	if err != nil {
		return nil, 0, err
	}
	rundata.In = mm
	var out []edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("UpdateClusterInst")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowClusterInst(uri string, token string, in *ormapi.RegionClusterInst) ([]edgeproto.ClusterInst, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.ClusterInst
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowClusterInst")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) DeleteIdleReservableClusterInsts(uri string, token string, in *ormapi.RegionIdleReservableClusterInsts) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("DeleteIdleReservableClusterInsts")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

// Generating group ClusterRefs

func (s *Client) ShowClusterRefs(uri string, token string, in *ormapi.RegionClusterRefs) ([]edgeproto.ClusterRefs, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.ClusterRefs
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowClusterRefs")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

// Generating group Config

func (s *Client) UpdateConfig(uri string, token string, in *cli.MapData) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("UpdateConfig")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) ResetConfig(uri string, token string) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token

	apiCmd := ormctl.MustGetCommand("ResetConfig")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowConfig(uri string, token string) (*ormapi.Config, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	var out ormapi.Config
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowConfig")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowPublicConfig(uri string) (*ormapi.Config, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	var out ormapi.Config
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowPublicConfig")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) MCVersion(uri string, token string) (*ormapi.Version, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	var out ormapi.Version
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("MCVersion")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

// Generating group Controller

func (s *Client) CreateController(uri string, token string, in *ormapi.Controller) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("CreateController")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) UpdateController(uri string, token string, in *cli.MapData) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("UpdateController")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) DeleteController(uri string, token string, in *ormapi.Controller) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("DeleteController")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowController(uri string, token string, in *cli.MapData) ([]ormapi.Controller, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []ormapi.Controller
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowController")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

// Generating group Debug

func (s *Client) EnableDebugLevels(uri string, token string, in *ormapi.RegionDebugRequest) ([]edgeproto.DebugReply, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.DebugReply
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("EnableDebugLevels")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) DisableDebugLevels(uri string, token string, in *ormapi.RegionDebugRequest) ([]edgeproto.DebugReply, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.DebugReply
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("DisableDebugLevels")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowDebugLevels(uri string, token string, in *ormapi.RegionDebugRequest) ([]edgeproto.DebugReply, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.DebugReply
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowDebugLevels")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) RunDebug(uri string, token string, in *ormapi.RegionDebugRequest) ([]edgeproto.DebugReply, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.DebugReply
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("RunDebug")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

// Generating group Device

func (s *Client) InjectDevice(uri string, token string, in *ormapi.RegionDevice) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("InjectDevice")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowDevice(uri string, token string, in *ormapi.RegionDevice) ([]edgeproto.Device, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.Device
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowDevice")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) EvictDevice(uri string, token string, in *ormapi.RegionDevice) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("EvictDevice")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowDeviceReport(uri string, token string, in *ormapi.RegionDeviceReport) ([]edgeproto.Device, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.Device
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowDeviceReport")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

// Generating group Events

func (s *Client) ShowEvents(uri string, token string, in *node.EventSearch) ([]node.EventData, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []node.EventData
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowEvents")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowOldEvents(uri string, token string, in *node.EventSearch) ([]node.EventDataOld, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []node.EventDataOld
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowOldEvents")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) FindEvents(uri string, token string, in *node.EventSearch) ([]node.EventData, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []node.EventData
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("FindEvents")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) EventTerms(uri string, token string, in *node.EventSearch) (*node.EventTerms, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out node.EventTerms
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("EventTerms")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

// Generating group Exec

func (s *Client) RunCommand(uri string, token string, in *ormapi.RegionExecRequest) (*edgeproto.ExecRequest, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.ExecRequest
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("RunCommand")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) RunConsole(uri string, token string, in *ormapi.RegionExecRequest) (*edgeproto.ExecRequest, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.ExecRequest
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("RunConsole")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowLogs(uri string, token string, in *ormapi.RegionExecRequest) (*edgeproto.ExecRequest, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.ExecRequest
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowLogs")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) AccessCloudlet(uri string, token string, in *ormapi.RegionExecRequest) (*edgeproto.ExecRequest, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.ExecRequest
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("AccessCloudlet")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

// Generating group Federation

func (s *Client) CreateFederation(uri string, token string, in *ormapi.Federation) (*ormapi.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out ormapi.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("CreateFederation")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) DeleteFederation(uri string, token string, in *ormapi.Federation) (*ormapi.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out ormapi.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("DeleteFederation")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) SetPartnerFederationAPIKey(uri string, token string, in *ormapi.Federation) (*ormapi.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out ormapi.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("SetPartnerFederationAPIKey")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) RegisterFederation(uri string, token string, in *ormapi.Federation) (*ormapi.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out ormapi.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("RegisterFederation")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) DeregisterFederation(uri string, token string, in *ormapi.Federation) (*ormapi.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out ormapi.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("DeregisterFederation")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowFederation(uri string, token string, in *cli.MapData) ([]ormapi.Federation, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []ormapi.Federation
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowFederation")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

// Generating group Federator

func (s *Client) CreateSelfFederator(uri string, token string, in *ormapi.Federator) (*ormapi.Federator, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out ormapi.Federator
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("CreateSelfFederator")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) UpdateSelfFederator(uri string, token string, in *cli.MapData) (*ormapi.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out ormapi.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("UpdateSelfFederator")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) DeleteSelfFederator(uri string, token string, in *ormapi.Federator) (*ormapi.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out ormapi.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("DeleteSelfFederator")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowSelfFederator(uri string, token string, in *cli.MapData) ([]ormapi.Federator, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []ormapi.Federator
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowSelfFederator")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) GenerateSelfFederatorAPIKey(uri string, token string, in *ormapi.Federator) (*ormapi.Federator, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out ormapi.Federator
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("GenerateSelfFederatorAPIKey")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

// Generating group FederatorZone

func (s *Client) CreateSelfFederatorZone(uri string, token string, in *ormapi.FederatorZone) (*ormapi.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out ormapi.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("CreateSelfFederatorZone")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) DeleteSelfFederatorZone(uri string, token string, in *ormapi.FederatorZone) (*ormapi.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out ormapi.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("DeleteSelfFederatorZone")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowSelfFederatorZone(uri string, token string, in *cli.MapData) ([]ormapi.FederatorZone, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []ormapi.FederatorZone
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowSelfFederatorZone")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShareSelfFederatorZone(uri string, token string, in *ormapi.FederatedSelfZone) (*ormapi.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out ormapi.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShareSelfFederatorZone")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) UnshareSelfFederatorZone(uri string, token string, in *ormapi.FederatedSelfZone) (*ormapi.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out ormapi.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("UnshareSelfFederatorZone")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) RegisterPartnerFederatorZone(uri string, token string, in *ormapi.FederatedZoneRegRequest) (*ormapi.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out ormapi.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("RegisterPartnerFederatorZone")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) DeRegisterPartnerFederatorZone(uri string, token string, in *ormapi.FederatedZoneRegRequest) (*ormapi.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out ormapi.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("DeRegisterPartnerFederatorZone")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowFederatedSelfZone(uri string, token string, in *cli.MapData) ([]ormapi.FederatedSelfZone, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []ormapi.FederatedSelfZone
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowFederatedSelfZone")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowFederatedPartnerZone(uri string, token string, in *cli.MapData) ([]ormapi.FederatedPartnerZone, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []ormapi.FederatedPartnerZone
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowFederatedPartnerZone")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

// Generating group Flavor

func (s *Client) CreateFlavor(uri string, token string, in *ormapi.RegionFlavor) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("CreateFlavor")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) DeleteFlavor(uri string, token string, in *ormapi.RegionFlavor) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("DeleteFlavor")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) UpdateFlavor(uri string, token string, in *ormapi.RegionFlavor) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	mm, err := ormutil.GetRegionObjStructMapForUpdate(in)
	if err != nil {
		return nil, 0, err
	}
	rundata.In = mm
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("UpdateFlavor")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowFlavor(uri string, token string, in *ormapi.RegionFlavor) ([]edgeproto.Flavor, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.Flavor
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowFlavor")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) AddFlavorRes(uri string, token string, in *ormapi.RegionFlavor) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("AddFlavorRes")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) RemoveFlavorRes(uri string, token string, in *ormapi.RegionFlavor) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("RemoveFlavorRes")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

// Generating group GPUDriver

func (s *Client) CreateGPUDriver(uri string, token string, in *ormapi.RegionGPUDriver) ([]edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("CreateGPUDriver")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) DeleteGPUDriver(uri string, token string, in *ormapi.RegionGPUDriver) ([]edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("DeleteGPUDriver")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) UpdateGPUDriver(uri string, token string, in *ormapi.RegionGPUDriver) ([]edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	mm, err := ormutil.GetRegionObjStructMapForUpdate(in)
	if err != nil {
		return nil, 0, err
	}
	rundata.In = mm
	var out []edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("UpdateGPUDriver")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowGPUDriver(uri string, token string, in *ormapi.RegionGPUDriver) ([]edgeproto.GPUDriver, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.GPUDriver
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowGPUDriver")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) AddGPUDriverBuild(uri string, token string, in *ormapi.RegionGPUDriverBuildMember) ([]edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("AddGPUDriverBuild")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) RemoveGPUDriverBuild(uri string, token string, in *ormapi.RegionGPUDriverBuildMember) ([]edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("RemoveGPUDriverBuild")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) GetGPUDriverBuildURL(uri string, token string, in *ormapi.RegionGPUDriverBuildMember) (*edgeproto.GPUDriverBuildURL, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.GPUDriverBuildURL
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("GetGPUDriverBuildURL")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) GetGPUDriverLicenseConfig(uri string, token string, in *ormapi.RegionGPUDriverKey) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("GetGPUDriverLicenseConfig")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

// Generating group Metrics

func (s *Client) ShowAppMetrics(uri string, token string, in *ormapi.RegionAppInstMetrics) (*ormapi.AllMetrics, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out ormapi.AllMetrics
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowAppMetrics")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowClusterMetrics(uri string, token string, in *ormapi.RegionClusterInstMetrics) (*ormapi.AllMetrics, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out ormapi.AllMetrics
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowClusterMetrics")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowCloudletMetrics(uri string, token string, in *ormapi.RegionCloudletMetrics) (*ormapi.AllMetrics, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out ormapi.AllMetrics
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowCloudletMetrics")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowCloudletUsage(uri string, token string, in *ormapi.RegionCloudletMetrics) (*ormapi.AllMetrics, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out ormapi.AllMetrics
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowCloudletUsage")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowClientApiUsageMetrics(uri string, token string, in *ormapi.RegionClientApiUsageMetrics) (*ormapi.AllMetrics, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out ormapi.AllMetrics
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowClientApiUsageMetrics")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowClientAppUsageMetrics(uri string, token string, in *ormapi.RegionClientAppUsageMetrics) (*ormapi.AllMetrics, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out ormapi.AllMetrics
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowClientAppUsageMetrics")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowClientCloudletUsageMetrics(uri string, token string, in *ormapi.RegionClientCloudletUsageMetrics) (*ormapi.AllMetrics, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out ormapi.AllMetrics
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowClientCloudletUsageMetrics")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

// Generating group MetricsV2

func (s *Client) ShowAppV2Metrics(uri string, token string, in *ormapi.RegionCustomAppMetrics) (*ormapi.AllMetrics, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out ormapi.AllMetrics
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowAppV2Metrics")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

// Generating group Network

func (s *Client) CreateNetwork(uri string, token string, in *ormapi.RegionNetwork) ([]edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("CreateNetwork")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) DeleteNetwork(uri string, token string, in *ormapi.RegionNetwork) ([]edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("DeleteNetwork")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) UpdateNetwork(uri string, token string, in *ormapi.RegionNetwork) ([]edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	mm, err := ormutil.GetRegionObjStructMapForUpdate(in)
	if err != nil {
		return nil, 0, err
	}
	rundata.In = mm
	var out []edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("UpdateNetwork")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowNetwork(uri string, token string, in *ormapi.RegionNetwork) ([]edgeproto.Network, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.Network
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowNetwork")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

// Generating group Node

func (s *Client) ShowNode(uri string, token string, in *ormapi.RegionNode) ([]edgeproto.Node, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.Node
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowNode")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

// Generating group OperatorCode

func (s *Client) CreateOperatorCode(uri string, token string, in *ormapi.RegionOperatorCode) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("CreateOperatorCode")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) DeleteOperatorCode(uri string, token string, in *ormapi.RegionOperatorCode) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("DeleteOperatorCode")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowOperatorCode(uri string, token string, in *ormapi.RegionOperatorCode) ([]edgeproto.OperatorCode, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.OperatorCode
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowOperatorCode")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

// Generating group Org

func (s *Client) CreateOrg(uri string, token string, in *ormapi.Organization) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("CreateOrg")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) UpdateOrg(uri string, token string, in *cli.MapData) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("UpdateOrg")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) DeleteOrg(uri string, token string, in *ormapi.Organization) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("DeleteOrg")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowOrg(uri string, token string, in *cli.MapData) ([]ormapi.Organization, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []ormapi.Organization
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowOrg")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

// Generating group OrgCloudlet

func (s *Client) ShowOrgCloudlet(uri string, token string, in *ormapi.OrgCloudlet) ([]edgeproto.Cloudlet, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.Cloudlet
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowOrgCloudlet")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

// Generating group OrgCloudletInfo

func (s *Client) ShowOrgCloudletInfo(uri string, token string, in *ormapi.OrgCloudlet) ([]edgeproto.CloudletInfo, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.CloudletInfo
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowOrgCloudletInfo")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

// Generating group RateLimitSettings

func (s *Client) ShowRateLimitSettings(uri string, token string, in *ormapi.RegionRateLimitSettings) ([]edgeproto.RateLimitSettings, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.RateLimitSettings
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowRateLimitSettings")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) CreateFlowRateLimitSettings(uri string, token string, in *ormapi.RegionFlowRateLimitSettings) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("CreateFlowRateLimitSettings")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) UpdateFlowRateLimitSettings(uri string, token string, in *ormapi.RegionFlowRateLimitSettings) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	mm, err := ormutil.GetRegionObjStructMapForUpdate(in)
	if err != nil {
		return nil, 0, err
	}
	rundata.In = mm
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("UpdateFlowRateLimitSettings")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) DeleteFlowRateLimitSettings(uri string, token string, in *ormapi.RegionFlowRateLimitSettings) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("DeleteFlowRateLimitSettings")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowFlowRateLimitSettings(uri string, token string, in *ormapi.RegionFlowRateLimitSettings) ([]edgeproto.FlowRateLimitSettings, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.FlowRateLimitSettings
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowFlowRateLimitSettings")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) CreateMaxReqsRateLimitSettings(uri string, token string, in *ormapi.RegionMaxReqsRateLimitSettings) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("CreateMaxReqsRateLimitSettings")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) UpdateMaxReqsRateLimitSettings(uri string, token string, in *ormapi.RegionMaxReqsRateLimitSettings) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	mm, err := ormutil.GetRegionObjStructMapForUpdate(in)
	if err != nil {
		return nil, 0, err
	}
	rundata.In = mm
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("UpdateMaxReqsRateLimitSettings")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) DeleteMaxReqsRateLimitSettings(uri string, token string, in *ormapi.RegionMaxReqsRateLimitSettings) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("DeleteMaxReqsRateLimitSettings")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowMaxReqsRateLimitSettings(uri string, token string, in *ormapi.RegionMaxReqsRateLimitSettings) ([]edgeproto.MaxReqsRateLimitSettings, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.MaxReqsRateLimitSettings
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowMaxReqsRateLimitSettings")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

// Generating group RateLimitSettingsMc

func (s *Client) ShowRateLimitSettingsMc(uri string, token string, in *ormapi.McRateLimitSettings) ([]ormapi.McRateLimitSettings, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []ormapi.McRateLimitSettings
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowRateLimitSettingsMc")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) CreateFlowRateLimitSettingsMc(uri string, token string, in *ormapi.McRateLimitFlowSettings) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("CreateFlowRateLimitSettingsMc")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) UpdateFlowRateLimitSettingsMc(uri string, token string, in *cli.MapData) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("UpdateFlowRateLimitSettingsMc")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) DeleteFlowRateLimitSettingsMc(uri string, token string, in *ormapi.McRateLimitFlowSettings) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("DeleteFlowRateLimitSettingsMc")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowFlowRateLimitSettingsMc(uri string, token string, in *ormapi.McRateLimitFlowSettings) ([]ormapi.McRateLimitFlowSettings, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []ormapi.McRateLimitFlowSettings
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowFlowRateLimitSettingsMc")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) CreateMaxReqsRateLimitSettingsMc(uri string, token string, in *ormapi.McRateLimitMaxReqsSettings) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("CreateMaxReqsRateLimitSettingsMc")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) UpdateMaxReqsRateLimitSettingsMc(uri string, token string, in *cli.MapData) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("UpdateMaxReqsRateLimitSettingsMc")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) DeleteMaxReqsRateLimitSettingsMc(uri string, token string, in *ormapi.McRateLimitMaxReqsSettings) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("DeleteMaxReqsRateLimitSettingsMc")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowMaxReqsRateLimitSettingsMc(uri string, token string, in *ormapi.McRateLimitMaxReqsSettings) ([]ormapi.McRateLimitMaxReqsSettings, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []ormapi.McRateLimitMaxReqsSettings
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowMaxReqsRateLimitSettingsMc")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

// Generating group Report

func (s *Client) GenerateReport(uri string, token string, in *ormapi.GenerateReport) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("GenerateReport")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowReport(uri string, token string, in *ormapi.DownloadReport) ([]string, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []string
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowReport")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) DownloadReport(uri string, token string, in *ormapi.DownloadReport) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("DownloadReport")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

// Generating group ReportData

func (s *Client) GenerateReportData(uri string, token string, in *ormapi.GenerateReport) (map[string]interface{}, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out map[string]interface{}
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("GenerateReportData")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

// Generating group Reporter

func (s *Client) CreateReporter(uri string, token string, in *ormapi.Reporter) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("CreateReporter")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) UpdateReporter(uri string, token string, in *cli.MapData) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("UpdateReporter")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) DeleteReporter(uri string, token string, in *ormapi.Reporter) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("DeleteReporter")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowReporter(uri string, token string, in *ormapi.Reporter) ([]ormapi.Reporter, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []ormapi.Reporter
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowReporter")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

// Generating group Repos

func (s *Client) ArtifactoryResync(uri string, token string) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token

	apiCmd := ormctl.MustGetCommand("ArtifactoryResync")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) GitlabResync(uri string, token string) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token

	apiCmd := ormctl.MustGetCommand("GitlabResync")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

// Generating group ResTagTable

func (s *Client) CreateResTagTable(uri string, token string, in *ormapi.RegionResTagTable) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("CreateResTagTable")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) DeleteResTagTable(uri string, token string, in *ormapi.RegionResTagTable) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("DeleteResTagTable")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) UpdateResTagTable(uri string, token string, in *ormapi.RegionResTagTable) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	mm, err := ormutil.GetRegionObjStructMapForUpdate(in)
	if err != nil {
		return nil, 0, err
	}
	rundata.In = mm
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("UpdateResTagTable")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowResTagTable(uri string, token string, in *ormapi.RegionResTagTable) ([]edgeproto.ResTagTable, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.ResTagTable
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowResTagTable")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) AddResTag(uri string, token string, in *ormapi.RegionResTagTable) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("AddResTag")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) RemoveResTag(uri string, token string, in *ormapi.RegionResTagTable) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("RemoveResTag")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) GetResTagTable(uri string, token string, in *ormapi.RegionResTagTableKey) (*edgeproto.ResTagTable, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.ResTagTable
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("GetResTagTable")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

// Generating group Role

func (s *Client) ShowRoleNames(uri string, token string) ([]string, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	var out []string
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowRoleNames")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) AddUserRole(uri string, token string, in *ormapi.Role) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("AddUserRole")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) RemoveUserRole(uri string, token string, in *ormapi.Role) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("RemoveUserRole")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowUserRole(uri string, token string, in *cli.MapData) ([]ormapi.Role, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []ormapi.Role
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowUserRole")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowRoleAssignment(uri string, token string, in *cli.MapData) ([]ormapi.Role, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []ormapi.Role
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowRoleAssignment")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowRolePerm(uri string, token string, in *cli.MapData) ([]ormapi.RolePerm, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []ormapi.RolePerm
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowRolePerm")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

// Generating group Settings

func (s *Client) UpdateSettings(uri string, token string, in *ormapi.RegionSettings) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	mm, err := ormutil.GetRegionObjStructMapForUpdate(in)
	if err != nil {
		return nil, 0, err
	}
	rundata.In = mm
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("UpdateSettings")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ResetSettings(uri string, token string, in *ormapi.RegionSettings) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ResetSettings")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowSettings(uri string, token string, in *ormapi.RegionSettings) (*edgeproto.Settings, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Settings
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowSettings")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

// Generating group Spans

func (s *Client) SpanTerms(uri string, token string, in *node.SpanSearch) (*node.SpanTerms, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out node.SpanTerms
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("SpanTerms")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowSpans(uri string, token string, in *node.SpanSearch) ([]node.SpanOutCondensed, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []node.SpanOutCondensed
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowSpans")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowSpansVerbose(uri string, token string, in *node.SpanSearch) ([]dbmodel.Span, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []dbmodel.Span
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowSpansVerbose")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

// Generating group StreamObj

func (s *Client) StreamAppInst(uri string, token string, in *ormapi.RegionAppInstKey) ([]edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("StreamAppInst")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) StreamClusterInst(uri string, token string, in *ormapi.RegionClusterInstKey) ([]edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("StreamClusterInst")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) StreamCloudlet(uri string, token string, in *ormapi.RegionCloudletKey) ([]edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("StreamCloudlet")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) StreamGPUDriver(uri string, token string, in *ormapi.RegionGPUDriverKey) ([]edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("StreamGPUDriver")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

// Generating group TrustPolicy

func (s *Client) CreateTrustPolicy(uri string, token string, in *ormapi.RegionTrustPolicy) ([]edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("CreateTrustPolicy")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) DeleteTrustPolicy(uri string, token string, in *ormapi.RegionTrustPolicy) ([]edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("DeleteTrustPolicy")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) UpdateTrustPolicy(uri string, token string, in *ormapi.RegionTrustPolicy) ([]edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	mm, err := ormutil.GetRegionObjStructMapForUpdate(in)
	if err != nil {
		return nil, 0, err
	}
	rundata.In = mm
	var out []edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("UpdateTrustPolicy")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowTrustPolicy(uri string, token string, in *ormapi.RegionTrustPolicy) ([]edgeproto.TrustPolicy, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.TrustPolicy
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowTrustPolicy")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

// Generating group TrustPolicyException

func (s *Client) CreateTrustPolicyException(uri string, token string, in *ormapi.RegionTrustPolicyException) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("CreateTrustPolicyException")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) UpdateTrustPolicyException(uri string, token string, in *ormapi.RegionTrustPolicyException) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	mm, err := ormutil.GetRegionObjStructMapForUpdate(in)
	if err != nil {
		return nil, 0, err
	}
	rundata.In = mm
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("UpdateTrustPolicyException")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) DeleteTrustPolicyException(uri string, token string, in *ormapi.RegionTrustPolicyException) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("DeleteTrustPolicyException")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowTrustPolicyException(uri string, token string, in *ormapi.RegionTrustPolicyException) ([]edgeproto.TrustPolicyException, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.TrustPolicyException
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowTrustPolicyException")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

// Generating group Usage

func (s *Client) ShowAppUsage(uri string, token string, in *ormapi.RegionAppInstUsage) (*ormapi.AllMetrics, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out ormapi.AllMetrics
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowAppUsage")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowClusterUsage(uri string, token string, in *ormapi.RegionClusterInstUsage) (*ormapi.AllMetrics, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out ormapi.AllMetrics
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowClusterUsage")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowCloudletPoolUsage(uri string, token string, in *ormapi.RegionCloudletPoolUsage) (*ormapi.AllMetrics, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out ormapi.AllMetrics
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowCloudletPoolUsage")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

// Generating group User

func (s *Client) CreateUser(uri string, in *ormapi.CreateUser) (*ormapi.UserResponse, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.In = in
	var out ormapi.UserResponse
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("CreateUser")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) DeleteUser(uri string, token string, in *ormapi.User) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("DeleteUser")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) UpdateUser(uri string, token string, in *cli.MapData) (*ormapi.UserResponse, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out ormapi.UserResponse
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("UpdateUser")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowUser(uri string, token string, in *cli.MapData) ([]ormapi.User, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []ormapi.User
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowUser")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) CurrentUser(uri string, token string) (*ormapi.User, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	var out ormapi.User
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("CurrentUser")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) NewPassword(uri string, token string, in *ormapi.NewPassword) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("NewPassword")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) ResendVerify(uri string, in *ormapi.EmailRequest) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("ResendVerify")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) VerifyEmail(uri string, in *ormapi.Token) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("VerifyEmail")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) PasswordResetRequest(uri string, in *ormapi.EmailRequest) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("PasswordResetRequest")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) PasswordReset(uri string, in *ormapi.PasswordReset) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("PasswordReset")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) CreateUserApiKey(uri string, token string, in *ormapi.CreateUserApiKey) (*ormapi.CreateUserApiKey, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out ormapi.CreateUserApiKey
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("CreateUserApiKey")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) DeleteUserApiKey(uri string, token string, in *ormapi.CreateUserApiKey) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("DeleteUserApiKey")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowUserApiKey(uri string, token string, in *ormapi.CreateUserApiKey) ([]ormapi.CreateUserApiKey, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []ormapi.CreateUserApiKey
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowUserApiKey")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

// Generating group VMPool

func (s *Client) CreateVMPool(uri string, token string, in *ormapi.RegionVMPool) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("CreateVMPool")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) DeleteVMPool(uri string, token string, in *ormapi.RegionVMPool) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("DeleteVMPool")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) UpdateVMPool(uri string, token string, in *ormapi.RegionVMPool) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	mm, err := ormutil.GetRegionObjStructMapForUpdate(in)
	if err != nil {
		return nil, 0, err
	}
	rundata.In = mm
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("UpdateVMPool")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowVMPool(uri string, token string, in *ormapi.RegionVMPool) ([]edgeproto.VMPool, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out []edgeproto.VMPool
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowVMPool")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) AddVMPoolMember(uri string, token string, in *ormapi.RegionVMPoolMember) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("AddVMPoolMember")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

func (s *Client) RemoveVMPoolMember(uri string, token string, in *ormapi.RegionVMPoolMember) (*edgeproto.Result, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out edgeproto.Result
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("RemoveVMPoolMember")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return &out, rundata.RetStatus, rundata.RetError
}

// Generating ungrouped

func (s *Client) AccessCloudletCli(uri string, token string, in *ormapi.RegionExecRequest) (string, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out string
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("AccessCloudletCli")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return "", rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) Login(uri string, in *ormapi.UserLogin) (map[string]interface{}, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.In = in
	var out map[string]interface{}
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("Login")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return nil, rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) RestrictedUpdateOrg(uri string, token string, in *cli.MapData) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("RestrictedUpdateOrg")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) RestrictedUpdateUser(uri string, token string, in *cli.MapData) (int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in

	apiCmd := ormctl.MustGetCommand("RestrictedUpdateUser")
	s.ClientRun.Run(apiCmd, &rundata)
	return rundata.RetStatus, rundata.RetError
}

func (s *Client) RunCommandCli(uri string, token string, in *ormapi.RegionExecRequest) (string, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out string
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("RunCommandCli")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return "", rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

func (s *Client) ShowLogsCli(uri string, token string, in *ormapi.RegionExecRequest) (string, int, error) {
	rundata := RunData{}
	rundata.Uri = uri
	rundata.Token = token
	rundata.In = in
	var out string
	rundata.Out = &out

	apiCmd := ormctl.MustGetCommand("ShowLogsCli")
	s.ClientRun.Run(apiCmd, &rundata)
	if rundata.RetError != nil {
		return "", rundata.RetStatus, rundata.RetError
	}
	return out, rundata.RetStatus, rundata.RetError
}

