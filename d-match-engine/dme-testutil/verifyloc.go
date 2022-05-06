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

package dmetest

import dme "github.com/edgexr/edge-cloud/d-match-engine/dme-proto"

type VerifyLocRR struct {
	Reg   dme.RegisterClientRequest
	Req   dme.VerifyLocationRequest
	Reply dme.VerifyLocationReply
	Error string
}

const Unknown = dme.VerifyLocationReply_LOC_UNKNOWN
const Verified = dme.VerifyLocationReply_LOC_VERIFIED
const Mismatch = dme.VerifyLocationReply_LOC_MISMATCH_SAME_COUNTRY
const ErrorOther = dme.VerifyLocationReply_LOC_ERROR_OTHER

// VerifyLocation API test data.
// Replies are based on AppInst data generated by GenerateAppInsts()
// in this package.
var VerifyLocData = []VerifyLocRR{
	VerifyLocRR{
		Reg: dme.RegisterClientRequest{
			OrgName: "Untomt",
			AppName: "Untomt",
			AppVers: "1.1",
		},
		Req: dme.VerifyLocationRequest{
			GpsLocation: &dme.Loc{Latitude: 32.0139, Longitude: -96.598},
		},
		Reply: dme.VerifyLocationReply{
			GpsLocationStatus:     Verified,
			GpsLocationAccuracyKm: 2,
		},
	},
	VerifyLocRR{
		Reg: dme.RegisterClientRequest{
			OrgName: "Untomt",
			AppName: "Untomt",
			AppVers: "1.1",
		},
		Req: dme.VerifyLocationRequest{
			GpsLocation: &dme.Loc{Latitude: 32.747, Longitude: -97.095},
		},
		Reply: dme.VerifyLocationReply{
			GpsLocationStatus:     Verified,
			GpsLocationAccuracyKm: 100,
		},
	},
	VerifyLocRR{
		Reg: dme.RegisterClientRequest{
			OrgName: "Untomt",
			AppName: "Untomt",
			AppVers: "1.1",
		},
		Req: dme.VerifyLocationRequest{
			CarrierName: "ATT",
			GpsLocation: &dme.Loc{Latitude: 52.65, Longitude: 10.341},
		},
		Reply: dme.VerifyLocationReply{
			GpsLocationStatus:     Mismatch,
			GpsLocationAccuracyKm: -1,
		},
	},
	VerifyLocRR{
		Reg: dme.RegisterClientRequest{
			OrgName: "Untomt",
			AppName: "Untomt",
			AppVers: "1.1",
		},
		Req: dme.VerifyLocationRequest{
			CarrierName: "GDDT",
			GpsLocation: &dme.Loc{Latitude: 37.3382, Longitude: -121.886},
		},
		Reply: dme.VerifyLocationReply{
			GpsLocationStatus:     Mismatch,
			GpsLocationAccuracyKm: -1,
		},
	},
	VerifyLocRR{
		Reg: dme.RegisterClientRequest{
			OrgName: "Atlantic Labs",
			AppName: "Pillimo-go",
			AppVers: "2.1",
		},
		Req: dme.VerifyLocationRequest{
			GpsLocation: &dme.Loc{Latitude: 52.75, Longitude: 12.9050},
		},
		Reply: dme.VerifyLocationReply{
			GpsLocationStatus:     Mismatch,
			GpsLocationAccuracyKm: -1,
		},
	},
	VerifyLocRR{
		Reg: dme.RegisterClientRequest{
			OrgName: "Atlantic Labs",
			AppName: "HarryPotter-go",
			AppVers: "1.0",
		},
		Req: dme.VerifyLocationRequest{
			GpsLocation: &dme.Loc{Latitude: 50.75, Longitude: 11.9050},
		},
		Reply: dme.VerifyLocationReply{
			GpsLocationStatus:     Mismatch,
			GpsLocationAccuracyKm: -1,
		},
	},
	VerifyLocRR{
		Reg: dme.RegisterClientRequest{
			OrgName: "Ever.AI",
			AppName: "Ever",
			AppVers: "1.7",
		},
		Req: dme.VerifyLocationRequest{
			CarrierName: "DMUUS",
			GpsLocation: &dme.Loc{Latitude: 32.747, Longitude: -97.095},
		},
		Reply: dme.VerifyLocationReply{
			GpsLocationStatus:     Verified,
			GpsLocationAccuracyKm: 100,
		},
	},
}
