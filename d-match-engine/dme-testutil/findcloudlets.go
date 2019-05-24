package dmetest

import dme "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"

type FindCloudletRR struct {
	Reg   dme.RegisterClientRequest
	Req   dme.FindCloudletRequest
	Reply dme.FindCloudletReply
}

// FindCloudlet API test data.
// Replies are based on AppInst data generated by GenerateAppInsts()
// in this package.
var FindCloudletData = []FindCloudletRR{
	FindCloudletRR{
		Reg: dme.RegisterClientRequest{
			DevName: "Untomt",
			AppName: "Untomt",
			AppVers: "1.1",
		},
		Req: dme.FindCloudletRequest{
			CarrierName: "GDDT",
			GpsLocation: &dme.Loc{Latitude: 50.65, Longitude: 6.341},
		},
		Reply: dme.FindCloudletReply{
			Fqdn:             Cloudlets[2].Uri,
			CloudletLocation: &Cloudlets[2].Location,
			Status:           1,
		},
	},
	FindCloudletRR{
		Reg: dme.RegisterClientRequest{
			DevName: "Untomt",
			AppName: "Untomt",
			AppVers: "1.1",
		},
		Req: dme.FindCloudletRequest{
			CarrierName: "GDDT",
			GpsLocation: &dme.Loc{Latitude: 51.65, Longitude: 9.341},
		},
		Reply: dme.FindCloudletReply{
			Fqdn:             Cloudlets[1].Uri,
			CloudletLocation: &Cloudlets[1].Location,
			Status:           1,
		},
	},
	FindCloudletRR{
		Reg: dme.RegisterClientRequest{
			DevName: "Untomt",
			AppName: "Untomt",
			AppVers: "1.1",
		}, // ATT does not exist and so should return default cloudlet
		Req: dme.FindCloudletRequest{
			CarrierName: "ATT",
			GpsLocation: &dme.Loc{Latitude: 52.65, Longitude: 10.341},
		},
		Reply: dme.FindCloudletReply{
			Fqdn:             Cloudlets[4].Uri,
			CloudletLocation: &Cloudlets[4].Location,
			Status:           1,
		},
	},
	FindCloudletRR{
		Reg: dme.RegisterClientRequest{
			DevName: "Untomt",
			AppName: "Untomt",
			AppVers: "1.1",
		},
		Req: dme.FindCloudletRequest{
			CarrierName: "GDDT",
			GpsLocation: &dme.Loc{Latitude: 50.75, Longitude: 7.9050},
		},
		Reply: dme.FindCloudletReply{
			Fqdn:             Cloudlets[2].Uri,
			CloudletLocation: &Cloudlets[2].Location,
			Status:           1,
		},
	},
	FindCloudletRR{
		Reg: dme.RegisterClientRequest{
			DevName: "Atlantic Labs",
			AppName: "Pillimo-go",
			AppVers: "2.1",
		},
		Req: dme.FindCloudletRequest{
			CarrierName: "GDDT",
			GpsLocation: &dme.Loc{Latitude: 52.75, Longitude: 12.9050},
		},
		Reply: dme.FindCloudletReply{
			Fqdn:             Cloudlets[1].Uri,
			CloudletLocation: &Cloudlets[1].Location,
			Status:           1,
		},
	},
	FindCloudletRR{
		Reg: dme.RegisterClientRequest{
			DevName: "Atlantic Labs",
			AppName: "HarryPotter-go",
			AppVers: "1.0",
		},
		Req: dme.FindCloudletRequest{
			CarrierName: "GDDT",
			GpsLocation: &dme.Loc{Latitude: 50.75, Longitude: 11.9050},
		},
		Reply: dme.FindCloudletReply{
			Fqdn:             Cloudlets[1].Uri,
			CloudletLocation: &Cloudlets[1].Location,
			Status:           1,
		},
	},
	FindCloudletRR{
		Reg: dme.RegisterClientRequest{
			DevName: "Ever.AI",
			AppName: "Ever",
			AppVers: "1.7",
		},
		Req: dme.FindCloudletRequest{
			CarrierName: "DMUUS",
			GpsLocation: &dme.Loc{Latitude: 47.75, Longitude: 122.9050},
		},
		Reply: dme.FindCloudletReply{
			Fqdn:             Cloudlets[3].Uri,
			CloudletLocation: &Cloudlets[3].Location,
			Status:           1,
		},
	},
}
