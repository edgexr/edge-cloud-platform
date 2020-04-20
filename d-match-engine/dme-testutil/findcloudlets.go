package dmetest

import dme "github.com/mobiledgex/edge-cloud/d-match-engine/dme-proto"

type FindCloudletRR struct {
	Reg           dme.RegisterClientRequest
	Req           dme.FindCloudletRequest
	Reply         dme.FindCloudletReply
	ReplyCarrier  string
	ReplyCloudlet string
}

// FindCloudlet API test data.
// Replies are based on AppInst data generated by GenerateAppInsts()
// in this package.
var FindCloudletData = []FindCloudletRR{
	FindCloudletRR{
		Reg: dme.RegisterClientRequest{
			OrgName: "Untomt",
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
		ReplyCarrier:  Cloudlets[2].CarrierName,
		ReplyCloudlet: Cloudlets[2].Name,
	},
	FindCloudletRR{
		Reg: dme.RegisterClientRequest{
			OrgName:      "Untomt",
			AppName:      "Untomt",
			AppVers:      "1.1",
			UniqueId:     "123",
			UniqueIdType: "1000Realities",
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
		ReplyCarrier:  Cloudlets[1].CarrierName,
		ReplyCloudlet: Cloudlets[1].Name,
	},
	FindCloudletRR{
		Reg: dme.RegisterClientRequest{
			OrgName:      "Untomt",
			AppName:      "Untomt",
			AppVers:      "1.1",
			UniqueId:     "1234",
			UniqueIdType: "1000Realities",
		}, // ATT does not exist and so should return default cloudlet
		Req: dme.FindCloudletRequest{
			CarrierName: "ATT",
			GpsLocation: &dme.Loc{Latitude: 52.65, Longitude: 10.341},
		},
		Reply: dme.FindCloudletReply{
			Status: 2,
		},
	},
	FindCloudletRR{
		Reg: dme.RegisterClientRequest{
			OrgName: "Untomt",
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
		ReplyCarrier:  Cloudlets[2].CarrierName,
		ReplyCloudlet: Cloudlets[2].Name,
	},
	FindCloudletRR{
		Reg: dme.RegisterClientRequest{
			OrgName: "Atlantic Labs",
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
		ReplyCarrier:  Cloudlets[1].CarrierName,
		ReplyCloudlet: Cloudlets[1].Name,
	},
	FindCloudletRR{
		Reg: dme.RegisterClientRequest{
			OrgName: "Atlantic Labs",
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
		ReplyCarrier:  Cloudlets[1].CarrierName,
		ReplyCloudlet: Cloudlets[1].Name,
	},
	FindCloudletRR{
		Reg: dme.RegisterClientRequest{
			OrgName: "Ever.AI",
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
		ReplyCarrier:  Cloudlets[3].CarrierName,
		ReplyCloudlet: Cloudlets[3].Name,
	},
	FindCloudletRR{
		Reg: dme.RegisterClientRequest{
			OrgName: "Ever.AI",
			AppName: "Ever",
			AppVers: "1.7",
		},
		Req: dme.FindCloudletRequest{
			CarrierName: "",
			GpsLocation: &dme.Loc{Latitude: 47.75, Longitude: 122.9050},
		},
		Reply: dme.FindCloudletReply{
			Fqdn:             Cloudlets[3].Uri,
			CloudletLocation: &Cloudlets[3].Location,
			Status:           1,
		},
		ReplyCarrier:  Cloudlets[3].CarrierName,
		ReplyCloudlet: Cloudlets[3].Name,
	},
	FindCloudletRR{
		Reg: dme.RegisterClientRequest{
			OrgName: "Ever.AI",
			AppName: "Ever",
			AppVers: "1.7",
		},
		Req: dme.FindCloudletRequest{
			CarrierName: "",
			GpsLocation: &dme.Loc{Latitude: 48.31, Longitude: 11.66},
		},
		Reply: dme.FindCloudletReply{
			Fqdn:             Cloudlets[2].Uri,
			CloudletLocation: &Cloudlets[2].Location,
			Status:           1,
		},
		ReplyCarrier:  Cloudlets[2].CarrierName,
		ReplyCloudlet: Cloudlets[2].Name,
	},
}

// copy of FindCloudletData[3] with a changed reply to Sunnydale cloudlet
var DisabledCloudletRR = FindCloudletRR{
	Reg: dme.RegisterClientRequest{
		OrgName: "Untomt",
		AppName: "Untomt",
		AppVers: "1.1",
	},
	Req: dme.FindCloudletRequest{
		CarrierName: "GDDT",
		GpsLocation: &dme.Loc{Latitude: 50.75, Longitude: 7.9050},
	},
	Reply: dme.FindCloudletReply{
		Fqdn:             Cloudlets[1].Uri,
		CloudletLocation: &Cloudlets[1].Location,
		Status:           1,
	},
}
