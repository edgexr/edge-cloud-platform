package client

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/jinzhu/gorm"
	"github.com/mobiledgex/edge-cloud-infra/mc/gormlog"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormutil"
	"github.com/mobiledgex/edge-cloud/edgeproto"
)

type FederationClient struct {
	ormapi.Federation
	Database *gorm.DB
}

func GetFederationIDFromCloudlet(cloudletName string) (int, error) {
	out := strings.Split(cloudletName, ".")
	if len(out) != 2 {
		// not a federated cloudlet
		return -1, nil
	}
	id, err := strconv.Atoi(out[1])
	if err != nil {
		return -1, err
	}

	return id, nil
}

func (f *FederationClient) loggedDB(ctx context.Context) *gorm.DB {
	return gormlog.LoggedDB(ctx, f.Database)
}

func GetFederationClient(ctx context.Context, database *gorm.DB, federationId int) (*FederationClient, bool, error) {
	// This client will abstract actions on partner federator's edge infra
	partnerFed := ormapi.Federation{
		Id: federationId,
	}
	db := gormlog.LoggedDB(ctx, database)
	res := db.Where(&partnerFed).First(&partnerFed)
	if res.Error != nil {
		if res.RecordNotFound() {
			// return empty object if not found
			return &FederationClient{}, false, nil
		}
		return nil, false, res.Error
	}

	fedClient := FederationClient{
		Database:   database,
		Federation: partnerFed,
	}
	return &fedClient, true, nil
}

// Get Federation Clients using region as CountryCode and optionally operator as OperatorId
func GetFederationClients(ctx context.Context, database *gorm.DB, region string, cloudletKey *edgeproto.CloudletKey) ([]FederationClient, error) {
	if region == "" {
		return nil, fmt.Errorf("no region specified")
	}
	if cloudletKey.Name != "" {
		federationId, err := GetFederationIDFromCloudlet(cloudletKey.Name)
		if err != nil {
			return nil, err
		}
		fedClient, _, err := GetFederationClient(ctx, database, federationId)
		if err != nil {
			return nil, err
		}
		return []FederationClient{*fedClient}, nil
	}
	// This client will abstract actions on partner federator's edge
	// infra. Hence, consider region as CountryCode
	partnerFed := ormapi.Federation{
		// Partner federator info
		Federator: ormapi.Federator{
			OperatorId:  cloudletKey.Organization,
			CountryCode: region,
		},
		// Only access those partner federators whose zones can be accessed by self federators
		PartnerRoleShareZonesWithSelf: true,
	}
	db := gormlog.LoggedDB(ctx, database)
	partnerFeds := []ormapi.Federation{}
	res := db.Where(&partnerFed).Find(&partnerFeds)
	if res.Error != nil {
		if res.RecordNotFound() {
			// return empty object if not found
			return []FederationClient{}, nil
		}
		return nil, res.Error
	}

	fedClients := []FederationClient{}
	for _, partnerFed := range partnerFeds {
		fedClient := FederationClient{
			Database:   database,
			Federation: partnerFed,
		}
		fedClients = append(fedClients, fedClient)
	}
	return fedClients, nil
}

func (f *FederationClient) ShowCloudletStream(ctx context.Context, rc *ormutil.RegionContext, obj *edgeproto.Cloudlet, cb func(res *edgeproto.Cloudlet) error) error {
	return nil
}
