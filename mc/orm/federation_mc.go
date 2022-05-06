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

package orm

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jinzhu/gorm"
	"github.com/labstack/echo"
	"github.com/edgexr/edge-cloud-infra/mc/ctrlclient"
	"github.com/edgexr/edge-cloud-infra/mc/federation"
	fedcommon "github.com/edgexr/edge-cloud-infra/mc/federation/common"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud-infra/mc/ormutil"
	fedmgmt "github.com/edgexr/edge-cloud/cloud-resource-manager/federationmgmt"
	"github.com/edgexr/edge-cloud/cloudcommon"
	dme_proto "github.com/edgexr/edge-cloud/d-match-engine/dme-proto"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/log"
)

func setForeignKeyConstraint(loggedDb *gorm.DB, fKeyTableName, fKeyFields, refTableName, refFields string) error {
	cmd := fmt.Sprintf("ALTER TABLE %s ADD CONSTRAINT self_fk_constraint FOREIGN KEY (%s) "+
		"REFERENCES %s(%s)", fKeyTableName, fKeyFields, refTableName, refFields)
	err := loggedDb.Exec(cmd).Error
	if err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			return err
		}
	}
	return nil
}

func InitFederationAPIConstraints(loggedDb *gorm.DB) error {
	// setup foreign key constraints, this is done separately here as gorm doesn't
	// support referencing composite primary key inline to the model

	// Federation's SelfFederationId references Federator's FederationId
	scope := loggedDb.Unscoped().NewScope(&ormapi.Federation{})
	fKeyTableName := scope.TableName()
	fKeyFields := fmt.Sprintf("%s", scope.Quote("self_federation_id"))

	scope = loggedDb.Unscoped().NewScope(&ormapi.Federator{})
	refTableName := scope.TableName()
	refFields := fmt.Sprintf("%s", scope.Quote("federation_id"))
	err := setForeignKeyConstraint(loggedDb, fKeyTableName, fKeyFields, refTableName, refFields)
	if err != nil {
		return err
	}

	// Add unique constraint for partner federation ID
	cmd := `ALTER TABLE IF EXISTS "federations" ADD UNIQUE ("federation_id")`
	err = loggedDb.Exec(cmd).Error
	if err != nil {
		return err
	}

	// Federator's OperatorId references Organization's Name
	scope = loggedDb.Unscoped().NewScope(&ormapi.Federator{})
	fKeyTableName = scope.TableName()
	fKeyFields = fmt.Sprintf("%s", scope.Quote("operator_id"))

	scope = loggedDb.Unscoped().NewScope(&ormapi.Organization{})
	refTableName = scope.TableName()
	refFields = fmt.Sprintf("%s", scope.Quote("name"))
	err = setForeignKeyConstraint(loggedDb, fKeyTableName, fKeyFields, refTableName, refFields)
	if err != nil {
		return err
	}

	// FederatorZone's OperatorId references Organization's Name
	scope = loggedDb.Unscoped().NewScope(&ormapi.FederatorZone{})
	fKeyTableName = scope.TableName()
	fKeyFields = fmt.Sprintf("%s", scope.Quote("operator_id"))

	scope = loggedDb.Unscoped().NewScope(&ormapi.Organization{})
	refTableName = scope.TableName()
	refFields = fmt.Sprintf("%s", scope.Quote("name"))
	err = setForeignKeyConstraint(loggedDb, fKeyTableName, fKeyFields, refTableName, refFields)
	if err != nil {
		return err
	}

	// FederatedSelfZone's FederationName references
	//   Federation's Name
	scope = loggedDb.Unscoped().NewScope(&ormapi.FederatedSelfZone{})
	fKeyTableName = scope.TableName()
	fKeyFields = fmt.Sprintf("%s", scope.Quote("federation_name"))

	scope = loggedDb.Unscoped().NewScope(&ormapi.Federation{})
	refTableName = scope.TableName()
	refFields = fmt.Sprintf("%s", scope.Quote("name"))
	err = setForeignKeyConstraint(loggedDb, fKeyTableName, fKeyFields, refTableName, refFields)
	if err != nil {
		return err
	}

	// FederatedPartnerZone's FederationName references
	//   Federation's Name
	scope = loggedDb.Unscoped().NewScope(&ormapi.FederatedPartnerZone{})
	fKeyTableName = scope.TableName()
	fKeyFields = fmt.Sprintf("%s", scope.Quote("federation_name"))

	scope = loggedDb.Unscoped().NewScope(&ormapi.Federation{})
	refTableName = scope.TableName()
	refFields = fmt.Sprintf("%s", scope.Quote("name"))
	err = setForeignKeyConstraint(loggedDb, fKeyTableName, fKeyFields, refTableName, refFields)
	if err != nil {
		return err
	}

	return nil
}

func fedAuthorized(ctx context.Context, username, operatorId string) error {
	if operatorId == "" {
		return fmt.Errorf("Missing self operator ID")
	}
	return authorized(ctx, username, operatorId, ResourceCloudlets, ActionManage, withRequiresOrg(operatorId))
}

func GetSelfFederator(ctx context.Context, operatorId, federationId string) (*ormapi.Federator, error) {
	if federationId == "" {
		return nil, fmt.Errorf("Missing self federation ID")
	}
	db := loggedDB(ctx)
	fedObj := ormapi.Federator{
		FederationId: federationId,
		OperatorId:   operatorId,
	}
	res := db.Where(&fedObj).First(&fedObj)
	if res.RecordNotFound() {
		return nil, fmt.Errorf("Self federator with ID %q does not exist for operator %q", federationId, operatorId)
	}
	if res.Error != nil {
		return nil, ormutil.DbErr(res.Error)
	}
	return &fedObj, nil
}

func GetFederationById(ctx context.Context, selfFederationId string) (bool, *ormapi.Federation, error) {
	if selfFederationId == "" {
		return false, nil, fmt.Errorf("Missing self federation ID %q", selfFederationId)
	}

	db := loggedDB(ctx)
	partnerLookup := ormapi.Federation{
		SelfFederationId: selfFederationId,
	}
	partnerFed := ormapi.Federation{}
	res := db.Where(&partnerLookup).First(&partnerFed)
	if !res.RecordNotFound() && res.Error != nil {
		return false, nil, ormutil.DbErr(res.Error)
	}
	if res.RecordNotFound() {
		return false, &ormapi.Federation{}, nil
	}

	return true, &partnerFed, nil
}

func GetFederationByName(ctx context.Context, operatorId, name string) (*ormapi.Federator, *ormapi.Federation, error) {
	if name == "" {
		return nil, nil, fmt.Errorf("Missing federation name %q", name)
	}

	db := loggedDB(ctx)
	fed := ormapi.Federation{
		Name:           name,
		SelfOperatorId: operatorId,
	}
	res := db.Where(&fed).First(&fed)
	if !res.RecordNotFound() && res.Error != nil {
		return nil, nil, ormutil.DbErr(res.Error)
	}
	if res.RecordNotFound() {
		return nil, nil, fmt.Errorf("Federation with name %q does not exist for self operator ID %q", name, operatorId)
	}

	selfFed := ormapi.Federator{
		FederationId: fed.SelfFederationId,
		OperatorId:   operatorId,
	}
	res = db.Where(&selfFed).First(&selfFed)
	if !res.RecordNotFound() && res.Error != nil {
		return nil, nil, ormutil.DbErr(res.Error)
	}
	if res.RecordNotFound() {
		return nil, nil, fmt.Errorf("Self federator with ID %q does not exist for operator %q", fed.SelfFederationId, operatorId)
	}

	return &selfFed, &fed, nil
}

// Create self federator for an operator labelled by a country code
func CreateSelfFederator(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	opFed := ormapi.Federator{}
	if err := c.Bind(&opFed); err != nil {
		return ormutil.BindErr(err)
	}
	span := log.SpanFromContext(ctx)
	log.SetTags(span, opFed.GetTags())
	// sanity check
	if opFed.OperatorId == "" {
		return fmt.Errorf("Missing Operator ID")
	}
	if opFed.CountryCode == "" {
		return fmt.Errorf("Missing country code")
	}
	if opFed.Region == "" {
		return fmt.Errorf("Missing region")
	}
	if opFed.MCC == "" {
		return fmt.Errorf("Missing MCC")
	}
	if len(opFed.MNC) == 0 {
		return fmt.Errorf("Missing MNCs. Please specify one or more MNCs")
	}
	if _, err := getControllerObj(ctx, opFed.Region); err != nil {
		return err
	}
	if err := fedcommon.ValidateCountryCode(opFed.CountryCode); err != nil {
		return err
	}
	if err := fedAuthorized(ctx, claims.Username, opFed.OperatorId); err != nil {
		return err
	}
	// ensure that operator ID is a valid operator org
	org, err := orgExists(ctx, opFed.OperatorId)
	if err != nil {
		return fmt.Errorf("Invalid operator ID specified")
	}
	if org.Type != OrgTypeOperator {
		return fmt.Errorf("Invalid operator ID, must be a valid operator org")
	}

	db := loggedDB(ctx)
	if opFed.FederationId == "" {
		opFed.FederationId = uuid.New().String()
	} else {
		if err := fedcommon.ValidateFederationId(opFed.FederationId); err != nil {
			return err
		}
	}
	opFed.FederationAddr = serverConfig.FederationAddr
	opFed.Revision = log.SpanTraceID(ctx)

	// auto-create api key
	apiKey := uuid.New().String()
	apiKeyHash, apiKeySalt, apiKeyIter := ormutil.NewPasshash(apiKey)
	opFed.ApiKeyHash = apiKeyHash
	opFed.Salt = apiKeySalt
	opFed.Iter = apiKeyIter

	if err := db.Create(&opFed).Error; err != nil {
		if strings.Contains(err.Error(), "pq: duplicate key value violates unique constraint") {
			return fmt.Errorf("Self federator with ID %q already exists", opFed.FederationId)
		}
		return ormutil.DbErr(err)
	}

	opFedOut := ormapi.Federator{
		OperatorId:     opFed.OperatorId,
		CountryCode:    opFed.CountryCode,
		FederationId:   opFed.FederationId,
		FederationAddr: opFed.FederationAddr,
		ApiKey:         apiKey,
	}
	return c.JSON(http.StatusOK, &opFedOut)
}

// Update self federator attributes and notify associated
// partner federators who have access to self federator zones
func UpdateSelfFederator(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	opFed := ormapi.Federator{}
	if err := c.Bind(&opFed); err != nil {
		return ormutil.BindErr(err)
	}
	span := log.SpanFromContext(ctx)
	log.SetTags(span, opFed.GetTags())

	// get self federator information
	selfFed, err := GetSelfFederator(ctx, opFed.OperatorId, opFed.FederationId)
	if err != nil {
		return err
	}
	span.SetTag("region", selfFed.Region)
	if err := fedAuthorized(ctx, claims.Username, opFed.OperatorId); err != nil {
		return err
	}

	db := loggedDB(ctx)

	update := false
	if opFed.MCC != selfFed.MCC {
		update = true
		selfFed.MCC = opFed.MCC
	}
	curMNCs := selfFed.MNC
	if len(curMNCs) != len(opFed.MNC) {
		update = true
		selfFed.MNC = opFed.MNC
	} else {
		newMNCsMap := make(map[string]struct{})
		for _, nm := range opFed.MNC {
			newMNCsMap[nm] = struct{}{}
		}
		for _, cm := range curMNCs {
			if _, ok := newMNCsMap[cm]; !ok {
				update = true
				selfFed.MNC = opFed.MNC
				break
			}
		}
	}
	if opFed.LocatorEndPoint != selfFed.LocatorEndPoint {
		update = true
		selfFed.LocatorEndPoint = opFed.LocatorEndPoint
	}
	if !update {
		return fmt.Errorf("nothing to update")
	}
	selfFed.Revision = log.SpanTraceID(ctx)
	err = db.Save(selfFed).Error
	if err != nil {
		return ormutil.DbErr(err)
	}

	// Notify partner federator who have access to self zones
	partnerFedExists, partnerFed, err := GetFederationById(ctx, selfFed.FederationId)
	if err != nil {
		return err
	}
	errOut := ""
	if partnerFedExists &&
		(partnerFed.PartnerRoleAccessToSelfZones ||
			partnerFed.PartnerRoleShareZonesWithSelf) {
		opConf := federation.UpdateMECNetConf{
			RequestId:        selfFed.Revision,
			OrigFederationId: selfFed.FederationId,
			DestFederationId: partnerFed.FederationId,
			Operator:         selfFed.OperatorId,
			Country:          selfFed.CountryCode,
			MCC:              selfFed.MCC,
			MNC:              selfFed.MNC,
			LocatorEndPoint:  selfFed.LocatorEndPoint,
		}
		err = fedClient.SendRequest(ctx, "PUT", partnerFed.FederationAddr, partnerFed.Name, federation.APIKeyFromVault, federation.OperatorPartnerAPI, &opConf, nil)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "Failed to update partner federator", "federation name", partnerFed.Name, "error", err)
			errOut = fmt.Sprintf(". But failed to update partner federation %q, err: %v", partnerFed.Name, err)
		}
	}

	return ormutil.SetReply(c, ormutil.Msg(
		fmt.Sprintf("Updated self federator attributes%s", errOut)))
}

// Delete self federator, given that there are no more
// partner federators associated with it
func DeleteSelfFederator(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	opFed := ormapi.Federator{}
	if err := c.Bind(&opFed); err != nil {
		return ormutil.BindErr(err)
	}
	span := log.SpanFromContext(ctx)
	log.SetTags(span, opFed.GetTags())
	// get federator information
	selfFed, err := GetSelfFederator(ctx, opFed.OperatorId, opFed.FederationId)
	if err != nil {
		return err
	}
	span.SetTag("region", opFed.Region)
	if err := fedAuthorized(ctx, claims.Username, opFed.OperatorId); err != nil {
		return err
	}

	db := loggedDB(ctx)

	// Ensure that there is no partner federation associated with
	// self federator. This also ensures that none of partner zones
	// are in use by self federator
	partnerLookup := ormapi.Federation{
		SelfFederationId: opFed.FederationId,
	}
	partnerFed := ormapi.Federation{}
	res := db.Where(&partnerLookup).First(&partnerFed)
	if !res.RecordNotFound() && res.Error != nil {
		return ormutil.DbErr(res.Error)
	}
	if !res.RecordNotFound() {
		return fmt.Errorf("Failed to delete self federator. Please delete existing federation %q", partnerFed.Name)
	}

	if err := db.Delete(&selfFed).Error; err != nil {
		return ormutil.DbErr(err)
	}

	return ormutil.SetReply(c, ormutil.Msg("Deleted self federator successfully"))
}

// Fields to ignore for ShowSelfFederator/ShowFederation filtering. Names are in database format.
var FederatorIgnoreFilterKeys = []string{
	"salt",
	"iter",
	"api_key",
	"api_key_hash",
	"mnc", // ignore array field
}

func ShowSelfFederator(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	filter, err := bindDbFilter(c, &ormapi.Federator{})
	if err != nil {
		return err
	}
	// prevent filtering output on sensitive data
	for _, name := range FederatorIgnoreFilterKeys {
		delete(filter, name)
	}

	authz, err := newShowAuthz(ctx, "", claims.Username, ResourceCloudlets, ActionView)
	if err != nil {
		return err
	}

	db := loggedDB(ctx)
	feds := []ormapi.Federator{}
	res := db.Where(filter).Find(&feds)
	if !res.RecordNotFound() && res.Error != nil {
		return ormutil.DbErr(res.Error)
	}
	out := []ormapi.Federator{}
	for _, fed := range feds {
		if !authz.Ok(fed.OperatorId) {
			continue
		}
		fed.ApiKeyHash = ""
		fed.Salt = ""
		fed.Iter = 0
		out = append(out, fed)
	}
	return c.JSON(http.StatusOK, out)
}

func orgInUseByFederatorCheck(ctx context.Context, orgName string) error {
	db := loggedDB(ctx)

	lookup := ormapi.Federator{
		OperatorId: orgName,
	}
	out := []ormapi.Federator{}
	res := db.Where(&lookup).Find(&out)
	if !res.RecordNotFound() && res.Error != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "failed to get federator details", "err", res.Error)
		return res.Error
	}
	if res.RecordNotFound() || len(out) == 0 {
		return nil
	}
	return fmt.Errorf("Organization is in use by federator")
}

func GenerateSelfFederatorAPIKey(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	opFed := ormapi.Federator{}
	if err := c.Bind(&opFed); err != nil {
		return ormutil.BindErr(err)
	}
	// get federator information
	selfFed, err := GetSelfFederator(ctx, opFed.OperatorId, opFed.FederationId)
	if err != nil {
		return err
	}
	span := log.SpanFromContext(ctx)
	log.SetTags(span, opFed.GetTags())
	if err := fedAuthorized(ctx, claims.Username, opFed.OperatorId); err != nil {
		return err
	}

	db := loggedDB(ctx)
	// generate new api key, this will invalidate old API key
	apiKey := uuid.New().String()
	apiKeyHash, apiKeySalt, apiKeyIter := ormutil.NewPasshash(apiKey)
	selfFed.ApiKeyHash = apiKeyHash
	selfFed.Salt = apiKeySalt
	selfFed.Iter = apiKeyIter
	err = db.Save(&selfFed).Error
	if err != nil {
		return ormutil.DbErr(err)
	}

	apiKeyOut := ormapi.Federator{
		ApiKey: apiKey,
	}
	return c.JSON(http.StatusOK, &apiKeyOut)
}

// A self federator will create a partner federator. This is done as
// part of federation planning. This does not form federation with
// partner federator
func CreateFederation(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	opFed := ormapi.Federation{}
	if err := c.Bind(&opFed); err != nil {
		return ormutil.BindErr(err)
	}
	span := log.SpanFromContext(ctx)
	log.SetTags(span, opFed.GetTags())
	// sanity check
	if opFed.Name == "" {
		return fmt.Errorf("Missing federation name")
	}
	if opFed.SelfFederationId == "" {
		return fmt.Errorf("Missing self federation ID")
	}
	if opFed.OperatorId == "" {
		return fmt.Errorf("Missing partner operator ID")
	}
	if opFed.CountryCode == "" {
		return fmt.Errorf("Missing partner country code")
	}
	if opFed.FederationId == "" {
		return fmt.Errorf("Missing partner federation ID")
	}
	if opFed.FederationAddr == "" {
		return fmt.Errorf("Missing partner federation access address")
	}
	if opFed.ApiKey == "" {
		return fmt.Errorf("Missing partner federation API key")
	}
	if err := fedcommon.ValidateFederationName(opFed.Name); err != nil {
		return err
	}
	if err := fedcommon.ValidateFederationId(opFed.FederationId); err != nil {
		return err
	}
	if err := fedcommon.ValidateCountryCode(opFed.CountryCode); err != nil {
		return err
	}

	// validate self federator
	selfFed, err := GetSelfFederator(ctx, opFed.SelfOperatorId, opFed.SelfFederationId)
	if err != nil {
		return err
	}
	span.SetTag("region", selfFed.Region)
	if err := fedAuthorized(ctx, claims.Username, opFed.SelfOperatorId); err != nil {
		return err
	}

	// store partner federator's API key in vault
	partnerApiKey := opFed.ApiKey
	opFed.ApiKey = ""

	db := loggedDB(ctx)
	opFed.Revision = log.SpanTraceID(ctx)
	if err := db.Create(&opFed).Error; err != nil {
		if strings.Contains(err.Error(), "pq: duplicate key value violates unique constraint") {
			if strings.Contains(err.Error(), "federations_self_federation_id_key") {
				return fmt.Errorf("Partner federation with same self federation id %q already exists", opFed.SelfFederationId)
			}
			if strings.Contains(err.Error(), "federations_name_key") {
				return fmt.Errorf("Partner federation %q already exists", opFed.Name)
			}
			if strings.Contains(err.Error(), "\"federations_federation_id_key\"") {
				return fmt.Errorf("Partner federation with same federation id %q already exists", opFed.FederationId)
			}
			return fmt.Errorf("Partner federation with same federation id pair already exists")
		}
		return ormutil.DbErr(err)
	}

	if partnerApiKey != "" {
		log.SpanLog(ctx, log.DebugLevelApi, "Storing partner federation API key in vault", "federation name", opFed.Name)
		err = fedmgmt.PutAPIKeyToVault(ctx, serverConfig.vaultConfig, opFed.Name, partnerApiKey)
		if err != nil {
			return err
		}
	}

	return ormutil.SetReply(c, ormutil.Msg("Created partner federation successfully"))
}

func DeleteFederation(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	opFed := ormapi.Federation{}
	if err := c.Bind(&opFed); err != nil {
		return ormutil.BindErr(err)
	}
	span := log.SpanFromContext(ctx)
	log.SetTags(span, opFed.GetTags())
	if err := fedAuthorized(ctx, claims.Username, opFed.SelfOperatorId); err != nil {
		return err
	}
	_, partnerFed, err := GetFederationByName(ctx, opFed.SelfOperatorId, opFed.Name)
	if err != nil {
		return err
	}

	// check if federation with partner federator exists
	db := loggedDB(ctx)
	if partnerFed.PartnerRoleShareZonesWithSelf || partnerFed.PartnerRoleAccessToSelfZones {
		return fmt.Errorf("Cannot delete federation %q as it is registered", partnerFed.Name)
	}

	// Delete partner federator
	if err := db.Delete(partnerFed).Error; err != nil {
		if strings.Contains(err.Error(), "violates foreign key constraint \"self_fk_constraint\" on table \"federated_self_zones\"") {
			return fmt.Errorf("Please unshare self zones before deleting federation")
		}
		return ormutil.DbErr(err)
	}

	// Delete partner API key
	log.SpanLog(ctx, log.DebugLevelApi, "Deleting partner federation API key from vault", "federation name", opFed.Name)
	err = fedmgmt.DeleteAPIKeyFromVault(ctx, serverConfig.vaultConfig, partnerFed.Name)
	log.SpanLog(ctx, log.DebugLevelApi, "Failed to delete API key from vault", "err", err)

	return ormutil.SetReply(c, ormutil.Msg("Deleted partner federation successfully"))
}

func SetPartnerFederationAPIKey(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	opFed := ormapi.Federation{}
	if err := c.Bind(&opFed); err != nil {
		return ormutil.BindErr(err)
	}
	span := log.SpanFromContext(ctx)
	log.SetTags(span, opFed.GetTags())
	if err := fedAuthorized(ctx, claims.Username, opFed.SelfOperatorId); err != nil {
		return err
	}
	_, _, err = GetFederationByName(ctx, opFed.SelfOperatorId, opFed.Name)
	if err != nil {
		return err
	}

	if opFed.ApiKey == "" {
		return fmt.Errorf("nothing to update")
	}

	if err := fedcommon.ValidateApiKey(opFed.ApiKey); err != nil {
		return err
	}

	// allow update of API key in case partner federator regenerates it
	log.SpanLog(ctx, log.DebugLevelApi, "Storing partner federation API key in vault", "federation name", opFed.Name)
	err = fedmgmt.PutAPIKeyToVault(ctx, serverConfig.vaultConfig, opFed.Name, opFed.ApiKey)
	if err != nil {
		return err
	}
	return ormutil.SetReply(c, ormutil.Msg("Updated federation attributes"))
}

func CreateSelfFederatorZone(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	opZone := ormapi.FederatorZone{}
	if err := c.Bind(&opZone); err != nil {
		return ormutil.BindErr(err)
	}

	span := log.SpanFromContext(ctx)
	log.SetTags(span, opZone.GetTags())

	// sanity check
	if opZone.ZoneId == "" {
		return fmt.Errorf("Missing zone ID")
	}
	if opZone.OperatorId == "" {
		return fmt.Errorf("Missing operator ID")
	}
	if opZone.Region == "" {
		return fmt.Errorf("Missing region")
	}
	if len(opZone.Cloudlets) == 0 {
		return fmt.Errorf("Missing cloudlets")
	}
	if len(opZone.Cloudlets) > 1 {
		return fmt.Errorf("Only one cloudlet supported for now")
	}
	if err := fedcommon.ValidateZoneId(opZone.ZoneId); err != nil {
		return err
	}
	if _, _, err := fedcommon.ParseGeoLocation(opZone.GeoLocation); err != nil {
		return err
	}
	if _, err := getControllerObj(ctx, opZone.Region); err != nil {
		return err
	}
	if err := fedcommon.ValidateCountryCode(opZone.CountryCode); err != nil {
		return err
	}
	if err := fedAuthorized(ctx, claims.Username, opZone.OperatorId); err != nil {
		return err
	}
	// ensure that operator ID is a valid operator org
	org, err := orgExists(ctx, opZone.OperatorId)
	if err != nil {
		return fmt.Errorf("Invalid operator ID specified")
	}
	if org.Type != OrgTypeOperator {
		return fmt.Errorf("Invalid operator ID, must be a valid operator org")
	}
	db := loggedDB(ctx)
	lookup := ormapi.FederatorZone{
		ZoneId: opZone.ZoneId,
	}
	existingFed := ormapi.FederatorZone{}
	res := db.Where(&lookup).First(&existingFed)
	if !res.RecordNotFound() && res.Error != nil {
		return ormutil.DbErr(res.Error)
	}
	if existingFed.ZoneId != "" {
		return fmt.Errorf("Zone %q already exists", opZone.ZoneId)
	}

	rc := ormutil.RegionContext{
		Region:    opZone.Region,
		Username:  claims.Username,
		SkipAuthz: true,
		Database:  database,
	}
	cloudletMap := make(map[string]edgeproto.Cloudlet)
	cloudletLookup := edgeproto.Cloudlet{
		Key: edgeproto.CloudletKey{
			Organization: opZone.OperatorId,
		},
	}
	err = ctrlclient.ShowCloudletStream(ctx, &rc, &cloudletLookup, connCache, nil, func(cloudlet *edgeproto.Cloudlet) error {
		cloudletMap[cloudlet.Key.Name] = *cloudlet
		return nil
	})
	if err != nil {
		return err
	}
	for _, cl := range opZone.Cloudlets {
		if _, ok := cloudletMap[cl]; !ok {
			return fmt.Errorf("Cloudlet %q doesn't exist", cl)
		}
	}

	az := ormapi.FederatorZone{}
	az.OperatorId = opZone.OperatorId
	az.CountryCode = opZone.CountryCode
	az.ZoneId = opZone.ZoneId
	az.GeoLocation = opZone.GeoLocation
	az.City = opZone.City
	az.State = opZone.State
	az.Locality = opZone.Locality
	az.Region = opZone.Region
	az.Cloudlets = opZone.Cloudlets
	az.Revision = log.SpanTraceID(ctx)
	if err := db.Create(&az).Error; err != nil {
		if strings.Contains(err.Error(), "pq: duplicate key value violates unique constraint") {
			return fmt.Errorf("Zone with same zone ID %q already exists",
				az.ZoneId)
		}
		return ormutil.DbErr(err)
	}

	return ormutil.SetReply(c, ormutil.Msg("Created zone successfully"))
}

func DeleteSelfFederatorZone(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	opZone := ormapi.FederatorZone{}
	if err := c.Bind(&opZone); err != nil {
		return ormutil.BindErr(err)
	}

	span := log.SpanFromContext(ctx)
	log.SetTags(span, opZone.GetTags())

	// sanity check
	if opZone.ZoneId == "" {
		return fmt.Errorf("Missing zone ID")
	}
	if opZone.OperatorId == "" {
		return fmt.Errorf("Missing operator ID")
	}
	if err := fedAuthorized(ctx, claims.Username, opZone.OperatorId); err != nil {
		return err
	}
	db := loggedDB(ctx)
	lookup := ormapi.FederatorZone{
		ZoneId:      opZone.ZoneId,
		OperatorId:  opZone.OperatorId,
		CountryCode: opZone.CountryCode,
	}
	existingZone := ormapi.FederatorZone{}
	res := db.Where(&lookup).First(&existingZone)
	if !res.RecordNotFound() && res.Error != nil {
		return ormutil.DbErr(res.Error)
	}
	if res.RecordNotFound() {
		return fmt.Errorf("Zone %s does not exist", opZone.ZoneId)
	}

	// ensure that self federator zone is not shared/registered as part of federation
	shLookup := ormapi.FederatedSelfZone{
		ZoneId: opZone.ZoneId,
	}
	shZones := []ormapi.FederatedSelfZone{}
	res = db.Where(&shLookup).Find(&shZones)
	if !res.RecordNotFound() && res.Error != nil {
		return ormutil.DbErr(res.Error)
	}
	if len(shZones) > 0 {
		return fmt.Errorf("Cannot delete zone %q as it is shared as part of federation."+
			" Please unshare it before deleting it", opZone.ZoneId)
	}

	if err := db.Delete(&existingZone).Error; err != nil {
		return ormutil.DbErr(err)
	}

	return ormutil.SetReply(c, ormutil.Msg("Deleted federator zone successfully"))
}

// Fields to ignore for ShowSelfFederatorZone/ShowFederatedPartnerZone
// filtering. Names are in database format.
var FederatorZoneIgnoreFilterKeys = []string{
	"cloudlets", // ignore array field
}

func ShowSelfFederatorZone(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	filter, err := bindDbFilter(c, &ormapi.FederatorZone{})
	if err != nil {
		return err
	}
	// prevent filtering output on special fields
	for _, name := range FederatorZoneIgnoreFilterKeys {
		delete(filter, name)
	}
	authz, err := newShowAuthz(ctx, "", claims.Username, ResourceCloudlets, ActionView)
	if err != nil {
		return err
	}
	db := loggedDB(ctx)
	opZones := []ormapi.FederatorZone{}
	res := db.Where(filter).Find(&opZones)
	if !res.RecordNotFound() && res.Error != nil {
		return ormutil.DbErr(res.Error)
	}
	out := []ormapi.FederatorZone{}
	for _, opZone := range opZones {
		if !authz.Ok(opZone.OperatorId) {
			continue
		}
		out = append(out, opZone)
	}

	return c.JSON(http.StatusOK, out)
}

func ShowFederatedSelfZone(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	filter, err := bindDbFilter(c, &ormapi.FederatedSelfZone{})
	if err != nil {
		return err
	}
	authz, err := newShowAuthz(ctx, "", claims.Username, ResourceCloudlets, ActionView)
	if err != nil {
		return err
	}
	db := loggedDB(ctx)
	opZones := []ormapi.FederatedSelfZone{}
	res := db.Where(filter).Find(&opZones)
	if !res.RecordNotFound() && res.Error != nil {
		return ormutil.DbErr(res.Error)
	}
	out := []ormapi.FederatedSelfZone{}
	for _, zone := range opZones {
		if !authz.Ok(zone.SelfOperatorId) {
			continue
		}
		out = append(out, zone)
	}

	return c.JSON(http.StatusOK, out)
}

func ShowFederatedPartnerZone(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	filter, err := bindDbFilter(c, &ormapi.FederatedPartnerZone{})
	if err != nil {
		return err
	}
	// prevent filtering output on special fields
	for _, name := range FederatorZoneIgnoreFilterKeys {
		delete(filter, name)
	}
	authz, err := newShowAuthz(ctx, "", claims.Username, ResourceCloudlets, ActionView)
	if err != nil {
		return err
	}
	db := loggedDB(ctx)
	opZones := []ormapi.FederatedPartnerZone{}
	res := db.Where(filter).Find(&opZones)
	if !res.RecordNotFound() && res.Error != nil {
		return ormutil.DbErr(res.Error)
	}
	out := []ormapi.FederatedPartnerZone{}
	for _, zone := range opZones {
		if !authz.Ok(zone.SelfOperatorId) {
			continue
		}
		out = append(out, zone)
	}

	return c.JSON(http.StatusOK, out)
}

func ShareSelfFederatorZone(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	shZone := ormapi.FederatedSelfZone{}
	if err := c.Bind(&shZone); err != nil {
		return ormutil.BindErr(err)
	}

	span := log.SpanFromContext(ctx)
	log.SetTags(span, shZone.GetTags())

	// sanity check
	if shZone.ZoneId == "" {
		return fmt.Errorf("Must specify the zone which is to be shared")
	}

	if err := fedAuthorized(ctx, claims.Username, shZone.SelfOperatorId); err != nil {
		return err
	}

	selfFed, partnerFed, err := GetFederationByName(ctx, shZone.SelfOperatorId, shZone.FederationName)
	if err != nil {
		return err
	}

	// Check if zone exists
	db := loggedDB(ctx)
	lookup := ormapi.FederatorZone{
		ZoneId:      shZone.ZoneId,
		OperatorId:  selfFed.OperatorId,
		CountryCode: selfFed.CountryCode,
	}
	existingZone := ormapi.FederatorZone{}
	res := db.Where(&lookup).First(&existingZone)
	if !res.RecordNotFound() && res.Error != nil {
		return ormutil.DbErr(res.Error)
	}
	if res.RecordNotFound() {
		return fmt.Errorf("Zone ID %q not found for operatorID:%q/countrycode:%q", shZone.ZoneId, selfFed.OperatorId, selfFed.CountryCode)
	}

	// ensure that zone is part of the same region as federator
	if existingZone.Region != selfFed.Region {
		return fmt.Errorf("Only zones of region %q can be shared as part of federation %q", selfFed.Region, partnerFed.Name)
	}

	revision := log.SpanTraceID(ctx)

	// Only share with those partner federators who are permitted to access our zones
	// And only share if federation exists with partner federator, else
	// just add it to the DB (federation planning)
	if partnerFed.PartnerRoleAccessToSelfZones {
		opZoneShare := federation.NotifyPartnerOperatorZone{
			RequestId:        revision,
			OrigFederationId: selfFed.FederationId,
			DestFederationId: partnerFed.FederationId,
			Operator:         selfFed.OperatorId,
			Country:          selfFed.CountryCode,
			PartnerZone: federation.ZoneInfo{
				ZoneId:      existingZone.ZoneId,
				GeoLocation: existingZone.GeoLocation,
				City:        existingZone.City,
				State:       existingZone.State,
				Locality:    existingZone.Locality,
				EdgeCount:   len(existingZone.Cloudlets),
			},
		}
		err = fedClient.SendRequest(ctx, "POST", partnerFed.FederationAddr, partnerFed.Name, federation.APIKeyFromVault, federation.OperatorNotifyZoneAPI, &opZoneShare, nil)
		if err != nil {
			return err
		}
	}

	// Mark zone as shared in DB
	shareZone := ormapi.FederatedSelfZone{
		ZoneId:         existingZone.ZoneId,
		SelfOperatorId: selfFed.OperatorId,
		FederationName: partnerFed.Name,
		Revision:       revision,
	}
	if err := db.Create(&shareZone).Error; err != nil {
		if !strings.Contains(err.Error(), "pq: duplicate key value violates unique constraint") {
			return ormutil.DbErr(err)
		}
	}
	return ormutil.SetReply(c, ormutil.Msg(
		fmt.Sprintf("Zone %q shared as part of federation %q successfully",
			shareZone.ZoneId, partnerFed.Name)))
}

func UnshareSelfFederatorZone(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	unshZone := ormapi.FederatedSelfZone{}
	if err := c.Bind(&unshZone); err != nil {
		return ormutil.BindErr(err)
	}

	span := log.SpanFromContext(ctx)
	log.SetTags(span, unshZone.GetTags())

	// sanity check
	if unshZone.ZoneId == "" {
		return fmt.Errorf("Must specify the zone which is to be unshared")
	}

	if err := fedAuthorized(ctx, claims.Username, unshZone.SelfOperatorId); err != nil {
		return err
	}

	selfFed, partnerFed, err := GetFederationByName(ctx, unshZone.SelfOperatorId, unshZone.FederationName)
	if err != nil {
		return err
	}

	// Check if zone exists
	db := loggedDB(ctx)
	lookup := ormapi.FederatorZone{
		ZoneId:      unshZone.ZoneId,
		OperatorId:  selfFed.OperatorId,
		CountryCode: selfFed.CountryCode,
	}
	existingZone := ormapi.FederatorZone{}
	res := db.Where(&lookup).First(&existingZone)
	if !res.RecordNotFound() && res.Error != nil {
		return ormutil.DbErr(res.Error)
	}
	if res.RecordNotFound() {
		return fmt.Errorf("Zone %s not found", unshZone.ZoneId)
	}

	// Ensure that zone is not registered by partner federator
	fedZone := ormapi.FederatedSelfZone{
		ZoneId:         unshZone.ZoneId,
		FederationName: partnerFed.Name,
	}
	res = db.Where(&fedZone).First(&fedZone)
	if !res.RecordNotFound() && res.Error != nil {
		return ormutil.DbErr(res.Error)
	}
	if fedZone.Registered {
		return fmt.Errorf("Cannot unshare zone %q as it is registered as part of federation %q. Please deregister it first",
			unshZone.ZoneId, partnerFed.Name)
	}

	revision := log.SpanTraceID(ctx)

	// Only unshare with those partner federators who are permitted to access our zones
	// And only unshare if federation exists with partner federator, else
	// just add it to the DB (federation planning)
	if partnerFed.PartnerRoleAccessToSelfZones {
		// Notify federated partner about deleted zone
		opZoneUnShare := federation.ZoneSingleRequest{
			RequestId:        revision,
			OrigFederationId: selfFed.FederationId,
			DestFederationId: partnerFed.FederationId,
			Operator:         selfFed.OperatorId,
			Country:          selfFed.CountryCode,
			Zone:             existingZone.ZoneId,
		}
		err = fedClient.SendRequest(ctx, "DELETE", partnerFed.FederationAddr, partnerFed.Name, federation.APIKeyFromVault, federation.OperatorNotifyZoneAPI, &opZoneUnShare, nil)
		if err != nil {
			return err
		}
	}

	// Delete zone from shared list in DB
	if err := db.Delete(&fedZone).Error; err != nil {
		if err != gorm.ErrRecordNotFound {
			return ormutil.DbErr(err)
		}
	}
	return ormutil.SetReply(c, ormutil.Msg(fmt.Sprintf("Zone %s unshared as part of federation %q successfully",
		unshZone.ZoneId, partnerFed.Name)))
}

func RegisterPartnerFederatorZone(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	reg := ormapi.FederatedZoneRegRequest{}
	if err := c.Bind(&reg); err != nil {
		return ormutil.BindErr(err)
	}

	span := log.SpanFromContext(ctx)
	log.SetTags(span, reg.GetTags())

	// sanity check
	if len(reg.Zones) == 0 {
		return fmt.Errorf("Must specify the zones to be registered")
	}

	if err := fedAuthorized(ctx, claims.Username, reg.SelfOperatorId); err != nil {
		return err
	}

	selfFed, partnerFed, err := GetFederationByName(ctx, reg.SelfOperatorId, reg.FederationName)
	if err != nil {
		return err
	}

	// Only register with those partner federator whose zones can be accessed by self federator
	if !partnerFed.PartnerRoleShareZonesWithSelf {
		return fmt.Errorf("Self federator is not allowed to access zones of partner federator")
	}

	// Check if zone exists
	db := loggedDB(ctx)
	zonesMap := make(map[string]ormapi.FederatedPartnerZone)
	for _, inZone := range reg.Zones {
		if inZone == "" {
			return fmt.Errorf("Invalid zone ID %q specified", inZone)
		}
		existingZone := ormapi.FederatedPartnerZone{}
		lookup := ormapi.FederatedPartnerZone{
			FederationName: partnerFed.Name,
			FederatorZone: ormapi.FederatorZone{
				OperatorId:  partnerFed.OperatorId,
				CountryCode: partnerFed.CountryCode,
				ZoneId:      inZone,
			},
		}
		res := db.Where(&lookup).First(&existingZone)
		if !res.RecordNotFound() && res.Error != nil {
			return ormutil.DbErr(res.Error)
		}
		if res.RecordNotFound() {
			return fmt.Errorf("Zone ID %q not found", inZone)
		}
		if existingZone.Registered {
			return fmt.Errorf("Zone ID %q is already registered", inZone)
		}
		zonesMap[existingZone.ZoneId] = existingZone
	}

	revision := log.SpanTraceID(ctx)

	// Notify partner federator about zone registration
	opZoneReg := federation.OperatorZoneRegister{
		RequestId:        revision,
		OrigFederationId: selfFed.FederationId,
		DestFederationId: partnerFed.FederationId,
		Operator:         selfFed.OperatorId,
		Country:          selfFed.CountryCode,
		Zones:            reg.Zones,
	}
	opZoneRes := federation.OperatorZoneRegisterResponse{}
	err = fedClient.SendRequest(ctx, "POST", partnerFed.FederationAddr, partnerFed.Name, federation.APIKeyFromVault, federation.OperatorZoneAPI, &opZoneReg, &opZoneRes)
	if err != nil {
		return err
	}

	// Mark zone as registered in DB
	for _, pZone := range zonesMap {
		pZone.Revision = revision
		pZone.Registered = true
		err = db.Save(&pZone).Error
		if err != nil {
			return ormutil.DbErr(err)
		}
	}

	rc := &ormutil.RegionContext{}
	rc.Username = claims.Username
	rc.Region = selfFed.Region
	rc.Database = database
	cb := func(res *edgeproto.Result) error {
		log.SpanLog(ctx, log.DebugLevelApi, "add partner zone as cloudlet progress", "progress result", res)
		return nil
	}
	for _, zoneReg := range opZoneRes.Zone {
		existingZone, ok := zonesMap[zoneReg.ZoneId]
		if !ok {
			log.SpanLog(ctx, log.DebugLevelApi, "missing zone in DB", "zone ID", zoneReg.ZoneId)
			continue
		}
		// Store this zone as a cloudlet on the regional controller
		lat, long, err := fedcommon.ParseGeoLocation(existingZone.GeoLocation)
		if err != nil {
			return err
		}
		fedCloudlet := edgeproto.Cloudlet{
			Key: edgeproto.CloudletKey{
				Name:                  existingZone.ZoneId,
				Organization:          selfFed.OperatorId,
				FederatedOrganization: partnerFed.OperatorId,
			},
			Location: dme_proto.Loc{
				Latitude:  lat,
				Longitude: long,
			},
			PlatformType: edgeproto.PlatformType_PLATFORM_TYPE_FEDERATION,
			// TODO: This should be removed as a required field
			NumDynamicIps: int32(10),
			FederationConfig: edgeproto.FederationConfig{
				FederationName:        partnerFed.Name,
				PartnerFederationAddr: partnerFed.FederationAddr,
				SelfFederationId:      selfFed.FederationId,
				PartnerFederationId:   partnerFed.FederationId,
				ZoneCountryCode:       existingZone.CountryCode,
			},
		}
		if zoneReg.UpperLimitQuota.CPU > 0 {
			fedCloudlet.ResourceQuotas = append(fedCloudlet.ResourceQuotas, edgeproto.ResourceQuota{
				Name:  cloudcommon.ResourceVcpus,
				Value: uint64(zoneReg.UpperLimitQuota.CPU),
			})
		}
		if zoneReg.UpperLimitQuota.RAM > 0 {
			fedCloudlet.ResourceQuotas = append(fedCloudlet.ResourceQuotas, edgeproto.ResourceQuota{
				Name:  cloudcommon.ResourceRamMb,
				Value: uint64(zoneReg.UpperLimitQuota.RAM) * 1024, // Received RAM is in GBs
			})
		}
		if zoneReg.UpperLimitQuota.Disk > 0 {
			fedCloudlet.ResourceQuotas = append(fedCloudlet.ResourceQuotas, edgeproto.ResourceQuota{
				Name:  cloudcommon.ResourceDiskGb,
				Value: uint64(zoneReg.UpperLimitQuota.Disk),
			})
		}
		log.SpanLog(ctx, log.DebugLevelApi, "add partner zone as cloudlet", "key", fedCloudlet.Key)
		err = ctrlclient.CreateCloudletStream(ctx, rc, &fedCloudlet, connCache, cb)
		if err != nil {
			return err
		}
	}

	return ormutil.SetReply(c, ormutil.Msg("Partner federator zones registered successfully"))
}

func DeregisterPartnerFederatorZone(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	reg := ormapi.FederatedZoneRegRequest{}
	if err := c.Bind(&reg); err != nil {
		return ormutil.BindErr(err)
	}

	span := log.SpanFromContext(ctx)
	log.SetTags(span, reg.GetTags())

	// sanity check
	if len(reg.Zones) == 0 {
		return fmt.Errorf("Must specify zones to be deregistered")
	}

	if err := fedAuthorized(ctx, claims.Username, reg.SelfOperatorId); err != nil {
		return err
	}

	selfFed, partnerFed, err := GetFederationByName(ctx, reg.SelfOperatorId, reg.FederationName)
	if err != nil {
		return err
	}

	// Only deregister with those partner federator whose zones can be accessed by self federator
	if !partnerFed.PartnerRoleShareZonesWithSelf {
		return fmt.Errorf("Self federator is not allowed to access zones of partner federator")
	}

	// Check if zone exists
	zonesMap := make(map[string]ormapi.FederatedPartnerZone)
	db := loggedDB(ctx)
	for _, inZone := range reg.Zones {
		existingZone := ormapi.FederatedPartnerZone{}
		lookup := ormapi.FederatedPartnerZone{
			FederationName: partnerFed.Name,
			FederatorZone: ormapi.FederatorZone{
				OperatorId:  partnerFed.OperatorId,
				CountryCode: partnerFed.CountryCode,
				ZoneId:      inZone,
			},
		}
		res := db.Where(&lookup).First(&existingZone)
		if !res.RecordNotFound() && res.Error != nil {
			return ormutil.DbErr(res.Error)
		}
		if res.RecordNotFound() {
			return fmt.Errorf("Zone ID %q not found", inZone)
		}
		if !existingZone.Registered {
			return fmt.Errorf("Zone ID %q is already deregistered", inZone)
		}
		zonesMap[existingZone.ZoneId] = existingZone
	}

	rc := &ormutil.RegionContext{}
	rc.Username = claims.Username
	rc.Region = selfFed.Region
	rc.Database = database
	cb := func(res *edgeproto.Result) error {
		log.SpanLog(ctx, log.DebugLevelApi, "delete partner zone as cloudlet progress", "progress result", res)
		return nil
	}

	// Delete the zone added as cloudlet from regional controller.
	// This also ensures that no AppInsts are deployed on the cloudlet
	// before the zone is deregistered
	for _, existingZone := range zonesMap {
		fedCloudlet := edgeproto.Cloudlet{
			Key: edgeproto.CloudletKey{
				Name:                  existingZone.ZoneId,
				Organization:          existingZone.SelfOperatorId,
				FederatedOrganization: existingZone.OperatorId,
			},
		}
		log.SpanLog(ctx, log.DebugLevelApi, "delete partner zone as cloudlet", "key", fedCloudlet.Key)
		err = ctrlclient.DeleteCloudletStream(ctx, rc, &fedCloudlet, connCache, cb)
		if err != nil && !strings.Contains(err.Error(), fedCloudlet.Key.NotFoundError().Error()) {
			return err
		}
	}

	revision := log.SpanTraceID(ctx)

	// Notify federated partner about zone deregistration
	opZoneReg := federation.ZoneMultiRequest{
		RequestId:        revision,
		OrigFederationId: selfFed.FederationId,
		DestFederationId: partnerFed.FederationId,
		Operator:         selfFed.OperatorId,
		Country:          selfFed.CountryCode,
		Zones:            reg.Zones,
	}
	err = fedClient.SendRequest(ctx, "DELETE", partnerFed.FederationAddr, partnerFed.Name, federation.APIKeyFromVault, federation.OperatorZoneAPI, &opZoneReg, nil)
	if err != nil {
		return err
	}

	// Mark zone as deregistered in DB
	for _, existingZone := range zonesMap {
		existingZone.Revision = revision
		existingZone.Registered = false
		err = db.Save(&existingZone).Error
		if err != nil {
			return ormutil.DbErr(err)
		}
	}
	return ormutil.SetReply(c, ormutil.Msg("Partner federator zones deregistered successfully"))
}

// Creates a directed federation between self federator and partner federator.
// This gives self federator access to all the zones of the partner federator
// which it is willing to share
func RegisterFederation(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	opFed := ormapi.Federation{}
	if err := c.Bind(&opFed); err != nil {
		return ormutil.BindErr(err)
	}

	span := log.SpanFromContext(ctx)
	log.SetTags(span, opFed.GetTags())

	if err := fedAuthorized(ctx, claims.Username, opFed.SelfOperatorId); err != nil {
		return err
	}

	selfFed, partnerFed, err := GetFederationByName(ctx, opFed.SelfOperatorId, opFed.Name)
	if err != nil {
		return err
	}

	// check that there is no existing federation with partner federator
	if partnerFed.PartnerRoleShareZonesWithSelf {
		return fmt.Errorf("Federation %q is already registered", opFed.Name)
	}

	revision := log.SpanTraceID(ctx)

	// Call federation API
	opRegReq := federation.OperatorRegistrationRequest{
		RequestId:        revision,
		OrigFederationId: selfFed.FederationId,
		DestFederationId: partnerFed.FederationId,
		OperatorId:       selfFed.OperatorId,
		CountryCode:      selfFed.CountryCode,
	}
	opRegRes := federation.OperatorRegistrationResponse{}
	err = fedClient.SendRequest(ctx, "POST", partnerFed.FederationAddr, partnerFed.Name, federation.APIKeyFromVault, federation.OperatorPartnerAPI, &opRegReq, &opRegRes)
	if err != nil {
		return err
	}
	db := loggedDB(ctx)
	// Store partner zones in DB
	for _, partnerZone := range opRegRes.PartnerZone {
		zoneObj := ormapi.FederatedPartnerZone{}
		zoneObj.SelfOperatorId = selfFed.OperatorId
		zoneObj.FederationName = partnerFed.Name
		zoneObj.OperatorId = partnerFed.OperatorId
		zoneObj.CountryCode = partnerFed.CountryCode
		zoneObj.ZoneId = partnerZone.ZoneId
		zoneObj.GeoLocation = partnerZone.GeoLocation
		zoneObj.City = partnerZone.City
		zoneObj.Locality = partnerZone.Locality
		zoneObj.Revision = revision
		if err := db.Create(&zoneObj).Error; err != nil {
			if strings.Contains(err.Error(), "pq: duplicate key value violates unique constraint") {
				return fmt.Errorf("Zone Id %q already exists", zoneObj.ZoneId)
			}
			return ormutil.DbErr(err)
		}
	}

	// Mark partner federator as federated and update attributes
	partnerFed.MCC = opRegRes.MCC
	partnerFed.MNC = opRegRes.MNC
	partnerFed.LocatorEndPoint = opRegRes.LocatorEndPoint
	partnerFed.PartnerRoleShareZonesWithSelf = true
	partnerFed.Revision = revision
	err = db.Save(partnerFed).Error
	if err != nil {
		return ormutil.DbErr(err)
	}

	return ormutil.SetReply(c, ormutil.Msg(
		fmt.Sprintf("Created directed federation %q successfully", partnerFed.Name)))
}

// Delete directed federation between self federator and partner federator.
// Partner federator will no longer have access to any of self federator zones
func DeregisterFederation(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	opFed := ormapi.Federation{}
	if err := c.Bind(&opFed); err != nil {
		return ormutil.BindErr(err)
	}

	span := log.SpanFromContext(ctx)
	log.SetTags(span, opFed.GetTags())

	if err := fedAuthorized(ctx, claims.Username, opFed.SelfOperatorId); err != nil {
		return err
	}

	selfFed, partnerFed, err := GetFederationByName(ctx, opFed.SelfOperatorId, opFed.Name)
	if err != nil {
		return err
	}

	if !partnerFed.PartnerRoleShareZonesWithSelf {
		return fmt.Errorf("No federation exists with partner federator")
	}

	// Check if all the partner zones are unused before deleting the partner federator
	lookup := ormapi.FederatedPartnerZone{
		FederationName: opFed.Name,
	}
	partnerZones := []ormapi.FederatedPartnerZone{}
	db := loggedDB(ctx)
	res := db.Where(&lookup).Find(&partnerZones)
	if !res.RecordNotFound() && res.Error != nil {
		return ormutil.DbErr(res.Error)
	}
	for _, pZone := range partnerZones {
		if pZone.Registered {
			return fmt.Errorf("Cannot deregister federation %q as partner "+
				"zone %q is registered locally. Please deregister it before deregistering federation",
				partnerFed.Name, pZone.ZoneId)
		}
	}

	revision := log.SpanTraceID(ctx)

	// call federation API
	opFedReq := federation.FederationRequest{
		RequestId:        revision,
		OrigFederationId: selfFed.FederationId,
		DestFederationId: partnerFed.FederationId,
		Operator:         selfFed.OperatorId,
		Country:          selfFed.CountryCode,
	}
	err = fedClient.SendRequest(ctx, "DELETE", partnerFed.FederationAddr, partnerFed.Name, federation.APIKeyFromVault, federation.OperatorPartnerAPI, &opFedReq, nil)
	if err != nil {
		return err
	}

	// Delete all the local copy of partner federator zones
	for _, pZone := range partnerZones {
		if err := db.Delete(pZone).Error; err != nil {
			if err != gorm.ErrRecordNotFound {

				return ormutil.DbErr(err)
			}
		}
	}

	// Remove partner federator federation flag
	partnerFed.Revision = revision
	partnerFed.PartnerRoleShareZonesWithSelf = false
	err = db.Save(partnerFed).Error
	if err != nil {
		return ormutil.DbErr(err)
	}

	return ormutil.SetReply(c, ormutil.Msg(
		fmt.Sprintf("Deregistered federation %q successfully", partnerFed.Name)))
}

func ShowFederation(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	filter, err := bindDbFilter(c, &ormapi.Federation{})
	if err != nil {
		return err
	}
	// prevent filtering output on sensitive data
	for _, name := range FederatorIgnoreFilterKeys {
		delete(filter, name)
	}
	authz, err := newShowAuthz(ctx, "", claims.Username, ResourceCloudlets, ActionView)
	if err != nil {
		return err
	}
	db := loggedDB(ctx)
	outFeds := []ormapi.Federation{}
	res := db.Where(filter).Find(&outFeds)
	if !res.RecordNotFound() && res.Error != nil {
		return ormutil.DbErr(res.Error)
	}
	out := []ormapi.Federation{}
	for _, fed := range outFeds {
		if !authz.Ok(fed.SelfOperatorId) {
			continue
		}
		fed.ApiKeyHash = ""
		fed.Salt = ""
		fed.Iter = 0
		out = append(out, fed)
	}
	return c.JSON(http.StatusOK, out)
}
