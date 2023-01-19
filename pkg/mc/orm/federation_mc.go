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
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	fedmgmt "github.com/edgexr/edge-cloud-platform/pkg/federationmgmt"
	"github.com/edgexr/edge-cloud-platform/pkg/fedewapi"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ctrlclient"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/federation"
	fedcommon "github.com/edgexr/edge-cloud-platform/pkg/mc/federation/common"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormutil"
	"github.com/google/uuid"
	"github.com/jinzhu/gorm"
	"github.com/labstack/echo/v4"
)

const (
	FederationProviderKeyDescription = "Federation Provider access key"
	FederationConsumerKeyDescription = "Federation Consumer access key"

	AllowUpdate = true
	CreateOnly  = false
)

func fixFederationTables(ctx context.Context, db *gorm.DB) error {
	if !db.HasTable(&ormapi.FederationProvider{}) {
		// no federation tables, skip this
		return nil
	}
	// upgrade function to fix federation table constraints
	// this deletes old constraints, and adds new ones that
	// gorm's AutoMigrate doesn't handle.
	var err, newerr error

	log.SpanLog(ctx, log.DebugLevelInfo, "fixing federation tables upgrade function")

	// delete foreign key constraints first so we can change column type
	err = cleanupOldSql(db, "ALTER TABLE provider_zones DROP CONSTRAINT IF EXISTS fk_provider_nameoperator_id_constraint", err)
	err = cleanupOldSql(db, "ALTER TABLE provider_zones DROP CONSTRAINT IF EXISTS fk_zoneidoperator_id_constraint", err)
	err = cleanupOldSql(db, "ALTER TABLE consumer_zones DROP CONSTRAINT IF EXISTS fk_consumer_nameoperator_id_constraint", err)
	err = cleanupOldSql(db, "DROP INDEX IF EXISTS fedprovindex", err)

	newerr = fixColumnType(ctx, db, "federation_providers",
		[]ColType{{"name", "citext"}})
	err = accumulateErr(err, newerr)

	newerr = fixColumnType(ctx, db, "federation_providers",
		[]ColType{{"name", "citext"}})
	err = accumulateErr(err, newerr)

	newerr = fixColumnType(ctx, db, "federation_consumers",
		[]ColType{{"name", "citext"}})
	err = accumulateErr(err, newerr)

	newerr = fixColumnType(ctx, db, "provider_zones",
		[]ColType{{"provider_name", "citext"}})
	err = accumulateErr(err, newerr)

	newerr = fixColumnType(ctx, db, "consumer_zones",
		[]ColType{{"consumer_name", "citext"}})
	err = accumulateErr(err, newerr)

	err = cleanupOldSql(db, "ALTER TABLE federation_consumers DROP COLUMN IF EXISTS region", err)

	newerr = setUniqueConstraint(db, "federation_providers", "name")
	err = accumulateErr(err, newerr)

	newerr = setUniqueConstraint(db, "federation_consumers", "name")
	err = accumulateErr(err, newerr)

	newerr = fixPrimaryKeys(ctx, db, "provider_zones", []string{"zone_id", "provider_name"})
	err = accumulateErr(err, newerr)

	newerr = fixPrimaryKeys(ctx, db, "consumer_zones", []string{"zone_id", "consumer_name"})
	err = accumulateErr(err, newerr)

	err = setForeignKey(db, &ormapi.FederationProvider{}, "name", &ormapi.Organization{}, "name", err)
	err = setForeignKey(db, &ormapi.FederationConsumer{}, "name", &ormapi.Organization{}, "name", err)

	return err
}

func cleanupOldSql(loggedDb *gorm.DB, cmd string, prevErr error) error {
	err := loggedDb.Exec(cmd).Error
	return accumulateErr(prevErr, err)
}

func setForeignKeyConstraint(loggedDb *gorm.DB, constraintName, fKeyTableName, fKeyFields, refTableName, refFields string) error {
	cmd := fmt.Sprintf("ALTER TABLE %s ADD CONSTRAINT %s FOREIGN KEY (%s) REFERENCES %s(%s)", fKeyTableName, constraintName, fKeyFields, refTableName, refFields)
	err := loggedDb.Exec(cmd).Error
	if err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			return err
		}
	}
	return nil
}

func setForeignKey(loggedDb *gorm.DB, fromObj interface{}, fromFields string, toObj interface{}, toFields string, prevErr error) error {
	scope := loggedDb.Unscoped().NewScope(fromObj)
	fKeyTableName := scope.TableName()
	fKeyFields := []string{}
	for _, field := range strings.Split(fromFields, ",") {
		fKeyFields = append(fKeyFields, scope.Quote(field))
	}
	fromFieldsStr := strings.Join(fKeyFields, ",")

	scope = loggedDb.Unscoped().NewScope(toObj)
	refTableName := scope.TableName()
	refFields := []string{}
	for _, field := range strings.Split(toFields, ",") {
		refFields = append(refFields, scope.Quote(field))
	}
	toFieldsStr := strings.Join(refFields, ",")
	constraintName := fKeyTableName + "_" + strings.ReplaceAll(fromFields, ",", "_") + "_fkey"

	err := setForeignKeyConstraint(loggedDb, constraintName, fKeyTableName, fromFieldsStr, refTableName, toFieldsStr)
	return accumulateErr(prevErr, err)
}

func accumulateErr(prevErr, err error) error {
	if err == nil {
		return prevErr
	} else if prevErr == nil {
		return err
	} else {
		return fmt.Errorf("%s, %s", prevErr, err)
	}
}

func InitFederationAPIConstraints(db *gorm.DB) error {
	// Setup foreign key constraints, this is done separately here as
	// gorm doesn't support referencing composite primary key inline
	// to the model without including the reference structure.
	// One thing to note is postgres cannot reference a single field
	// that is part of a composite unique/primary key. The referenced
	// field(s) must define a unique value in the table.
	var err error
	err = setForeignKey(db, &ormapi.ProviderZone{}, "provider_name", &ormapi.FederationProvider{}, "name", err)
	err = setForeignKey(db, &ormapi.ProviderZone{}, "zone_id,operator_id", &ormapi.ProviderZoneBase{}, "zone_id,operator_id", err)
	err = setForeignKey(db, &ormapi.ConsumerZone{}, "consumer_name", &ormapi.FederationConsumer{}, "name", err)
	err = setForeignKey(db, &ormapi.ProviderImage{}, "federation_name", &ormapi.FederationProvider{}, "name", err)
	err = setForeignKey(db, &ormapi.ConsumerImage{}, "federation_name", &ormapi.FederationConsumer{}, "name", err)
	err = setForeignKey(db, &ormapi.ConsumerImage{}, "organization", &ormapi.Organization{}, "name", err)
	cerr := setCompositeUniqueConstraint(db, "consumer_apps", "consumer_apps_unique_key", []string{"region", "app_name", "app_org", "app_vers", "federation_name"})
	err = accumulateErr(err, cerr)
	return err
}

func fedAuthorized(ctx context.Context, username, operatorId string) error {
	if operatorId == "" {
		return fmt.Errorf("Missing operator ID")
	}
	return authorized(ctx, username, operatorId, ResourceCloudlets, ActionManage, withRequiresOrg(operatorId))
}

func lookupFederationProvider(ctx context.Context, id uint, name string) (*ormapi.FederationProvider, error) {
	if id == 0 && name == "" {
		return nil, fmt.Errorf("missing federation provider name or id")
	}
	db := loggedDB(ctx)
	fedObj := ormapi.FederationProvider{
		ID:   id,
		Name: name,
	}
	res := db.Where(&fedObj).First(&fedObj)
	if res.RecordNotFound() {
		return nil, fmt.Errorf("FederationProvider %q not found", name)
	}
	if res.Error != nil {
		return nil, ormutil.DbErr(res.Error)
	}
	return &fedObj, nil
}

func lookupFederationConsumer(ctx context.Context, id uint, name string) (*ormapi.FederationConsumer, error) {
	if id == 0 && name == "" {
		return nil, fmt.Errorf("missing federation consumer name or id")
	}
	db := loggedDB(ctx)
	fedObj := ormapi.FederationConsumer{
		ID:   id,
		Name: name,
	}
	res := db.Where(&fedObj).First(&fedObj)
	if res.RecordNotFound() {
		return nil, fmt.Errorf("FederationConsumer %q not found", name)
	}
	if res.Error != nil {
		return nil, ormutil.DbErr(res.Error)
	}
	return &fedObj, nil
}

func setMyFedId(fed *ormapi.Federator, name string) {
	// Federation ID is supposed to be a globally unique identifier
	// allocated to an operator platform. Not sure who decides what
	// these are or manages global uniqueness. For now just hard code
	// to name plus a random UUID.
	if fed.FederationId == "" {
		fed.FederationId = name + "085d364c07fb4fe0b09979127f7c3d68"
	}
}

// Create federation provider to receive EWBI create request
// and provide resources to remote Operator platform.
func CreateFederationProvider(c echo.Context) (reterr error) {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	provider := ormapi.FederationProvider{}
	if err := c.Bind(&provider); err != nil {
		return ormutil.BindErr(err)
	}
	// sanity check
	if provider.OperatorId == "" {
		return fmt.Errorf("Missing operator organization")
	}
	if provider.Name == "" {
		return fmt.Errorf("Please provide a name for this federation provider")
	}
	span := log.SpanFromContext(ctx)
	log.SetTags(span, provider.GetTags())

	if len(provider.Regions) == 0 {
		return fmt.Errorf("Missing regions")
	}
	for _, region := range provider.Regions {
		if _, err := getControllerObj(ctx, region); err != nil {
			return err
		}
	}
	if err := fedAuthorized(ctx, claims.Username, provider.OperatorId); err != nil {
		return err
	}
	if provider.MyInfo.CountryCode != "" {
		if err := fedcommon.ValidateCountryCode(provider.MyInfo.CountryCode); err != nil {
			return err
		}
	}
	setMyFedId(&provider.MyInfo, provider.Name)
	// allocate a federation context id here, so that when we
	// write to the database it will guarantee it is unique.
	fedCtxId := strings.ReplaceAll(uuid.New().String(), "-", "")
	provider.FederationContextId = fedCtxId

	// ensure that operator ID is a valid operator org
	org, err := orgExists(ctx, provider.OperatorId)
	if err != nil {
		return fmt.Errorf("Invalid operator ID specified")
	}
	if org.Type != OrgTypeOperator {
		return fmt.Errorf("Invalid operator ID, must be a valid operator org")
	}
	provider.ProviderClientId = uuid.New().String()
	provider.Status = federation.StatusUnregistered

	// create a developer org from the provider name
	// this org will be used to house images, apps, appinsts, etc
	// that are created by the partner.
	devOrg := ormapi.Organization{
		Name: provider.Name,
		Type: OrgTypeDeveloper,
	}
	err = CreateOrgObj(ctx, claims, &devOrg)
	if err != nil {
		return fmt.Errorf("failed to create developer org %q based on provider name to house partner images and apps: %s", devOrg.Name, err)
	}
	defer func() {
		if reterr == nil {
			return
		}
		undoErr := DeleteOrgObj(ctx, claims, &devOrg)
		if undoErr != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "undo failed to delete developer org for federation provider", "name", devOrg.Name, "err", undoErr)
		}
	}()

	// notify key may be specified during create
	if provider.PartnerNotifyClientId != "" || provider.PartnerNotifyClientKey != "" {
		err := federation.SaveProviderPartnerApiKey(ctx, &provider, serverConfig.vaultConfig)
		if err != nil {
			return err
		}
		defer func() {
			if reterr == nil {
				return
			}
			undoErr := federation.DeleteProviderPartnerApiKey(ctx, &provider, serverConfig.vaultConfig)
			if undoErr != nil {
				log.SpanLog(ctx, log.DebugLevelApi, "undo failed to delete provider partner api key", "err", undoErr)
			}
		}()
	}

	db := loggedDB(ctx)

	if err := db.Create(&provider).Error; err != nil {
		if strings.Contains(err.Error(), "pq: duplicate key value violates unique constraint") {
			return fmt.Errorf("FederationProvider with name %q already exists", provider.Name)
		}
		return ormutil.DbErr(err)
	}
	// create api key for access to provider
	// username is important to bind key to this provider
	username := fedmgmt.GetFedApiKeyUser(fedmgmt.FederationTypeProvider, provider.ID)
	log.SpanLog(ctx, log.DebugLevelApi, "create provider api key", "provider", provider.Name, "operatorId", provider.OperatorId, "username", username)
	_, key, err := ormutil.CreateApiKey(ctx, db, provider.ProviderClientId, provider.OperatorId, username, FederationProviderKeyDescription, CreateOnly)
	if err != nil {
		undoErr := db.Delete(&provider).Error
		if undoErr != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "Undo failed to delete federation provider", "err", undoErr)
		}
		return err
	}

	opFedOut := ormapi.FederationProviderInfo{
		ClientId:   provider.ProviderClientId,
		ClientKey:  key,
		TargetAddr: serverConfig.FederationExternalAddr,
		TokenUrl:   serverConfig.ConsoleAddr + federation.TokenUrl,
	}
	return c.JSON(http.StatusOK, &opFedOut)
}

// Update federation provider and notify associated
// partner federators
func UpdateFederationProvider(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	// Pull json directly so we can unmarshal twice.
	// First time is to do lookup, second time is to apply
	// modified fields.
	body, err := ioutil.ReadAll(c.Request().Body)
	in := ormapi.FederationProvider{}
	err = BindJson(body, &in)
	if err != nil {
		return ormutil.BindErr(err)
	}
	span := log.SpanFromContext(ctx)
	log.SetTags(span, in.GetTags())

	provider, err := lookupFederationProvider(ctx, 0, in.Name)
	if err != nil {
		return err
	}
	if err := fedAuthorized(ctx, claims.Username, provider.OperatorId); err != nil {
		return err
	}
	// Umarshal to map to know what was specified
	inMap := make(map[string]interface{})
	err = BindJson(body, &inMap)
	if err != nil {
		return err
	}
	// Ensure only allowed fields were updated
	// Note these names are the json field names.
	allowedFields := map[string]struct{}{
		"Name":                     {}, // for lookup
		"OperatorId":               {}, // for lookup
		"MyInfo":                   {},
		"MyInfo.CountryCode":       {},
		"MyInfo.MCC":               {},
		"MyInfo.MNC":               {},
		"MyInfo.DiscoveryEndPoint": {},
		"MyInfo.InitialDate":       {},
	}
	for _, field := range ormutil.GetMapKeys(inMap) {
		if _, found := allowedFields[field]; !found {
			return fmt.Errorf("Update %s not allowed", field)
		}
	}
	// Update via json unmarshal
	err = BindJson(body, provider)
	if err != nil {
		return err
	}

	db := loggedDB(ctx)
	err = db.Save(provider).Error
	if err != nil {
		return ormutil.DbErr(err)
	}

	// Notify partner federator
	if provider.PartnerNotifyDest != "" {
		// TODO: callback update
		/*
			opConf := fedapi.UpdateMECNetConf{
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
		*/
	}

	return ormutil.SetReply(c, ormutil.Msg("Updated federation provider"))
}

// Delete FederationProvider
func DeleteFederationProvider(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	in := ormapi.FederationProvider{}
	if err := c.Bind(&in); err != nil {
		return ormutil.BindErr(err)
	}
	provider, err := lookupFederationProvider(ctx, in.ID, in.Name)
	if err != nil {
		return err
	}
	span := log.SpanFromContext(ctx)
	log.SetTags(span, provider.GetTags())
	if err := fedAuthorized(ctx, claims.Username, provider.OperatorId); err != nil {
		return err
	}
	db := loggedDB(ctx)

	// check if images exist
	images := []ormapi.ProviderImage{}
	imageLookup := ormapi.ProviderImage{
		FederationName: provider.Name,
	}
	err = db.Where(&imageLookup).Find(&images).Error
	if err != nil {
		return ormutil.DbErr(err)
	}
	if len(images) > 0 {
		return fmt.Errorf("Cannot delete provider when there are files (images) still present")
	}

	// Ensure no zones are shared.
	// TODO: clean up files/artifacts
	zones := []ormapi.ProviderZone{}
	zoneLookup := ormapi.ProviderZone{
		ProviderName: provider.Name,
		OperatorId:   provider.OperatorId,
	}
	err = db.Where(&zoneLookup).Find(&zones).Error
	if err != nil {
		return ormutil.DbErr(err)
	}
	registeredZones := []string{}
	for _, zone := range zones {
		if zone.Status == federation.StatusRegistered {
			registeredZones = append(registeredZones, zone.ZoneId)
		}
	}
	if len(registeredZones) > 0 {
		return fmt.Errorf("Cannot delete when the following zones are still registered: %s", strings.Join(registeredZones, ", "))
	}
	// delete up the shared zones
	for _, zone := range zones {
		err = db.Delete(zone).Error
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "delete provider zone as part of delete federation provider failed", "zone", zone.ZoneId, "err", err)
		}
	}
	// delete provider
	if err := db.Delete(&provider).Error; err != nil {
		return ormutil.DbErr(err)
	}
	err = ormutil.DeleteApiKey(ctx, db, provider.ProviderClientId)
	log.SpanLog(ctx, log.DebugLevelApi, "delete provider api key", "err", err)
	err = federation.DeleteProviderPartnerApiKey(ctx, provider, serverConfig.vaultConfig)
	log.SpanLog(ctx, log.DebugLevelApi, "delete provider partner api key", "err", err)
	devOrg := ormapi.Organization{
		Name: provider.Name,
	}
	err = DeleteOrgObj(ctx, claims, &devOrg)
	log.SpanLog(ctx, log.DebugLevelApi, "delete provider's dev org", "name", devOrg.Name, "err", err)
	return ormutil.SetReply(c, ormutil.Msg(fmt.Sprintf("FederationProvider %s deleted", provider.Name)))
}

// Fields to ignore for ShowFederation filtering. Names are in database format.
var FederatorIgnoreFilterKeys = []string{
	"my_mnc", // ignore array field
}

func ShowFederationProvider(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	filter, err := bindDbFilter(c, &ormapi.FederationProvider{})
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
	feds := []ormapi.FederationProvider{}
	res := db.Where(filter).Find(&feds)
	if !res.RecordNotFound() && res.Error != nil {
		return ormutil.DbErr(res.Error)
	}
	out := []ormapi.FederationProvider{}
	for _, fed := range feds {
		if !authz.Ok(fed.OperatorId) {
			continue
		}
		out = append(out, fed)
	}
	return c.JSON(http.StatusOK, out)
}

func orgInUseByFederatorCheck(ctx context.Context, orgName string) error {
	db := loggedDB(ctx)

	lookupP := ormapi.FederationProvider{
		OperatorId: orgName,
	}
	outP := []ormapi.FederationProvider{}
	res := db.Where(&lookupP).Find(&outP)
	if !res.RecordNotFound() && res.Error != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "failed to get federator details", "err", res.Error)
		return res.Error
	}
	if !res.RecordNotFound() && len(outP) > 0 {
		return fmt.Errorf("org %s in use by FederationProvider", orgName)
	}

	lookupC := ormapi.FederationConsumer{
		OperatorId: orgName,
	}
	outC := []ormapi.FederationConsumer{}
	res = db.Where(&lookupC).Find(&outC)
	if !res.RecordNotFound() && res.Error != nil {
		log.SpanLog(ctx, log.DebugLevelApi, "failed to get federator details", "err", res.Error)
		return res.Error
	}
	if !res.RecordNotFound() && len(outC) > 0 {
		return fmt.Errorf("org %s in use by FederationConsumer", orgName)
	}
	return nil
}

func GenerateFederationProviderAPIKey(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	in := ormapi.FederationProvider{}
	if err := c.Bind(&in); err != nil {
		return ormutil.BindErr(err)
	}

	provider, err := lookupFederationProvider(ctx, in.ID, in.Name)
	if err != nil {
		return err
	}
	span := log.SpanFromContext(ctx)
	log.SetTags(span, provider.GetTags())
	if err := fedAuthorized(ctx, claims.Username, provider.OperatorId); err != nil {
		return err
	}

	// Id should not be blank. Generate a new one if needed.
	if provider.ProviderClientId == "" {
		provider.ProviderClientId = uuid.New().String()
	}
	username := fedmgmt.GetFedApiKeyUser(fedmgmt.FederationTypeProvider, provider.ID)
	db := loggedDB(ctx)
	_, key, err := ormutil.CreateApiKey(ctx, db, provider.ProviderClientId, provider.OperatorId, username, FederationProviderKeyDescription, AllowUpdate)

	apiKeyOut := ormapi.FederationProviderInfo{
		ClientId:   provider.ProviderClientId,
		ClientKey:  key,
		TargetAddr: serverConfig.ConsoleAddr,
	}
	return c.JSON(http.StatusOK, &apiKeyOut)
}

// Set provider notify auth creds for callbacks
func SetFederationProviderNotifyKey(c echo.Context) error {
	// TODO
	// requires id, key, and tokenUrl
	return nil
}

// Create a Federation Consumer to use partner resources.
// This will attempt to create the connection to the partner.
func CreateFederationConsumer(c echo.Context) (reterr error) {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	consumer := ormapi.FederationConsumer{}
	if err := c.Bind(&consumer); err != nil {
		return ormutil.BindErr(err)
	}
	span := log.SpanFromContext(ctx)
	log.SetTags(span, consumer.GetTags())
	// sanity check
	if consumer.OperatorId == "" {
		return fmt.Errorf("Missing operator id")
	}
	if consumer.Name == "" {
		return fmt.Errorf("Please provide a name for this federation provider")
	}
	if consumer.PartnerAddr == "" {
		return fmt.Errorf("Missing partner EWBI address")
	}
	if consumer.ProviderClientId == "" {
		return fmt.Errorf("Missing OAuth Client Id for connecting to Provider")
	}
	if consumer.ProviderClientKey == "" {
		return fmt.Errorf("Missing OAuth Client key for connecting to Provider")
	}
	if err := fedAuthorized(ctx, claims.Username, consumer.OperatorId); err != nil {
		return err
	}
	if consumer.MyInfo.CountryCode != "" {
		if err := fedcommon.ValidateCountryCode(consumer.MyInfo.CountryCode); err != nil {
			return err
		}
	}
	if consumer.AutoRegisterZones {
		if consumer.AutoRegisterRegion == "" {
			return fmt.Errorf("please specify auto register region to use with auto register zones")
		}
		if _, err := getControllerObj(ctx, consumer.AutoRegisterRegion); err != nil {
			return err
		}
	}
	setMyFedId(&consumer.MyInfo, consumer.Name)

	if consumer.PartnerTokenUrl == "" {
		consumer.PartnerTokenUrl = consumer.PartnerAddr + "/" + federation.TokenUrl
	}

	// create operator organization to house partner's cloudlets (zones)
	operOrg := ormapi.Organization{
		Name: consumer.Name,
		Type: OrgTypeOperator,
	}
	err = CreateOrgObj(ctx, claims, &operOrg)
	if err != nil {
		return fmt.Errorf("failed to create operator org %q base on consumer name to house partner zones: %s", operOrg.Name, err)
	}
	defer func() {
		if reterr == nil {
			return
		}
		undoErr := DeleteOrgObj(ctx, claims, &operOrg)
		if undoErr != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "undo failed to delete operator org for federation consumer", "name", operOrg.Name, "err", undoErr)
		}
	}()

	// create consumer to generate ID
	consumer.Status = federation.StatusUnregistered
	db := loggedDB(ctx)
	if err := db.Create(&consumer).Error; err != nil {
		if strings.Contains(err.Error(), "pq: duplicate key value violates unique constraint") {
			return fmt.Errorf("FederationConsumer with name %q already exists", consumer.Name)
		}
		return ormutil.DbErr(err)
	}
	defer func() {
		if reterr == nil {
			return
		}
		undoErr := db.Delete(&consumer).Error
		if undoErr != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "undo failed to delete federation consumer", "err", undoErr)
		}
	}()

	if err := federation.SaveConsumerPartnerApiKey(ctx, &consumer, serverConfig.vaultConfig); err != nil {
		return err
	}
	defer func() {
		if reterr == nil {
			return
		}
		undoErr := fedmgmt.DeleteAPIKeyFromVault(ctx, serverConfig.vaultConfig, federation.ConsumerFedKey(&consumer))
		if undoErr != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "undo failed to delete secret from vault", "err", undoErr)
		}
	}()

	if err := registerFederationConsumer(ctx, &consumer); err != nil {
		return err
	}

	return ormutil.SetReply(c, ormutil.Msg(fmt.Sprintf("Federation consumer %s created", consumer.Name)))
}

func DeleteFederationConsumer(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	in := ormapi.FederationConsumer{}
	if err := c.Bind(&in); err != nil {
		return ormutil.BindErr(err)
	}
	consumer, err := lookupFederationConsumer(ctx, in.ID, in.Name)
	if err != nil {
		return err
	}
	span := log.SpanFromContext(ctx)
	log.SetTags(span, consumer.GetTags())
	if err := fedAuthorized(ctx, claims.Username, consumer.OperatorId); err != nil {
		return err
	}
	db := loggedDB(ctx)

	// check if images exist
	images := []ormapi.ConsumerImage{}
	imageLookup := ormapi.ConsumerImage{
		FederationName: consumer.Name,
	}
	err = db.Where(&imageLookup).Find(&images).Error
	if err != nil {
		return ormutil.DbErr(err)
	}
	if len(images) > 0 {
		return fmt.Errorf("Cannot delete consumer when there are files (images) still present")
	}

	// check if federation with partner federator exists
	if consumer.Status == federation.StatusRegistered {
		if err := deregisterFederationConsumer(ctx, consumer); err != nil {
			return err
		}
	}

	// Delete federation consumer
	if err := db.Delete(consumer).Error; err != nil {
		return ormutil.DbErr(err)
	}

	// Delete partner API key
	fedKey := federation.ConsumerFedKey(consumer)
	log.SpanLog(ctx, log.DebugLevelApi, "Deleting partner federation API key from vault", "fedkey", fedKey)
	err = fedmgmt.DeleteAPIKeyFromVault(ctx, serverConfig.vaultConfig, fedKey)
	log.SpanLog(ctx, log.DebugLevelApi, "delete API key from vault", "err", err)
	operOrg := ormapi.Organization{
		Name: consumer.Name,
	}
	err = DeleteOrgObj(ctx, claims, &operOrg)
	log.SpanLog(ctx, log.DebugLevelApi, "delete consumer's operator org", "name", operOrg.Name, "err", err)

	return ormutil.SetReply(c, ormutil.Msg(fmt.Sprintf("Federation consumer %s deleted", consumer.Name)))
}

func UpdateFederationConsumer(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	// Pull json directly so we can unmarshal twice.
	// First time is to do lookup, second time is to apply
	// modified fields.
	body, err := ioutil.ReadAll(c.Request().Body)
	in := ormapi.FederationConsumer{}
	err = BindJson(body, &in)
	if err != nil {
		return ormutil.BindErr(err)
	}
	span := log.SpanFromContext(ctx)
	log.SetTags(span, in.GetTags())

	consumer, err := lookupFederationConsumer(ctx, 0, in.Name)
	if err != nil {
		return err
	}
	if err := fedAuthorized(ctx, claims.Username, consumer.OperatorId); err != nil {
		return err
	}
	// Umarshal to map to know what was specified
	inMap := make(map[string]interface{})
	err = BindJson(body, &inMap)
	if err != nil {
		return err
	}
	// Ensure only allowed fields were updated
	// Note these names are the json field names.
	allowedFields := map[string]struct{}{
		"Name":       {}, // for lookup
		"OperatorId": {}, // for lookup
		"Public":     {},
	}
	for _, field := range ormutil.GetMapKeys(inMap) {
		if _, found := allowedFields[field]; !found {
			return fmt.Errorf("Update %s not allowed", field)
		}
	}
	// Update via json unmarshal
	err = BindJson(body, consumer)
	if err != nil {
		return err
	}

	db := loggedDB(ctx)
	err = db.Save(consumer).Error
	if err != nil {
		return ormutil.DbErr(err)
	}
	return ormutil.SetReply(c, ormutil.Msg(fmt.Sprintf("Federation consumer %s updated", consumer.Name)))
}

// Update consumer's client key for provider in case provider regenerated it.
func SetFederationConsumerAPIKey(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	opFed := ormapi.FederationConsumer{}
	if err := c.Bind(&opFed); err != nil {
		return ormutil.BindErr(err)
	}
	span := log.SpanFromContext(ctx)
	log.SetTags(span, opFed.GetTags())
	if err := fedAuthorized(ctx, claims.Username, opFed.OperatorId); err != nil {
		return err
	}
	consumer, err := lookupFederationConsumer(ctx, opFed.ID, opFed.Name)
	if err != nil {
		return err
	}
	consumer.ProviderClientId = opFed.ProviderClientId
	consumer.ProviderClientKey = opFed.ProviderClientKey
	if err := federation.SaveConsumerPartnerApiKey(ctx, consumer, serverConfig.vaultConfig); err != nil {
		return err
	}

	db := loggedDB(ctx)
	err = db.Save(consumer).Error
	if err != nil {
		return ormutil.DbErr(err)
	}
	return ormutil.SetReply(c, ormutil.Msg(fmt.Sprintf("Federation consumer %s api key set", consumer.Name)))
}

// Generate a notify key to allow provider to callback to consumer
func GenerateFederationConsumerNotifyKey(c echo.Context) error {
	// TODO
	return fmt.Errorf("Not implemented yet")
}

func CreateProviderZoneBase(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	opZone := ormapi.ProviderZoneBase{}
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
		return fmt.Errorf("Missing operator")
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
	if _, err := getControllerObj(ctx, opZone.Region); err != nil {
		return err
	}
	if opZone.CountryCode != "" {
		if err := fedcommon.ValidateCountryCode(opZone.CountryCode); err != nil {
			return err
		}
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
	lookup := ormapi.ProviderZoneBase{
		ZoneId: opZone.ZoneId,
	}
	existingFed := ormapi.ProviderZoneBase{}
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
	// By design this should not be able to see cloudlets that
	// were created via a federation and have their
	// FederatedOrganization field set.
	for _, clname := range opZone.Cloudlets {
		if _, found := cloudletMap[clname]; !found {
			return fmt.Errorf("cloudlet %s not found", clname)
		}
	}

	// get average lat/long of cloudlets to calculate geo location
	var lat, long float64
	for _, cl := range opZone.Cloudlets {
		cloudlet, ok := cloudletMap[cl]
		if !ok {
			return fmt.Errorf("Cloudlet %q doesn't exist", cl)
		}
		lat += cloudlet.Location.Latitude
		long += cloudlet.Location.Longitude
	}
	lat /= float64(len(opZone.Cloudlets))
	long /= float64(len(opZone.Cloudlets))

	az := ormapi.ProviderZoneBase{}
	az.OperatorId = opZone.OperatorId
	az.CountryCode = opZone.CountryCode
	az.ZoneId = opZone.ZoneId
	az.GeoLocation = fedcommon.GenGeoLocation(lat, long)
	az.GeographyDetails = opZone.GeographyDetails
	az.Region = opZone.Region
	az.Cloudlets = opZone.Cloudlets
	if err := db.Create(&az).Error; err != nil {
		if strings.Contains(err.Error(), "pq: duplicate key value violates unique constraint") {
			return fmt.Errorf("Zone with same zone ID %q already exists",
				az.ZoneId)
		}
		return ormutil.DbErr(err)
	}

	return ormutil.SetReply(c, ormutil.Msg("Created zone successfully"))
}

func DeleteProviderZoneBase(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	opZone := ormapi.ProviderZoneBase{}
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
	lookup := ormapi.ProviderZoneBase{
		ZoneId:      opZone.ZoneId,
		OperatorId:  opZone.OperatorId,
		CountryCode: opZone.CountryCode,
	}
	existingZone := ormapi.ProviderZoneBase{}
	res := db.Where(&lookup).First(&existingZone)
	if !res.RecordNotFound() && res.Error != nil {
		return ormutil.DbErr(res.Error)
	}
	if res.RecordNotFound() {
		return fmt.Errorf("Zone %s does not exist", opZone.ZoneId)
	}

	// ensure that provider zone is not shared/registered as part of federation
	shLookup := ormapi.ProviderZone{
		ZoneId: opZone.ZoneId,
	}
	shZones := []ormapi.ProviderZone{}
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

// Fields to ignore for ShowProviderZoneBase
// filtering. Names are in database format.
var ProviderZoneBaseIgnoreFilterKeys = []string{
	"cloudlets", // ignore array field
}

func ShowProviderZoneBase(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	filter, err := bindDbFilter(c, &ormapi.ProviderZoneBase{})
	if err != nil {
		return err
	}
	// prevent filtering output on special fields
	for _, name := range ProviderZoneBaseIgnoreFilterKeys {
		delete(filter, name)
	}
	authz, err := newShowAuthz(ctx, "", claims.Username, ResourceCloudlets, ActionView)
	if err != nil {
		return err
	}
	db := loggedDB(ctx)
	opZones := []ormapi.ProviderZoneBase{}
	res := db.Where(filter).Find(&opZones)
	if !res.RecordNotFound() && res.Error != nil {
		return ormutil.DbErr(res.Error)
	}
	out := []ormapi.ProviderZoneBase{}
	for _, opZone := range opZones {
		if !authz.Ok(opZone.OperatorId) {
			continue
		}
		out = append(out, opZone)
	}

	return c.JSON(http.StatusOK, out)
}

func ShareProviderZone(c echo.Context) (reterr error) {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	share := ormapi.FederatedZoneShareRequest{}
	if err := c.Bind(&share); err != nil {
		return ormutil.BindErr(err)
	}
	if len(share.Zones) == 0 {
		return fmt.Errorf("Must specify the zones to be shared")
	}
	provider, err := lookupFederationProvider(ctx, 0, share.ProviderName)
	if err != nil {
		return err
	}
	span := log.SpanFromContext(ctx)
	log.SetTags(span, provider.GetTags())

	if err := fedAuthorized(ctx, claims.Username, provider.OperatorId); err != nil {
		return err
	}

	db := loggedDB(ctx)
	createdZones := []*ormapi.ProviderZone{}
	defer func() {
		if reterr == nil {
			return
		}
		for _, zone := range createdZones {
			undoErr := db.Delete(zone).Error
			if undoErr != nil {
				log.SpanLog(ctx, log.DebugLevelApi, "failed to undo provider zone create", "err", undoErr)
			}
		}
	}()

	zoneDetails := []fedewapi.ZoneDetails{}
	for _, zoneId := range share.Zones {
		// Check if zones exist
		lookup := ormapi.ProviderZoneBase{
			ZoneId:     zoneId,
			OperatorId: provider.OperatorId,
		}
		basis := ormapi.ProviderZoneBase{}
		res := db.Where(&lookup).First(&basis)
		if !res.RecordNotFound() && res.Error != nil {
			return ormutil.DbErr(res.Error)
		}
		if res.RecordNotFound() {
			return fmt.Errorf("Provider zone base id %q not found for operatorID %q", zoneId, provider.OperatorId)
		}

		// Ensure the basis is in a region that provider supports
		regionOk := false
		for _, region := range provider.Regions {
			if region == basis.Region {
				regionOk = true
			}
		}
		if !regionOk {
			return fmt.Errorf("Provider is not sharing resources from region %s", basis.Region)
		}

		// create provider zone if it doesn't already exist
		shareZone := ormapi.ProviderZone{
			ProviderName: provider.Name,
			ZoneId:       basis.ZoneId,
			OperatorId:   provider.OperatorId,
			Status:       federation.StatusUnregistered,
		}
		if err := db.Create(&shareZone).Error; err != nil {
			if !strings.Contains(err.Error(), "pq: duplicate key value violates unique constraint") {
				err = nil
			}
			if err != nil {
				return ormutil.DbErr(err)
			}
		}
		zoneDetails = append(zoneDetails, fedewapi.ZoneDetails{
			GeographyDetails: basis.GeographyDetails,
			Geolocation:      basis.GeoLocation,
			ZoneId:           basis.ZoneId,
		})
		createdZones = append(createdZones, &shareZone)
	}

	log.SpanLog(ctx, log.DebugLevelApi, "share provider zone", "provider-status", provider.Status, "notify", provider.PartnerNotifyDest)
	if provider.Status == federation.StatusRegistered && provider.PartnerNotifyDest != "" {
		fedClient, err := partnerApi.ProviderPartnerClient(ctx, provider, provider.PartnerNotifyDest)
		if err != nil {
			return err
		}
		req := fedewapi.PartnerPostRequest{
			ObjectType:    "ZONES",
			OperationType: "ADD_ZONES",
			AddZones:      zoneDetails,
		}
		_, _, err = fedClient.SendRequest(ctx, "POST", "", &req, nil, nil)
		if err != nil {
			return fmt.Errorf("failed to notify partner: %s", err)
		}
	}

	return ormutil.SetReply(c, ormutil.Msg(
		fmt.Sprintf("Zones shared as part of federation %q successfully",
			provider.Name)))
}

func UnshareProviderZone(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	share := ormapi.FederatedZoneShareRequest{}
	if err := c.Bind(&share); err != nil {
		return ormutil.BindErr(err)
	}
	if len(share.Zones) == 0 {
		return fmt.Errorf("Must specify the zones to be unshared")
	}
	provider, err := lookupFederationProvider(ctx, 0, share.ProviderName)
	if err != nil {
		return err
	}
	span := log.SpanFromContext(ctx)
	log.SetTags(span, provider.GetTags())

	if err := fedAuthorized(ctx, claims.Username, provider.OperatorId); err != nil {
		return err
	}

	rmZones := []string{}
	zonesMap := make(map[string]*ormapi.ProviderZone)
	registeredZones := []string{}
	for _, zoneId := range share.Zones {
		// Check if zone exists
		db := loggedDB(ctx)
		lookup := ormapi.ProviderZone{
			OperatorId:   provider.OperatorId,
			ProviderName: provider.Name,
			ZoneId:       zoneId,
		}
		existingZone := ormapi.ProviderZone{}
		res := db.Where(&lookup).First(&existingZone)
		if !res.RecordNotFound() && res.Error != nil {
			return ormutil.DbErr(res.Error)
		}
		if res.RecordNotFound() {
			return fmt.Errorf("ProviderZone %s not found", zoneId)
		}
		if existingZone.Status == federation.StatusRegistered {
			registeredZones = append(registeredZones, zoneId)
		}
		rmZones = append(rmZones, zoneId)
		zonesMap[zoneId] = &existingZone
	}
	if len(registeredZones) > 0 {
		// For now, cannot unshare registered zones.
		// We may want some way to force unshare though, if remote
		// is completely gone.
		return fmt.Errorf("Cannot unshare registered zones %s, please ask consumer to deregister it", strings.Join(registeredZones, ","))
	}

	if provider.Status == federation.StatusRegistered && provider.PartnerNotifyDest != "" {
		// Notify partner
		fedClient, err := partnerApi.ProviderPartnerClient(ctx, provider, provider.PartnerNotifyDest)
		if err != nil {
			return err
		}
		req := fedewapi.PartnerPostRequest{
			ObjectType:    "ZONES",
			OperationType: "REMOVE_ZONES",
			RemoveZones:   rmZones,
		}
		_, _, err = fedClient.SendRequest(ctx, "POST", "", &req, nil, nil)
		if err != nil {
			return fmt.Errorf("failed to notify partner: %s", err)
		}
	}

	// Delete zones from DB
	db := loggedDB(ctx)
	for _, fedZone := range zonesMap {
		if err := db.Delete(fedZone).Error; err != nil {
			if err != gorm.ErrRecordNotFound {
				return ormutil.DbErr(err)
			}
		}
	}
	return ormutil.SetReply(c, ormutil.Msg(fmt.Sprintf("Zones unshared from federation %q successfully", provider.Name)))
}

func ShowProviderZone(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	filter, err := bindDbFilter(c, &ormapi.ProviderZone{})
	if err != nil {
		return err
	}
	authz, err := newShowAuthz(ctx, "", claims.Username, ResourceCloudlets, ActionView)
	if err != nil {
		return err
	}
	db := loggedDB(ctx)
	opZones := []ormapi.ProviderZone{}
	res := db.Where(filter).Find(&opZones)
	if !res.RecordNotFound() && res.Error != nil {
		return ormutil.DbErr(res.Error)
	}
	out := []ormapi.ProviderZone{}
	for _, zone := range opZones {
		if !authz.Ok(zone.OperatorId) {
			continue
		}
		out = append(out, zone)
	}

	return c.JSON(http.StatusOK, out)
}

func ShowConsumerZone(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	filter, err := bindDbFilter(c, &ormapi.ConsumerZone{})
	if err != nil {
		return err
	}
	// prevent filtering output on special fields
	for _, name := range ProviderZoneBaseIgnoreFilterKeys {
		delete(filter, name)
	}
	authz, err := newShowAuthz(ctx, "", claims.Username, ResourceCloudlets, ActionView)
	if err != nil {
		return err
	}
	db := loggedDB(ctx)
	opZones := []ormapi.ConsumerZone{}
	res := db.Where(filter).Find(&opZones)
	if !res.RecordNotFound() && res.Error != nil {
		return ormutil.DbErr(res.Error)
	}
	out := []ormapi.ConsumerZone{}
	for _, zone := range opZones {
		if !authz.Ok(zone.OperatorId) {
			continue
		}
		out = append(out, zone)
	}

	return c.JSON(http.StatusOK, out)
}

// Register consumer zone creates a Cloudlet in the region that users
// can deploy AppInsts to, which will deploy those AppInsts on the
// federation partner's zone.
func RegisterConsumerZone(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	reg := ormapi.FederatedZoneRegRequest{}
	if err := c.Bind(&reg); err != nil {
		return ormutil.BindErr(err)
	}
	if len(reg.Zones) == 0 {
		return fmt.Errorf("Must specify the zones to be registered")
	}
	if reg.Region == "" {
		return fmt.Errorf("Region in which to create cloudlets for zones must be specified")
	}
	if _, err := getControllerObj(ctx, reg.Region); err != nil {
		return err
	}
	consumer, err := lookupFederationConsumer(ctx, 0, reg.ConsumerName)
	if err != nil {
		return err
	}
	span := log.SpanFromContext(ctx)
	log.SetTags(span, consumer.GetTags())

	if err := fedAuthorized(ctx, claims.Username, consumer.OperatorId); err != nil {
		return err
	}

	// register zones
	err = partnerApi.RegisterConsumerZones(ctx, consumer, reg.Region, reg.Zones)
	if err != nil {
		return err
	}

	return ormutil.SetReply(c, ormutil.Msg("Partner federator zones registered successfully"))
}

func DeregisterConsumerZone(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	reg := ormapi.FederatedZoneRegRequest{}
	if err := c.Bind(&reg); err != nil {
		return ormutil.BindErr(err)
	}
	if len(reg.Zones) == 0 {
		return fmt.Errorf("Must specify zones to be deregistered")
	}
	consumer, err := lookupFederationConsumer(ctx, 0, reg.ConsumerName)
	if err != nil {
		return err
	}
	span := log.SpanFromContext(ctx)
	log.SetTags(span, consumer.GetTags())

	if err := fedAuthorized(ctx, claims.Username, consumer.OperatorId); err != nil {
		return err
	}
	err = partnerApi.DeregisterConsumerZones(ctx, consumer, reg.Zones)
	if err != nil {
		return err
	}
	return ormutil.SetReply(c, ormutil.Msg("Partner federator zones deregistered successfully"))
}

// Registers the consumer with the remote provider.
// This gives consumer access to all the zones of the provider federator
// which it is willing to share.
func registerFederationConsumer(ctx context.Context, consumer *ormapi.FederationConsumer) (reterr error) {
	log.SpanLog(ctx, log.DebugLevelApi, "registering federation consumer", "name", consumer.Name, "operator", consumer.OperatorId, "partnerAddr", consumer.PartnerAddr, "tokenURL", consumer.PartnerTokenUrl)

	// create apikey for provider to callback to consumer
	allowKeyUpdate := false
	if consumer.NotifyClientId == "" {
		// new key
		consumer.NotifyClientId = uuid.New().String()
	} else {
		// update existing key
		allowKeyUpdate = true
	}
	username := fedmgmt.GetFedApiKeyUser(fedmgmt.FederationTypeConsumer, consumer.ID)
	db := loggedDB(ctx)
	_, notifyKey, err := ormutil.CreateApiKey(ctx, db, consumer.NotifyClientId, consumer.OperatorId, username, FederationConsumerKeyDescription, allowKeyUpdate)
	if err != nil {
		return err
	}
	defer func() {
		if reterr == nil {
			return
		}
		undoErr := ormutil.DeleteApiKey(ctx, db, consumer.NotifyClientId)
		if undoErr != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "undo failed to delete api key", "err", undoErr, "id", consumer.NotifyClientId)
		}
	}()

	// Call federation API
	fedClient, err := partnerApi.ConsumerPartnerClient(ctx, consumer)
	if err != nil {
		return err
	}

	req := fedewapi.FederationRequestData{
		FederationNotificationDest: serverConfig.FederationExternalAddr + "/" + federation.CallbackRoot,
		InitialDate:                time.Now(),
		OrigOPCountryCode:          &consumer.MyInfo.CountryCode,
		OrigOPFederationId:         consumer.MyInfo.FederationId,
		OrigOPFixedNetworkCodes:    federation.GetFixedNetworkIds(&consumer.MyInfo),
		OrigOPMobileNetworkCodes:   federation.GetMobileNetworkIds(&consumer.MyInfo),
	}
	res := fedewapi.FederationResponseData{}

	auth := ormutil.EncodeBasicAuth(consumer.NotifyClientId, notifyKey)
	headerVals := http.Header{}
	headerVals.Add(federation.HeaderXNotifyAuth, auth)
	headerVals.Add(federation.HeaderXNotifyTokenUrl, serverConfig.ConsoleAddr+federation.TokenUrl)
	_, _, err = fedClient.SendRequest(ctx, "POST", "/"+federation.ApiRoot+"/partner", &req, &res, headerVals)
	if err != nil {
		return err
	}
	if res.FederationContextId == "" {
		return fmt.Errorf("partner did not specify federation context id")
	}
	consumer.FederationContextId = res.FederationContextId
	consumer.PartnerInfo.FederationId = res.PartnerOPFederationId
	if res.PartnerOPCountryCode != nil {
		consumer.PartnerInfo.CountryCode = *res.PartnerOPCountryCode
	}
	federation.SetFixedNetworkIds(&consumer.PartnerInfo, res.PartnerOPFixedNetworkCodes)
	federation.SetMobileNetworkIds(&consumer.PartnerInfo, res.PartnerOPMobileNetworkCodes)
	consumer.Status = federation.StatusRegistered

	// Save data received from partner
	err = db.Save(consumer).Error
	if err != nil {
		return ormutil.DbErr(err)
	}
	if err := partnerApi.AddConsumerZones(ctx, consumer, res.OfferedAvailabilityZones); err != nil {
		return err
	}
	return nil
}

// Deregister directed federation between consumer and provider.
// Consumer will no longer have access to any of provider zones
func deregisterFederationConsumer(ctx context.Context, consumer *ormapi.FederationConsumer) error {
	fedClient, err := partnerApi.ConsumerPartnerClient(ctx, consumer)
	if err != nil {
		return err
	}

	// Check if all the partner zones are unused before deleting the partner federator
	lookup := ormapi.ConsumerZone{
		ConsumerName: consumer.Name,
		OperatorId:   consumer.OperatorId,
	}
	partnerZones := []ormapi.ConsumerZone{}
	db := loggedDB(ctx)
	res := db.Where(&lookup).Find(&partnerZones)
	if !res.RecordNotFound() && res.Error != nil {
		return ormutil.DbErr(res.Error)
	}
	registeredZones := []string{}
	for _, pZone := range partnerZones {
		if pZone.Status == federation.StatusRegistered {
			registeredZones = append(registeredZones, pZone.ZoneId)
		}
	}
	if len(registeredZones) > 0 {
		return fmt.Errorf("Cannot deregister federation %q as partner zones %s are registered locally. Please deregister zones before deregistering federation", consumer.Name, strings.Join(registeredZones, ", "))
	}

	apiPath := fmt.Sprintf("/%s/%s/partner", federation.ApiRoot, consumer.FederationContextId)
	_, _, err = fedClient.SendRequest(ctx, "DELETE", apiPath, nil, nil, nil)
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
	consumer.Status = federation.StatusUnregistered
	err = db.Save(consumer).Error
	if err != nil {
		return ormutil.DbErr(err)
	}
	return err
}

func ShowFederationConsumer(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	filter, err := bindDbFilter(c, &ormapi.FederationConsumer{})
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
	feds := []ormapi.FederationConsumer{}
	res := db.Where(filter).Find(&feds)
	if !res.RecordNotFound() && res.Error != nil {
		return ormutil.DbErr(res.Error)
	}
	out := []ormapi.FederationConsumer{}
	for _, fed := range feds {
		if !authz.Ok(fed.OperatorId) {
			if fed.Public {
				// show public info
				fedpub := ormapi.FederationConsumer{
					Name:       fed.Name,
					OperatorId: fed.OperatorId,
					Status:     fed.Status,
				}
				out = append(out, fedpub)
			}
			continue
		}
		out = append(out, fed)
	}
	return c.JSON(http.StatusOK, out)
}
