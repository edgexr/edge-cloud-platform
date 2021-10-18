package orm

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/google/uuid"
	"github.com/jinzhu/gorm"
	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud-infra/mc/ctrlclient"
	"github.com/mobiledgex/edge-cloud-infra/mc/federation"
	fedcommon "github.com/mobiledgex/edge-cloud-infra/mc/federation/common"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormclient"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormutil"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/log"
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

func setUniqueConstraintOnFields(loggedDb *gorm.DB, tableName, fields string) error {
	cmd := fmt.Sprintf("ALTER TABLE %s ADD CONSTRAINT unique_key UNIQUE (%s)",
		tableName, fields)
	err := loggedDb.Exec(cmd).Error
	if err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			return err
		}
	}
	return nil
}

func InitFederationAPIConstraints(loggedDb *gorm.DB) error {
	// Cannot create unique constant for FederationKey in Federator object
	// inline as same object is used inline in Federation.
	// Hence, set it up here manually
	scope := loggedDb.Unscoped().NewScope(&ormapi.Federator{})
	err := setUniqueConstraintOnFields(loggedDb, scope.TableName(), scope.Quote("federation_key"))
	if err != nil {
		return err
	}

	// setup foreign key constraints, this is done separately here as gorm doesn't
	// support referencing composite primary key inline to the model

	// Federation's SelfOperatorId/SelfCountryCode references Federator's OperatorId/CountryCode
	scope = loggedDb.Unscoped().NewScope(&ormapi.Federation{})
	fKeyTableName := scope.TableName()
	fKeyFields := fmt.Sprintf("%s, %s", scope.Quote("self_operator_id"), scope.Quote("self_country_code"))

	scope = loggedDb.Unscoped().NewScope(&ormapi.Federator{})
	refTableName := scope.TableName()
	refFields := fmt.Sprintf("%s, %s", scope.Quote("operator_id"), scope.Quote("country_code"))
	err = setForeignKeyConstraint(loggedDb, fKeyTableName, fKeyFields, refTableName, refFields)
	if err != nil {
		return err
	}

	// FederatorZone's OperatorId/CountryCode references Federator's OperatorId/CountryCode
	scope = loggedDb.Unscoped().NewScope(&ormapi.FederatorZone{})
	fKeyTableName = scope.TableName()
	fKeyFields = fmt.Sprintf("%s, %s", scope.Quote("operator_id"), scope.Quote("country_code"))

	scope = loggedDb.Unscoped().NewScope(&ormapi.Federator{})
	refTableName = scope.TableName()
	refFields = fmt.Sprintf("%s, %s", scope.Quote("operator_id"), scope.Quote("country_code"))
	err = setForeignKeyConstraint(loggedDb, fKeyTableName, fKeyFields, refTableName, refFields)
	if err != nil {
		return err
	}

	// FederatedSelfZone's SelfOperatorId/SelfCountryCode/PartnerOperatorId/PartnerCountryCode references
	//   Federation's SelfOperatorId/SelfCountryCode/OperatorId/CountryCode
	scope = loggedDb.Unscoped().NewScope(&ormapi.FederatedSelfZone{})
	fKeyTableName = scope.TableName()
	fKeyFields = fmt.Sprintf("%s, %s, %s, %s",
		scope.Quote("self_operator_id"), scope.Quote("self_country_code"),
		scope.Quote("partner_operator_id"), scope.Quote("partner_country_code"))

	scope = loggedDb.Unscoped().NewScope(&ormapi.Federation{})
	refTableName = scope.TableName()
	refFields = fmt.Sprintf("%s, %s, %s, %s",
		scope.Quote("self_operator_id"), scope.Quote("self_country_code"),
		scope.Quote("operator_id"), scope.Quote("country_code"))
	err = setForeignKeyConstraint(loggedDb, fKeyTableName, fKeyFields, refTableName, refFields)
	if err != nil {
		return err
	}

	fKeyFields = fmt.Sprintf("%s, %s, %s",
		scope.Quote("self_operator_id"), scope.Quote("self_country_code"),
		scope.Quote("zone_id"))
	scope = loggedDb.Unscoped().NewScope(&ormapi.FederatorZone{})
	refTableName = scope.TableName()
	refFields = fmt.Sprintf("%s, %s, %s",
		scope.Quote("operator_id"), scope.Quote("country_code"),
		scope.Quote("zone_id"))
	err = setForeignKeyConstraint(loggedDb, fKeyTableName, fKeyFields, refTableName, refFields)
	if err != nil {
		return err
	}

	// FederatedPartnerZone's SelfOperatorId/SelfCountryCode/OperatorId/CountryCode references
	//   Federation's SelfOperatorId/SelfCountryCode/OperatorId/CountryCode
	scope = loggedDb.Unscoped().NewScope(&ormapi.FederatedPartnerZone{})
	fKeyTableName = scope.TableName()
	fKeyFields = fmt.Sprintf("%s, %s, %s, %s",
		scope.Quote("self_operator_id"), scope.Quote("self_country_code"),
		scope.Quote("operator_id"), scope.Quote("country_code"))

	scope = loggedDb.Unscoped().NewScope(&ormapi.Federation{})
	refTableName = scope.TableName()
	refFields = fmt.Sprintf("%s, %s, %s, %s",
		scope.Quote("self_operator_id"), scope.Quote("self_country_code"),
		scope.Quote("operator_id"), scope.Quote("country_code"))
	err = setForeignKeyConstraint(loggedDb, fKeyTableName, fKeyFields, refTableName, refFields)
	if err != nil {
		return err
	}

	return nil
}

func sendFederationRequest(method, fedAddr, endpoint string, reqData, replyData interface{}) error {
	if fedAddr == "" {
		return fmt.Errorf("Missing partner federation address")
	}
	restClient := &ormclient.Client{}
	if unitTest {
		restClient.ForceDefaultTransport = true
	}
	requestUrl := fmt.Sprintf("http://%s%s", fedAddr, endpoint)
	status, err := restClient.HttpJsonSend(method, requestUrl, "", reqData, replyData)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("Failed to get response for %s request to URL %s, status=%s", method, requestUrl, http.StatusText(status))
	}
	return nil
}

func fedAuthorized(ctx context.Context, username, operatorId string) error {
	if operatorId == "" {
		return fmt.Errorf("Missing self operator ID")
	}
	return authorized(ctx, username, operatorId, ResourceCloudlets, ActionManage)
}

func GetSelfFederator(ctx context.Context, operatorId, countryCode string) (*ormapi.Federator, error) {
	if operatorId == "" {
		return nil, fmt.Errorf("Missing self operator ID")
	}
	if countryCode == "" {
		return nil, fmt.Errorf("Missing self country code")
	}
	db := loggedDB(ctx)
	fedObj := ormapi.Federator{
		OperatorId:  operatorId,
		CountryCode: countryCode,
	}
	res := db.Where(&fedObj).First(&fedObj)
	if res.RecordNotFound() {
		return nil, fmt.Errorf("Self federator %s does not exist", fedObj.IdString())
	}
	if res.Error != nil {
		return nil, ormutil.DbErr(res.Error)
	}
	return &fedObj, nil
}

func GetFederation(ctx context.Context, selfOperatorId, selfCountryCode, partnerOperatorId, partnerCountryCode string) (*ormapi.Federation, error) {
	if partnerOperatorId == "" {
		return nil, fmt.Errorf("Missing partner operator ID %q", partnerOperatorId)
	}
	if partnerCountryCode == "" {
		return nil, fmt.Errorf("Missing partner country code %q", partnerCountryCode)
	}

	db := loggedDB(ctx)
	partnerLookup := ormapi.Federation{
		SelfOperatorId:  selfOperatorId,
		SelfCountryCode: selfCountryCode,
		Federator: ormapi.Federator{
			OperatorId:  partnerOperatorId,
			CountryCode: partnerCountryCode,
		},
	}
	partnerFed := ormapi.Federation{}
	res := db.Where(&partnerLookup).First(&partnerFed)
	if !res.RecordNotFound() && res.Error != nil {
		return nil, ormutil.DbErr(res.Error)
	}
	if res.RecordNotFound() {
		return nil, fmt.Errorf("Partner federator (%s) does not exist",
			partnerFed.PartnerIdString())
	}

	return &partnerFed, nil
}

func GetFederationsForSelf(ctx context.Context, selfOperatorId, selfCountryCode string) ([]ormapi.Federation, error) {
	db := loggedDB(ctx)
	lookup := ormapi.Federation{
		SelfOperatorId:  selfOperatorId,
		SelfCountryCode: selfCountryCode,
	}
	partnerFederations := []ormapi.Federation{}
	res := db.Where(&lookup).Find(&partnerFederations)
	if !res.RecordNotFound() && res.Error != nil {
		return nil, ormutil.DbErr(res.Error)
	}
	return partnerFederations, nil
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
	// sanity check
	if opFed.OperatorId == "" {
		return fmt.Errorf("Missing Operator ID")
	}
	if opFed.CountryCode == "" {
		return fmt.Errorf("Missing country code")
	}
	if opFed.MCC == "" {
		return fmt.Errorf("Missing MCC")
	}
	if len(opFed.MNC) == 0 {
		return fmt.Errorf("Missing MNCs. Please specify one or more MNCs")
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
	if fTest := os.Getenv("E2ETEST_FEDERATION"); fTest != "" && opFed.FederationKey != "" {
		// In test mode, allow user specified federation key
	} else {
		fedKey := uuid.New().String()
		opFed.FederationKey = fedKey
	}
	opFed.FederationAddr = serverConfig.FederationAddr
	if err := db.Create(&opFed).Error; err != nil {
		if strings.Contains(err.Error(), "pq: duplicate key value violates unique constraint") {
			return fmt.Errorf("Self federator %s already exists", opFed.IdString())
		}
		return ormutil.DbErr(err)
	}

	opFedOut := ormapi.Federator{
		FederationKey: opFed.FederationKey,
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
	if err := fedAuthorized(ctx, claims.Username, opFed.OperatorId); err != nil {
		return err
	}
	// get self federator information
	selfFed, err := GetSelfFederator(ctx, opFed.OperatorId, opFed.CountryCode)
	if err != nil {
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
	err = db.Save(selfFed).Error
	if err != nil {
		return ormutil.DbErr(err)
	}

	// Notify all the partner federators who have access to self zones
	partnerFeds, err := GetFederationsForSelf(ctx, selfFed.OperatorId, selfFed.CountryCode)
	if err != nil {
		return err
	}
	errMsgs := []string{}
	for _, partnerFed := range partnerFeds {
		if !partnerFed.PartnerRoleAccessToSelfZones {
			continue
		}
		opConf := federation.UpdateMECNetConf{
			OrigFederationId: selfFed.FederationKey,
			DestFederationId: partnerFed.FederationKey,
			Operator:         selfFed.OperatorId,
			Country:          selfFed.CountryCode,
			MCC:              selfFed.MCC,
			MNC:              selfFed.MNC,
			LocatorEndPoint:  selfFed.LocatorEndPoint,
		}
		err = sendFederationRequest("PUT", partnerFed.FederationAddr, federation.OperatorPartnerAPI, &opConf, nil)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "Failed to update partner federator", "partner federator", partnerFed.PartnerIdString(), "error", err)
			errMsgs = append(errMsgs, fmt.Sprintf("%s, err: %v", partnerFed.PartnerIdString(), err))
		}
	}

	errOut := ""
	if len(errMsgs) > 0 {
		errOut = fmt.Sprintf(". But failed to update partners %s", strings.Join(errMsgs, ";"))
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
	if err := fedAuthorized(ctx, claims.Username, opFed.OperatorId); err != nil {
		return err
	}
	// get federator information
	selfFed, err := GetSelfFederator(ctx, opFed.OperatorId, opFed.CountryCode)
	if err != nil {
		return err
	}

	db := loggedDB(ctx)

	// Ensure that there are no partner federators associated with
	// self federator. This also ensures that none of partner zones
	// are in use by self federator
	fedLookup := ormapi.Federation{
		SelfOperatorId:  selfFed.OperatorId,
		SelfCountryCode: selfFed.CountryCode,
	}
	partnerFeds := []ormapi.Federation{}
	res := db.Where(&fedLookup).Find(&partnerFeds)
	if !res.RecordNotFound() && res.Error != nil {
		return ormutil.DbErr(res.Error)
	}
	if len(partnerFeds) > 0 {
		return fmt.Errorf("Self federator is associated with multiple partner federators. Please delete all those associations before deleting the federator")
	}

	// Ensure that no self zone exists for this federator
	zoneLookup := ormapi.FederatorZone{
		OperatorId:  selfFed.OperatorId,
		CountryCode: selfFed.CountryCode,
	}
	selfZones := []ormapi.FederatorZone{}
	res = db.Where(&zoneLookup).Find(&selfZones)
	if !res.RecordNotFound() && res.Error != nil {
		return ormutil.DbErr(res.Error)
	}
	if len(selfZones) > 0 {
		// This will ensure that no self zones are used by any developer or partner federators
		return fmt.Errorf("Please delete all the associated zones before deleting the federator")
	}
	if err := db.Delete(&selfFed).Error; err != nil {
		return ormutil.DbErr(err)
	}

	return ormutil.SetReply(c, ormutil.Msg("Deleted self federator successfully"))
}

func ShowSelfFederator(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	opFed := ormapi.Federator{}
	if err := c.Bind(&opFed); err != nil {
		return ormutil.BindErr(err)
	}

	authz, err := newShowAuthz(ctx, "", claims.Username, ResourceCloudlets, ActionManage)
	if err != nil {
		return err
	}

	db := loggedDB(ctx)
	feds := []ormapi.Federator{}
	res := db.Where(&opFed).Find(&feds)
	if !res.RecordNotFound() && res.Error != nil {
		return ormutil.DbErr(res.Error)
	}
	out := []ormapi.Federator{}
	for _, fed := range feds {
		if !authz.Ok(fed.OperatorId) {
			continue
		}
		// Do not display federation ID
		fed.FederationKey = ""
		out = append(out, fed)
	}
	return c.JSON(http.StatusOK, out)
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
	// sanity check
	if opFed.SelfOperatorId == "" {
		return fmt.Errorf("Missing self operator ID")
	}
	if opFed.SelfCountryCode == "" {
		return fmt.Errorf("Missing self country code")
	}
	if opFed.OperatorId == "" {
		return fmt.Errorf("Missing partner operator ID")
	}
	if opFed.CountryCode == "" {
		return fmt.Errorf("Missing partner country code")
	}
	if opFed.FederationKey == "" {
		return fmt.Errorf("Missing partner federation key")
	}
	if opFed.FederationAddr == "" {
		return fmt.Errorf("Missing partner federation access address")
	}

	if err := fedAuthorized(ctx, claims.Username, opFed.SelfOperatorId); err != nil {
		return err
	}

	// validate self federator
	_, err = GetSelfFederator(ctx, opFed.SelfOperatorId, opFed.SelfCountryCode)
	if err != nil {
		return err
	}

	db := loggedDB(ctx)
	if err := db.Create(&opFed).Error; err != nil {
		if strings.Contains(err.Error(), "pq: duplicate key value violates unique constraint") {
			return fmt.Errorf("Partner federator (%s) already exists",
				opFed.PartnerIdString())
		}
		return ormutil.DbErr(err)
	}

	return ormutil.SetReply(c, ormutil.Msg("Created partner federator successfully"))
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
	if err := fedAuthorized(ctx, claims.Username, opFed.SelfOperatorId); err != nil {
		return err
	}

	// validate self federator
	_, err = GetSelfFederator(ctx, opFed.SelfOperatorId, opFed.SelfCountryCode)
	if err != nil {
		return err
	}

	partnerFed, err := GetFederation(ctx,
		opFed.SelfOperatorId, opFed.SelfCountryCode,
		opFed.OperatorId, opFed.CountryCode)
	if err != nil {
		return err
	}

	// check if federation with partner federator exists
	db := loggedDB(ctx)
	if partnerFed.PartnerRoleShareZonesWithSelf || partnerFed.PartnerRoleAccessToSelfZones {
		return fmt.Errorf("Cannot delete partner federator (%s) "+
			"as it is part of federation", partnerFed.PartnerIdString())
	}

	// Delete partner federator
	if err := db.Delete(partnerFed).Error; err != nil {
		return ormutil.DbErr(err)
	}

	return ormutil.SetReply(c, ormutil.Msg("Deleted partner federator successfully"))
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
	if err := fedAuthorized(ctx, claims.Username, opZone.OperatorId); err != nil {
		return err
	}
	// get self federation information
	selfFed, err := GetSelfFederator(ctx, opZone.OperatorId, opZone.CountryCode)
	if err != nil {
		return err
	}
	db := loggedDB(ctx)
	lookup := ormapi.FederatorZone{
		OperatorId:  opZone.OperatorId,
		CountryCode: opZone.CountryCode,
		ZoneId:      opZone.ZoneId,
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
			Organization: selfFed.OperatorId,
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
	az.OperatorId = selfFed.OperatorId
	az.CountryCode = selfFed.CountryCode
	az.ZoneId = opZone.ZoneId
	az.GeoLocation = opZone.GeoLocation
	az.State = opZone.State
	az.Locality = opZone.Locality
	az.Region = opZone.Region
	az.Cloudlets = opZone.Cloudlets
	if err := db.Create(&az).Error; err != nil {
		if strings.Contains(err.Error(), "pq: duplicate key value violates unique constraint") {
			return fmt.Errorf("Zone with same zone ID %q already exists for federator (%s)",
				az.ZoneId, az.IdString())
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

	shLookup := ormapi.FederatedSelfZone{
		ZoneId:          opZone.ZoneId,
		SelfOperatorId:  opZone.OperatorId,
		SelfCountryCode: opZone.CountryCode,
	}
	shZone := ormapi.FederatedSelfZone{}
	res = db.Where(&shLookup).First(&shZone)
	if !res.RecordNotFound() && res.Error != nil {
		return ormutil.DbErr(res.Error)
	}
	if shZone.ZoneId != "" {
		return fmt.Errorf("Cannot delete zone %q as it is shared with partner federator "+
			"(%s). Please unshare it before deleting it", shZone.ZoneId,
			shZone.PartnerIdString())
	}
	if shZone.Registered {
		return fmt.Errorf("Cannot delete zone %q as it is registered by partner federator "+
			"(%s). Please deregister it before deleting it", shZone.ZoneId,
			shZone.PartnerIdString())
	}

	if err := db.Delete(&existingZone).Error; err != nil {
		return ormutil.DbErr(err)
	}

	return ormutil.SetReply(c, ormutil.Msg("Deleted federator zone successfully"))
}

func ShowSelfFederatorZone(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	opZoneReq := ormapi.FederatorZone{}
	if err := c.Bind(&opZoneReq); err != nil {
		return ormutil.BindErr(err)
	}
	authz, err := newShowAuthz(ctx, "", claims.Username, ResourceCloudlets, ActionManage)
	if err != nil {
		return err
	}
	db := loggedDB(ctx)
	opZones := []ormapi.FederatorZone{}
	res := db.Where(&opZoneReq).Find(&opZones)
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
	opZoneReq := ormapi.FederatedSelfZone{}
	if err := c.Bind(&opZoneReq); err != nil {
		return ormutil.BindErr(err)
	}
	authz, err := newShowAuthz(ctx, "", claims.Username, ResourceCloudlets, ActionManage)
	if err != nil {
		return err
	}
	db := loggedDB(ctx)
	opZones := []ormapi.FederatedSelfZone{}
	res := db.Where(&opZoneReq).Find(&opZones)
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
	opZoneReq := ormapi.FederatedPartnerZone{}
	if err := c.Bind(&opZoneReq); err != nil {
		return ormutil.BindErr(err)
	}
	authz, err := newShowAuthz(ctx, "", claims.Username, ResourceCloudlets, ActionManage)
	if err != nil {
		return err
	}
	db := loggedDB(ctx)
	opZones := []ormapi.FederatedPartnerZone{}
	res := db.Where(&opZoneReq).Find(&opZones)
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
	// sanity check
	if shZone.ZoneId == "" {
		return fmt.Errorf("Must specify the zone which is to be shared")
	}
	if err := fedAuthorized(ctx, claims.Username, shZone.SelfOperatorId); err != nil {
		return err
	}

	// get self federator information
	selfFed, err := GetSelfFederator(ctx, shZone.SelfOperatorId, shZone.SelfCountryCode)
	if err != nil {
		return err
	}

	// get partner federator information
	partnerFed, err := GetFederation(ctx,
		shZone.SelfOperatorId, shZone.SelfCountryCode,
		shZone.PartnerOperatorId, shZone.PartnerCountryCode)
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
		return fmt.Errorf("Zone ID %q not found", shZone.ZoneId)
	}

	// Only share with those partner federators who are permitted to access our zones
	// And only share if federation exists with partner federator, else
	// just add it to the DB (federation planning)
	if partnerFed.PartnerRoleAccessToSelfZones {
		opZoneShare := federation.NotifyPartnerOperatorZone{
			OrigFederationId: selfFed.FederationKey,
			DestFederationId: partnerFed.FederationKey,
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
		err = sendFederationRequest("POST", partnerFed.FederationAddr, federation.OperatorNotifyZoneAPI, &opZoneShare, nil)
		if err != nil {
			return err
		}
	}

	// Mark zone as shared in DB
	shareZone := ormapi.FederatedSelfZone{
		ZoneId:             existingZone.ZoneId,
		SelfOperatorId:     existingZone.OperatorId,
		SelfCountryCode:    existingZone.CountryCode,
		PartnerOperatorId:  partnerFed.OperatorId,
		PartnerCountryCode: partnerFed.CountryCode,
	}
	if err := db.Create(&shareZone).Error; err != nil {
		if !strings.Contains(err.Error(), "pq: duplicate key value violates unique constraint") {
			return ormutil.DbErr(err)
		}
	}
	return ormutil.SetReply(c, ormutil.Msg(
		fmt.Sprintf("Zone %q shared with partner federator (%s) successfully",
			shareZone.ZoneId, partnerFed.PartnerIdString())))
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
	// sanity check
	if unshZone.ZoneId == "" {
		return fmt.Errorf("Must specify the zone which is to be unshared")
	}
	if err := fedAuthorized(ctx, claims.Username, unshZone.SelfOperatorId); err != nil {
		return err
	}
	// get self federator information
	selfFed, err := GetSelfFederator(ctx, unshZone.SelfOperatorId, unshZone.SelfCountryCode)
	if err != nil {
		return err
	}
	// get partner federator information
	partnerFed, err := GetFederation(ctx,
		unshZone.SelfOperatorId, unshZone.SelfCountryCode,
		unshZone.PartnerOperatorId, unshZone.PartnerCountryCode)
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
		ZoneId:             unshZone.ZoneId,
		SelfOperatorId:     selfFed.OperatorId,
		SelfCountryCode:    selfFed.CountryCode,
		PartnerOperatorId:  partnerFed.OperatorId,
		PartnerCountryCode: partnerFed.CountryCode,
	}
	res = db.Where(&fedZone).First(&fedZone)
	if !res.RecordNotFound() && res.Error != nil {
		return ormutil.DbErr(res.Error)
	}
	if fedZone.Registered {
		return fmt.Errorf("Cannot unshare zone %q as it is registered by partner federator (%s). Please deregister it first",
			unshZone.ZoneId, partnerFed.PartnerIdString())
	}

	// Only unshare with those partner federators who are permitted to access our zones
	// And only unshare if federation exists with partner federator, else
	// just add it to the DB (federation planning)
	if partnerFed.PartnerRoleAccessToSelfZones {
		// Notify federated partner about deleted zone
		opZoneUnShare := federation.ZoneRequest{
			OrigFederationId: selfFed.FederationKey,
			DestFederationId: partnerFed.FederationKey,
			Operator:         selfFed.OperatorId,
			Country:          selfFed.CountryCode,
			Zone:             existingZone.ZoneId,
		}
		err = sendFederationRequest("DELETE", partnerFed.FederationAddr, federation.OperatorNotifyZoneAPI, &opZoneUnShare, nil)
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
	return ormutil.SetReply(c, ormutil.Msg(fmt.Sprintf("Zone %s unshared from partner federator (%s) successfully",
		unshZone.ZoneId, partnerFed.PartnerIdString())))
}

func RegisterPartnerFederatorZone(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	reg := ormapi.FederatedPartnerZone{}
	if err := c.Bind(&reg); err != nil {
		return ormutil.BindErr(err)
	}
	// sanity check
	if reg.ZoneId == "" {
		return fmt.Errorf("Must specify the zone which is to be registered")
	}
	if err := fedAuthorized(ctx, claims.Username, reg.SelfOperatorId); err != nil {
		return err
	}
	// get self federator information
	selfFed, err := GetSelfFederator(ctx, reg.SelfOperatorId, reg.SelfCountryCode)
	if err != nil {
		return err
	}
	partnerFed, err := GetFederation(ctx,
		reg.SelfOperatorId, reg.SelfCountryCode,
		reg.OperatorId, reg.CountryCode,
	)
	if err != nil {
		return err
	}

	// Only register with those partner federator whose zones can be accessed by self federator
	if !partnerFed.PartnerRoleShareZonesWithSelf {
		return fmt.Errorf("Self federator is not allowed to access zones of partner federator")
	}

	// Check if zone exists
	db := loggedDB(ctx)
	existingZone := ormapi.FederatedPartnerZone{}
	lookup := ormapi.FederatedPartnerZone{
		SelfOperatorId:  reg.SelfOperatorId,
		SelfCountryCode: reg.SelfCountryCode,
		FederatorZone: ormapi.FederatorZone{
			OperatorId:  reg.OperatorId,
			CountryCode: reg.CountryCode,
			ZoneId:      reg.ZoneId,
		},
	}
	res := db.Where(&lookup).First(&existingZone)
	if !res.RecordNotFound() && res.Error != nil {
		return ormutil.DbErr(res.Error)
	}
	if res.RecordNotFound() {
		return fmt.Errorf("Zone ID %q not found", reg.ZoneId)
	}

	// Notify partner federator about zone registration
	opZoneReg := federation.OperatorZoneRegister{
		OrigFederationId: selfFed.FederationKey,
		DestFederationId: partnerFed.FederationKey,
		Operator:         selfFed.OperatorId,
		Country:          selfFed.CountryCode,
		Zones:            []string{existingZone.ZoneId},
	}
	opZoneRes := federation.OperatorZoneRegisterResponse{}
	err = sendFederationRequest("POST", partnerFed.FederationAddr, federation.OperatorZoneAPI, &opZoneReg, &opZoneRes)
	if err != nil {
		return err
	}

	// Mark zone as registered in DB
	existingZone.Registered = true
	err = db.Save(&existingZone).Error
	if err != nil {
		return ormutil.DbErr(err)
	}
	return ormutil.SetReply(c, ormutil.Msg(fmt.Sprintf("Partner federator zone %q registered successfully", existingZone.ZoneId)))
}

func DeregisterPartnerFederatorZone(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	reg := ormapi.FederatedPartnerZone{}
	if err := c.Bind(&reg); err != nil {
		return ormutil.BindErr(err)
	}
	// sanity check
	if reg.ZoneId == "" {
		return fmt.Errorf("Must specify the zone which is to be deregistered")
	}
	if err := fedAuthorized(ctx, claims.Username, reg.SelfOperatorId); err != nil {
		return err
	}
	// get self federator information
	selfFed, err := GetSelfFederator(ctx, reg.SelfOperatorId, reg.SelfCountryCode)
	if err != nil {
		return err
	}
	// Only deregister with those partner federator whose zones can be accessed by self federator
	partnerFed, err := GetFederation(ctx,
		reg.SelfOperatorId, reg.SelfCountryCode,
		reg.OperatorId, reg.CountryCode,
	)
	if err != nil {
		return err
	}

	// Only register with those partner federator whose zones can be accessed by self federator
	if !partnerFed.PartnerRoleShareZonesWithSelf {
		return fmt.Errorf("Self federator is not allowed to access zones of partner federator")
	}

	// Check if zone exists
	db := loggedDB(ctx)
	existingZone := ormapi.FederatedPartnerZone{}
	res := db.Where(&reg).First(&existingZone)
	if !res.RecordNotFound() && res.Error != nil {
		return ormutil.DbErr(res.Error)
	}
	if res.RecordNotFound() {
		return fmt.Errorf("Zone ID %q not found", reg.ZoneId)
	}

	// TODO: make sure no AppInsts are deployed on the cloudlet
	//       before the zone is deregistered

	// Notify federated partner about zone deregistration
	opZoneReg := federation.ZoneRequest{
		OrigFederationId: selfFed.FederationKey,
		DestFederationId: partnerFed.FederationKey,
		Operator:         selfFed.OperatorId,
		Country:          selfFed.CountryCode,
		Zone:             existingZone.ZoneId,
	}
	err = sendFederationRequest("DELETE", partnerFed.FederationAddr, federation.OperatorZoneAPI, &opZoneReg, nil)
	if err != nil {
		return err
	}

	// Mark zone as deregistered in DB
	existingZone.Registered = false
	err = db.Save(&existingZone).Error
	if err != nil {
		return ormutil.DbErr(err)
	}
	return ormutil.SetReply(c, ormutil.Msg(fmt.Sprintf("Partner federator zone %q deregistered successfully", existingZone.ZoneId)))
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
	if err := fedAuthorized(ctx, claims.Username, opFed.SelfOperatorId); err != nil {
		return err
	}

	// get federator information
	selfFed, err := GetSelfFederator(ctx, opFed.SelfOperatorId, opFed.SelfCountryCode)
	if err != nil {
		return err
	}

	// get partner federator information
	partnerFed, err := GetFederation(ctx,
		selfFed.OperatorId, selfFed.CountryCode,
		opFed.OperatorId, opFed.CountryCode)
	if err != nil {
		return err
	}

	// check that there is no existing federation with partner federator
	if partnerFed.PartnerRoleShareZonesWithSelf {
		return fmt.Errorf("Federation already exists with partner federator (%s)",
			opFed.PartnerIdString())
	}

	// Call federation API
	opRegReq := federation.OperatorRegistrationRequest{
		OrigFederationId: selfFed.FederationKey,
		DestFederationId: partnerFed.FederationKey,
		OperatorId:       selfFed.OperatorId,
		CountryCode:      selfFed.CountryCode,
	}
	opRegRes := federation.OperatorRegistrationResponse{}
	err = sendFederationRequest("POST", partnerFed.FederationAddr, federation.OperatorPartnerAPI, &opRegReq, &opRegRes)
	if err != nil {
		return err
	}
	db := loggedDB(ctx)
	// Store partner zones in DB
	for _, partnerZone := range opRegRes.PartnerZone {
		zoneObj := ormapi.FederatedPartnerZone{}
		zoneObj.SelfOperatorId = opFed.SelfOperatorId
		zoneObj.SelfCountryCode = opFed.SelfCountryCode
		zoneObj.OperatorId = opFed.OperatorId
		zoneObj.CountryCode = opFed.CountryCode
		zoneObj.ZoneId = partnerZone.ZoneId
		zoneObj.GeoLocation = partnerZone.GeoLocation
		zoneObj.City = partnerZone.City
		zoneObj.Locality = partnerZone.Locality
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
	err = db.Save(partnerFed).Error
	if err != nil {
		return ormutil.DbErr(err)
	}

	return ormutil.SetReply(c, ormutil.Msg(
		fmt.Sprintf("Created directed federation with partner federator (%s) successfully",
			opFed.PartnerIdString())))
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
	if err := fedAuthorized(ctx, claims.Username, opFed.SelfOperatorId); err != nil {
		return err
	}

	// get self federator information
	selfFed, err := GetSelfFederator(ctx, opFed.SelfOperatorId, opFed.SelfCountryCode)
	if err != nil {
		return err
	}

	// get partner federator information with appropriate federation role
	partnerFed, err := GetFederation(ctx,
		opFed.SelfOperatorId, opFed.SelfCountryCode,
		opFed.OperatorId, opFed.CountryCode,
	)
	if err != nil {
		return err
	}

	if !partnerFed.PartnerRoleShareZonesWithSelf {
		return fmt.Errorf("No federation exists with partner federator")
	}

	// Check if all the partner zones are unused before deleting the partner federator
	lookup := ormapi.FederatedPartnerZone{
		SelfOperatorId:  selfFed.OperatorId,
		SelfCountryCode: selfFed.CountryCode,
		FederatorZone: ormapi.FederatorZone{
			OperatorId:  partnerFed.OperatorId,
			CountryCode: partnerFed.CountryCode,
		},
	}
	partnerZones := []ormapi.FederatedPartnerZone{}
	db := loggedDB(ctx)
	res := db.Where(&lookup).Find(&partnerZones)
	if !res.RecordNotFound() && res.Error != nil {
		return ormutil.DbErr(res.Error)
	}
	for _, pZone := range partnerZones {
		if pZone.Registered {
			return fmt.Errorf("Cannot delete federation with partner federator (%s) as partner "+
				"zone %q is registered locally. Please deregister it before removing the federation partner",
				pZone.PartnerIdString(), pZone.ZoneId)
		}
	}

	// call federation API
	opFedReq := federation.FederationRequest{
		OrigFederationId: selfFed.FederationKey,
		DestFederationId: partnerFed.FederationKey,
		Operator:         selfFed.OperatorId,
		Country:          selfFed.CountryCode,
	}
	err = sendFederationRequest("DELETE", partnerFed.FederationAddr, federation.OperatorPartnerAPI, &opFedReq, nil)
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
	partnerFed.PartnerRoleShareZonesWithSelf = false
	err = db.Save(partnerFed).Error
	if err != nil {
		return ormutil.DbErr(err)
	}

	return ormutil.SetReply(c, ormutil.Msg(
		fmt.Sprintf("Deleted federation with partner federator (%s) successfully",
			opFed.PartnerIdString())))
}

func ShowFederation(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	opFed := ormapi.Federation{}
	if err := c.Bind(&opFed); err != nil {
		return ormutil.BindErr(err)
	}
	authz, err := newShowAuthz(ctx, "", claims.Username, ResourceCloudlets, ActionManage)
	if err != nil {
		return err
	}
	db := loggedDB(ctx)
	outFeds := []ormapi.Federation{}
	lookup := ormapi.Federation{
		SelfOperatorId:  opFed.SelfOperatorId,
		SelfCountryCode: opFed.SelfCountryCode,
		Federator: ormapi.Federator{
			OperatorId:  opFed.OperatorId,
			CountryCode: opFed.CountryCode,
		},
	}
	res := db.Where(&lookup).Find(&outFeds)
	if !res.RecordNotFound() && res.Error != nil {
		return ormutil.DbErr(res.Error)
	}
	out := []ormapi.Federation{}
	for _, fed := range outFeds {
		if !authz.Ok(fed.SelfOperatorId) {
			continue
		}
		// hide federation key
		fed.Federator.FederationKey = ""
		out = append(out, fed)
	}
	return c.JSON(http.StatusOK, out)
}
