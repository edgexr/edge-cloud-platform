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

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/edgeproto"
	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/cli"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon/node"
	"github.com/edgexr/edge-cloud-platform/pkg/fedewapi"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/orm"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/orm/testutil"
	"github.com/edgexr/edge-cloud-platform/pkg/mc/ormclient"
	"github.com/edgexr/edge-cloud-platform/pkg/mcctl/cliwrapper"
	"github.com/edgexr/edge-cloud-platform/pkg/mcctl/mctestclient"
	"github.com/edgexr/edge-cloud-platform/pkg/process"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
	edgetestutil "github.com/edgexr/edge-cloud-platform/test/testutil"
	"github.com/pquerna/otp/totp"
)

var mcClient *mctestclient.Client
var errs []Err

type Err struct {
	Desc   string
	Status int
	Err    string
}

type AllDataOut struct {
	Errors     []Err
	RegionData []edgetestutil.AllDataOut
}

type FedDataIn struct {
	Consumers []ormapi.FederationConsumer
	Zones     []ormapi.ConsumerZone
	Artefacts []ormapi.ConsumerApp
	Files     []ormapi.ConsumerImage
	Apps      []ormapi.ConsumerApp
	AppInsts  []ormapi.RegionAppInst
}

type FedDataOut struct {
	Partners  []fedewapi.GetFederationDetails200Response
	Zones     []fedewapi.ZoneRegisteredData
	Artefacts []fedewapi.GetArtefact200Response
	Files     []fedewapi.ViewFile200Response
	Apps      []fedewapi.ViewApplication200Response
	AppInsts  []fedewapi.GetAppInstanceDetails200Response
}

func RunMcAPI(api, mcname, apiFile string, actionVars, apiFileVars map[string]string, curUserFile, outputDir string, mods []string, vars, sharedData map[string]string, retry *bool) bool {
	mc := getMC(mcname)
	uri := "https://" + mc.Addr + "/api/v1"
	log.Printf("Using MC %s at %s", mc.Name, uri)

	vars = util.AddMaps(vars, apiFileVars)

	var clientRun mctestclient.ClientRun
	if hasMod("cli", mods) {
		cliclient := cliwrapper.NewClient()
		cliclient.DebugLog = true
		cliclient.SkipVerify = true
		cliclient.SilenceUsage = true
		clientRun = cliclient
	} else {
		clientRun = &ormclient.Client{
			SkipVerify: true,
		}
	}
	mcClient = mctestclient.NewClient(clientRun)

	if strings.HasSuffix(api, "users") {
		return runMcUsersAPI(api, uri, apiFile, curUserFile, outputDir, mods, actionVars, vars, sharedData)
	} else if strings.HasPrefix(api, "config") {
		return runMcConfig(api, uri, apiFile, curUserFile, outputDir, mods, actionVars, vars, sharedData)
	} else if strings.HasPrefix(api, "events") {
		return runMcEvents(api, uri, apiFile, curUserFile, outputDir, mods, vars, sharedData, retry)
	} else if strings.HasPrefix(api, "spans") {
		return runMcSpans(api, uri, apiFile, curUserFile, outputDir, mods, vars, retry)
	} else if api == "runcommand" {
		return runMcExec(api, uri, apiFile, curUserFile, outputDir, mods, actionVars, vars, sharedData)
	} else if api == "showlogs" {
		return runMcExec(api, uri, apiFile, curUserFile, outputDir, mods, actionVars, vars, sharedData)
	} else if api == "accesscloudlet" {
		return runMcExec(api, uri, apiFile, curUserFile, outputDir, mods, actionVars, vars, sharedData)
	} else if api == "nodeshow" {
		return runMcShowNode(uri, curUserFile, outputDir, actionVars, vars, sharedData)
	} else if api == "showalerts" {
		*retry = true
		return showMcAlerts(uri, apiFile, curUserFile, outputDir, actionVars, vars, sharedData)
	} else if strings.HasPrefix(api, "debug") {
		return runMcDebug(api, uri, apiFile, curUserFile, outputDir, mods, actionVars, vars, sharedData)
	} else if api == "showalertreceivers" {
		*retry = true
		return showMcAlertReceivers(uri, curUserFile, outputDir, actionVars, vars, sharedData)
	} else if api == "adduseralert" {
		return runMcAddUserAlertToApp(api, uri, apiFile, curUserFile, outputDir, mods, actionVars, vars, sharedData)
	} else if api == "removeuseralert" {
		return runMcRemoveUserAlertFromApp(api, uri, apiFile, curUserFile, outputDir, mods, actionVars, vars, sharedData)
	} else if strings.HasPrefix(api, "mcratelimit") {
		return runMcRateLimit(api, uri, apiFile, curUserFile, outputDir, mods, actionVars, vars, sharedData)
	} else if strings.HasPrefix(api, "ratelimit") {
		return runRateLimit(api, uri, apiFile, curUserFile, outputDir, mods, actionVars, vars, sharedData)
	}

	return runMcDataAPI(api, uri, apiFile, curUserFile, outputDir, mods, actionVars, vars, sharedData, retry)
}

func getMC(name string) *process.MC {
	if name == "" {
		return Deployment.Mcs[0]
	}
	for _, mc := range Deployment.Mcs {
		if mc.Name == name {
			return mc
		}
	}
	log.Fatalf("Error: could not find specified MC: %s\n", name)
	return nil //unreachable
}

func runMcUsersAPI(api, uri, apiFile, curUserFile, outputDir string, mods []string, actionVars, vars, sharedData map[string]string) bool {
	log.Printf("Applying MC users via APIs for %s\n", apiFile)

	rc := true
	if api == "showusers" {
		token, rc := getLoginToken(curUserFile, outputDir, actionVars, vars)
		if !rc {
			return false
		}
		filter := &cli.MapData{
			Namespace: cli.StructNamespace,
			Data:      map[string]interface{}{},
		}
		users, status, err := mcClient.ShowUser(uri, token, filter)
		checkMcErr("ShowUser", status, err, &rc)
		cmpFilterUsers(users)
		PrintToYamlFile("show-commands.yml", outputDir, users, true)
		return rc
	}

	usernames, hasUsernames := actionVars["usernames"]
	if hasUsernames && (api == "createusers" || api == "deleteusers") {
		// no file needed
		for _, name := range strings.Split(usernames, ",") {
			name = strings.TrimSpace(name)
			user := ormapi.User{
				Name: name,
			}
			if api == "createusers" {
				user.Passhash = name + "-password-super-long-difficult"
				user.Email = name + "@email.com"
				createUser := ormapi.CreateUser{
					User: user,
				}
				_, status, err := mcClient.CreateUser(uri, &createUser)
				checkMcErr("CreateUser", status, err, &rc)
				if err == nil {
					log.Printf("created user %s: %s\n", name, user.Passhash)
					// login and save token so we don't need to log in again
					doLogin(uri, outputDir, &user, "", &rc)
				}
			} else {
				actionVars["username"] = name
				token, ok := getLoginToken(curUserFile, outputDir, actionVars, vars)
				if !ok {
					return false
				}
				status, err := mcClient.DeleteUser(uri, token, &user)
				checkMcErr("DeleteUser", status, err, &rc)
			}
		}
		return rc
	}

	if apiFile == "" {
		log.Println("Error: Cannot run MC user APIs without API file")
		return false
	}

	if api == "newpassusers" {
		newpass := ormapi.NewPassword{}
		err := ReadYamlFile(apiFile, &newpass, WithVars(vars), ValidateReplacedVars())
		if err != nil {
			log.Printf("Failed to unmarshal NewPassword from file %s: %s\n", apiFile, err)
			return false
		}
		token, ok := getLoginToken(curUserFile, outputDir, actionVars, vars)
		if !ok {
			return false
		}
		status, err := mcClient.NewPassword(uri, token, &newpass)
		checkMcErr("NewPassword", status, err, &rc)
		return rc
	}

	users := readUsersFiles(apiFile, vars)

	switch api {
	case "loginusers":
		// Login users. This is really only needed for mexadmin, since
		// other users are automatically logged in on create.
		// otp is not supported since it's really just for mexadmin.
		for _, user := range users {
			doLogin(uri, outputDir, &user, "", &rc)
		}
	case "createusers":
		for _, user := range users {
			createUser := ormapi.CreateUser{
				User: user,
			}
			resp, status, err := mcClient.CreateUser(uri, &createUser)
			checkMcErr("CreateUser", status, err, &rc)
			if err == nil && resp != nil {
				otp := ""
				// generate TOTP so we can log in and save token
				// Don't test invalidating otp and needing to regenerate it
				// in e2e tests, that should be done in unit or integration.
				if resp.TOTPSharedKey != "" {
					otp, err = totp.GenerateCode(resp.TOTPSharedKey, time.Now())
					if err != nil {
						log.Printf("failed to generate otp: %v, %s\n", err, user.Name)
						rc = false
					}
				}
				// login and save token so we don't need to log in again
				doLogin(uri, outputDir, &user, otp, &rc)
			}
		}
	case "deleteusers":
		token, ok := getLoginToken(curUserFile, outputDir, actionVars, vars)
		if !ok {
			return false
		}
		for _, user := range users {
			u := user
			u.Passhash = ""
			status, err := mcClient.DeleteUser(uri, token, &u)
			checkMcErr("DeleteUser", status, err, &rc)
		}
	}
	return rc
}

func runMcConfig(api, uri, apiFile, curUserFile, outputDir string, mods []string, actionVars, vars, sharedData map[string]string) bool {
	log.Printf("Applying MC config via APIs for %s\n", apiFile)

	token, rc := getLoginToken(curUserFile, outputDir, actionVars, vars)
	if !rc {
		return false
	}

	switch api {
	case "configshow":
		config, st, err := mcClient.ShowConfig(uri, token)
		checkMcErr("ShowConfig", st, err, &rc)
		PrintToYamlFile("show-commands.yml", outputDir, config, true)
	case "configreset":
		st, err := mcClient.ResetConfig(uri, token)
		checkMcErr("ResetConfig", st, err, &rc)
	case "configupdate":
		if apiFile == "" {
			log.Println("Error: Cannot run MC config APIs without API file")
			return false
		}
		data := make(map[string]interface{})
		err := ReadYamlFile(apiFile, &data, WithVars(vars), ValidateReplacedVars())
		if err != nil && !IsYamlOk(err, "config") {
			log.Printf("error in unmarshal ormapi.Config for %s: %v\n", apiFile, err)
			return false
		}
		// Note: setting namespace to ArgsNamespace is strictly
		// incorrect, as it should be YamlNamespace. But for our
		// data, the yaml names and the arg names should be the
		// same because we don't use yaml tags on fields.
		// So they both end up as lowercased versions of the struct
		// field names.
		mdata := &cli.MapData{
			Namespace: cli.ArgsNamespace,
			Data:      data,
		}
		st, err := mcClient.UpdateConfig(uri, token, mdata)
		checkMcErr("UpdateConfig", st, err, &rc)
	}
	return rc
}

func runMcRateLimit(api, uri, apiFile, curUserFile, outputDir string, mods []string, actionVars, vars, sharedData map[string]string) bool {
	log.Printf("Applying MC ratelimit via APIs for %s\n", apiFile)
	token, rc := getLoginToken(curUserFile, outputDir, actionVars, vars)
	if !rc {
		return false
	}

	if api == "mcratelimitshow" {
		filter := &ormapi.McRateLimitSettings{}
		settings, st, err := mcClient.ShowRateLimitSettingsMc(uri, token, filter)
		checkMcErr("ShowRateLimitSettingsMc", st, err, &rc)
		cmpFilterRateLimit(settings)
		PrintToYamlFile("show-commands.yml", outputDir, settings, true)
		return rc
	} else if api == "mcratelimitflowshow" {
		filter := &ormapi.McRateLimitFlowSettings{}
		settings, st, err := mcClient.ShowFlowRateLimitSettingsMc(uri, token, filter)
		checkMcErr("ShowFlowRateLimitSettingsMc", st, err, &rc)
		cmpFilterRateLimitFlow(settings)
		PrintToYamlFile("show-commands.yml", outputDir, settings, true)
		return rc
	} else if api == "mcratelimitmaxreqsshow" {
		filter := &ormapi.McRateLimitMaxReqsSettings{}
		settings, st, err := mcClient.ShowMaxReqsRateLimitSettingsMc(uri, token, filter)
		checkMcErr("ShowMaxReqsRateLimitSettingsMc", st, err, &rc)
		cmpFilterRateLimitMaxReqs(settings)
		PrintToYamlFile("show-commands.yml", outputDir, settings, true)
		return rc
	}

	if apiFile == "" {
		log.Println("Error: Cannot run MC config APIs without API file")
		return false
	}

	switch api {
	case "mcratelimitflowcreate":
		fallthrough
	case "mcratelimitflowdelete":
		in := &ormapi.McRateLimitFlowSettings{}
		err := ReadYamlFile(apiFile, in, WithVars(vars), ValidateReplacedVars())
		if err != nil && !IsYamlOk(err, "mcratelimitflowsettings") {
			log.Printf("error in unmarshal ormapi.McRateLimitFlowSettings for %s: %v\n", apiFile, err)
			return false
		}
		if api == "mcratelimitflowcreate" {
			st, err := mcClient.CreateFlowRateLimitSettingsMc(uri, token, in)
			checkMcErr("CreateFlowRateLimitSettingsMc", st, err, &rc)
		} else {
			st, err := mcClient.DeleteFlowRateLimitSettingsMc(uri, token, in)
			checkMcErr("DeleteFlowRateLimitSettingsMc", st, err, &rc)
		}

	case "mcratelimitmaxreqscreate":
		fallthrough
	case "mcratelimitmaxreqsdelete":
		in := &ormapi.McRateLimitMaxReqsSettings{}
		err := ReadYamlFile(apiFile, in, WithVars(vars), ValidateReplacedVars())
		if err != nil && !IsYamlOk(err, "mcratelimitmaxreqssettings") {
			log.Printf("error in unmarshal ormapi.McRateLimitMaxReqsSettings for %s: %v\n", apiFile, err)
			return false
		}
		if api == "mcratelimitmaxreqscreate" {
			st, err := mcClient.CreateMaxReqsRateLimitSettingsMc(uri, token, in)
			checkMcErr("CreateMaxReqsRateLimitSettingsMc", st, err, &rc)
		} else {
			st, err := mcClient.DeleteMaxReqsRateLimitSettingsMc(uri, token, in)
			checkMcErr("DeleteMaxReqsRateLimitSettingsMc", st, err, &rc)
		}

	case "mcratelimitflowupdate":
		fallthrough
	case "mcratelimitmaxreqsupdate":
		data := make(map[string]interface{})
		err := ReadYamlFile(apiFile, data, WithVars(vars), ValidateReplacedVars())
		mdata := &cli.MapData{
			Namespace: cli.ArgsNamespace,
			Data:      data,
		}
		if api == "mcratelimitflowupdate" {
			if err != nil && !IsYamlOk(err, "mcratelimitflowsettings") {
				log.Printf("error in unmarshal ormapi.McRateLimitFlowSettings for %s: %v\n", apiFile, err)
				return false
			}
			st, err := mcClient.UpdateFlowRateLimitSettingsMc(uri, token, mdata)
			checkMcErr("UpdateFlowRateLimitSettingsMc", st, err, &rc)
		} else {
			if err != nil && !IsYamlOk(err, "mcratelimitmaxreqssettings") {
				log.Printf("error in unmarshal ormapi.McRateLimitMaxReqsSettings for %s: %v\n", apiFile, err)
				return false
			}
			st, err := mcClient.UpdateMaxReqsRateLimitSettingsMc(uri, token, mdata)
			checkMcErr("UpdateMaxReqsRateLimitSettingsMc", st, err, &rc)
		}
	}
	return rc
}

func runRateLimit(api, uri, apiFile, curUserFile, outputDir string, mods []string, actionVars, vars, sharedData map[string]string) bool {
	log.Printf("Applying Controller ratelimit via APIs for %s\n", apiFile)
	token, rc := getLoginToken(curUserFile, outputDir, actionVars, vars)
	if !rc {
		return false
	}
	if api == "ratelimitshow" {
		region, ok := vars["region"]
		if !ok {
			log.Printf("ratelimitshow requires \"region\" apifilevar in yaml testfile")
			return false
		}
		filter := &ormapi.RegionRateLimitSettings{
			Region: region,
		}
		settings, st, err := mcClient.ShowRateLimitSettings(uri, token, filter)
		checkMcErr("ShowRateLimitSettings", st, err, &rc)
		output := edgeproto.RateLimitSettingsData{}
		output.Settings = settings
		output.Sort()
		PrintToYamlFile("show-commands.yml", outputDir, output, true)
		return rc
	}
	return rc
}

func runMcDataAPI(api, uri, apiFile, curUserFile, outputDir string, mods []string, actionVars, vars, sharedData map[string]string, retry *bool) bool {
	log.Printf("Applying MC data via APIs for %s mods %v vars %v\n", apiFile, mods, vars)
	// Data APIs are all run by a given user.
	// That user is specified in the current user file.
	// We need to log in as that user.
	rc := true
	token, rc := getLoginToken(curUserFile, outputDir, actionVars, vars)
	if !rc {
		return false
	}

	tag := ""
	apiParams := strings.Split(api, "-")
	if len(apiParams) > 1 {
		api = apiParams[0]
		tag = apiParams[1]
	}

	if api == "show" {
		objTypes := getVarsObjTypes(actionVars)
		showData := showMcData(uri, token, tag, objTypes, &rc)
		if tag == "" {
			cmpFilterAllData(showData)
		} else if tag == "noignore" {
			cmpFilterAllDataNoIgnore(showData)
		}
		PrintToYamlFile("show-commands.yml", outputDir, showData, true)
		*retry = true
		return rc
	}

	if api == "showevents" {
		var showEvents *ormapi.AllMetrics
		targets := readMCMetricTargetsFile(apiFile, vars)
		showEvents = showMcEvents(uri, token, targets, &rc)
		// convert showMetrics into something yml compatible
		parsedMetrics := parseMetrics(showEvents)
		PrintToYamlFile("show-commands.yml", outputDir, parsedMetrics, true)
		*retry = true
		return rc
	}

	if strings.HasPrefix(api, "showmetrics") {
		var showMetrics *ormapi.AllMetrics
		targets := readMCMetricTargetsFile(apiFile, vars)
		var parsedMetrics *[]MetricsCompare
		// retry a couple times since prometheus takes a while on startup
		for i := 0; i < 100; i++ {
			if api == "showmetrics" {
				showMetrics = showMcMetricsSep(uri, token, targets, &rc)
			} else {
				showMetrics = showMcMetricsAll(uri, token, targets, &rc)
			}
			// convert showMetrics into something yml compatible
			parsedMetrics = parseMetrics(showMetrics)
			if len(*parsedMetrics) == len(E2eAppSelectors)+len(E2eClusterSelectors) {
				break
			} else {
				time.Sleep(100 * time.Millisecond)
			}
		}
		cmpFilterMetrics(*parsedMetrics)
		PrintToYamlFile("show-commands.yml", outputDir, parsedMetrics, true)
		*retry = true
		return rc
	}

	if api == "showclientapimetrics" {
		var showClientApiMetrics *ormapi.AllMetrics
		targets := readMCMetricTargetsFile(apiFile, vars)
		var parsedMetrics *[]OptimizedMetricsCompare
		showClientApiMetrics = showMcClientApiMetrics(uri, token, targets, &rc)
		parsedMetrics = parseOptimizedMetrics(showClientApiMetrics)
		cmpFilterApiMetricData(*parsedMetrics)
		PrintToYamlFile("show-commands.yml", outputDir, parsedMetrics, true)
		*retry = true
		return rc
	}

	if api == "showclientappmetrics" {
		var showClientAppMetrics *ormapi.AllMetrics
		targets := readMCMetricTargetsFile(apiFile, vars)
		var parsedMetrics *[]OptimizedMetricsCompare
		showClientAppMetrics = showMcClientAppMetrics(uri, token, targets, &rc)
		parsedMetrics = parseOptimizedMetrics(showClientAppMetrics)
		cmpFilterApiMetricData(*parsedMetrics)
		PrintToYamlFile("show-commands.yml", outputDir, parsedMetrics, true)
		*retry = true
		return rc
	}

	if api == "showclientcloudletmetrics" {
		var showClientCloudletMetrics *ormapi.AllMetrics
		targets := readMCMetricTargetsFile(apiFile, vars)
		var parsedMetrics *[]OptimizedMetricsCompare
		showClientCloudletMetrics = showMcClientCloudletMetrics(uri, token, targets, &rc)
		parsedMetrics = parseOptimizedMetrics(showClientCloudletMetrics)
		cmpFilterApiMetricData(*parsedMetrics)
		PrintToYamlFile("show-commands.yml", outputDir, parsedMetrics, true)
		*retry = true
		return rc
	}

	if api == "showfederationhosts" {
		showFilter := &cli.MapData{
			Namespace: cli.StructNamespace,
			Data:      map[string]interface{}{},
		}
		hosts, status, err := mcClient.ShowFederationHost(uri, token, showFilter)
		checkMcErr("ShowFederationHost", status, err, &rc)
		showData := ormapi.AllData{
			FederationProviders: hosts,
		}
		cmpFilterAllData(&showData)
		PrintToYamlFile("show-commands.yml", outputDir, &showData, true)
		*retry = true
		return rc
	}
	if api == "showhostzonebases" {
		showFilter := &cli.MapData{
			Namespace: cli.StructNamespace,
			Data:      map[string]interface{}{},
		}
		zones, status, err := mcClient.ShowHostZoneBase(uri, token, showFilter)
		checkMcErr("ShowHostZoneBase", status, err, &rc)
		showData := ormapi.AllData{
			ProviderZoneBases: zones,
		}
		cmpFilterAllData(&showData)
		PrintToYamlFile("show-commands.yml", outputDir, &showData, true)
		*retry = true
		return rc
	}
	if api == "showhostzones" {
		showFilter := &cli.MapData{
			Namespace: cli.StructNamespace,
			Data:      map[string]interface{}{},
		}
		zones, status, err := mcClient.ShowHostZone(uri, token, showFilter)
		checkMcErr("ShowHostZone", status, err, &rc)
		showData := ormapi.AllData{
			ProviderZones: zones,
		}
		cmpFilterAllData(&showData)
		PrintToYamlFile("show-commands.yml", outputDir, &showData, true)
		*retry = true
		return rc
	}
	if api == "showfederationguests" {
		showFilter := &cli.MapData{
			Namespace: cli.StructNamespace,
			Data:      map[string]interface{}{},
		}
		federations, status, err := mcClient.ShowFederationGuest(uri, token, showFilter)
		checkMcErr("ShowFederationGuest", status, err, &rc)
		showData := ormapi.AllData{
			FederationConsumers: federations,
		}
		cmpFilterAllData(&showData)
		PrintToYamlFile("show-commands.yml", outputDir, &showData, true)
		*retry = true
		return rc
	}
	if api == "showguestzones" {
		showFilter := &cli.MapData{
			Namespace: cli.StructNamespace,
			Data:      map[string]interface{}{},
		}
		zones, status, err := mcClient.ShowGuestZone(uri, token, showFilter)
		checkMcErr("ShowGuestZone", status, err, &rc)
		showData := ormapi.AllData{
			ConsumerZones: zones,
		}
		cmpFilterAllData(&showData)
		PrintToYamlFile("show-commands.yml", outputDir, &showData, true)
		*retry = true
		return rc
	}
	if api == "showhostappdata" {
		showFilter := &cli.MapData{
			Namespace: cli.StructNamespace,
			Data:      map[string]interface{}{},
		}
		images, status, err := mcClient.ShowHostImage(uri, token, showFilter)
		checkMcErr("ShowHostImage", status, err, &rc)
		artefacts, status, err := mcClient.ShowHostArtefact(uri, token, showFilter)
		checkMcErr("ShowHostArtefact", status, err, &rc)
		apps, status, err := mcClient.ShowHostApp(uri, token, showFilter)
		checkMcErr("ShowHostApp", status, err, &rc)
		appInsts, status, err := mcClient.ShowHostAppInst(uri, token, showFilter)
		checkMcErr("ShowHostAppInst", status, err, &rc)

		showData := ormapi.AllData{
			ProviderImages:    images,
			ProviderArtefacts: artefacts,
			ProviderApps:      apps,
			ProviderAppInsts:  appInsts,
		}
		cmpFilterAllData(&showData)
		PrintToYamlFile("show-commands.yml", outputDir, &showData, true)
		*retry = true
		return rc
	}
	if api == "showguestappdata" {
		showFilter := &cli.MapData{
			Namespace: cli.StructNamespace,
			Data:      map[string]interface{}{},
		}
		images, status, err := mcClient.ShowGuestImage(uri, token, showFilter)
		checkMcErr("ShowGuestImage", status, err, &rc)
		apps, status, err := mcClient.ShowGuestApp(uri, token, showFilter)
		checkMcErr("ShowGuestApp", status, err, &rc)

		showData := ormapi.AllData{
			ConsumerImages: images,
			ConsumerApps:   apps,
		}
		cmpFilterAllData(&showData)
		PrintToYamlFile("show-commands.yml", outputDir, &showData, true)
		*retry = true
		return rc
	}
	if api == "getfederationdirect" {
		fedDataIn := FedDataIn{}
		err := ReadYamlFile(apiFile, &fedDataIn, WithVars(vars), ValidateReplacedVars())
		if err != nil {
			fmt.Fprintf(os.Stderr, "error in unmarshal for file %s, %s\n", apiFile, err)
		}
		out := FedDataOut{}
		for _, cons := range fedDataIn.Consumers {
			partner, status, err := mcClient.GetFederationPartner(uri, token, &cons)
			checkMcErr("GetFederationPartner", status, err, &rc)
			if partner != nil {
				out.Partners = append(out.Partners, *partner)
			}
		}
		for _, zone := range fedDataIn.Zones {
			zoneOut, status, err := mcClient.GetFederationZone(uri, token, &zone)
			checkMcErr("GetFederationZone", status, err, &rc)
			if zoneOut != nil {
				out.Zones = append(out.Zones, *zoneOut)
			}
		}
		for _, art := range fedDataIn.Artefacts {
			artOut, status, err := mcClient.GetFederationArtefact(uri, token, &art)
			checkMcErr("GetFederationArtefact", status, err, &rc)
			if artOut != nil {
				out.Artefacts = append(out.Artefacts, *artOut)
			}
		}
		for _, file := range fedDataIn.Files {
			fileOut, status, err := mcClient.GetFederationFile(uri, token, &file)
			checkMcErr("GetFederationFile", status, err, &rc)
			if fileOut != nil {
				out.Files = append(out.Files, *fileOut)
			}
		}
		for _, app := range fedDataIn.Apps {
			appOut, status, err := mcClient.GetFederationApp(uri, token, &app)
			checkMcErr("GetFederationApp", status, err, &rc)
			if appOut != nil {
				out.Apps = append(out.Apps, *appOut)
			}
		}
		for _, inst := range fedDataIn.AppInsts {
			instsOut, status, err := mcClient.GetFederationAppInsts(uri, token, &inst)
			checkMcErr("GetFederationAppInsts", status, err, &rc)
			out.AppInsts = append(out.AppInsts, instsOut...)
		}
		PrintToYamlFile("show-commands.yml", outputDir, &out, true)
		*retry = true
		return rc
	}

	if strings.HasPrefix(api, "showcustommetrics") {
		query := readMcCustomMetricTargetsFile(apiFile, vars)
		metrics, status, err := mcClient.ShowAppV2Metrics(uri, token, query)
		checkMcErr("ShowAppV2Metrics", status, err, &rc)
		if !rc {
			return rc
		}
		// convert showMetrics into something yml compatible
		parsedMetrics := removeTimestampFromPromData(metrics)
		if parsedMetrics != nil {
			cmpFilterMetrics(*parsedMetrics)
			PrintToYamlFile("show-commands.yml", outputDir, parsedMetrics, true)
		}
		*retry = true
		return rc
	}

	if apiFile == "" {
		log.Println("Error: Cannot run MC data APIs without API file")
		return false
	}
	data := readMCDataFile(apiFile, vars)
	dataMap := readMCDataFileMap(apiFile, vars)

	var errs []Err
	switch api {
	case "setfederationguestapikey":
		/* TODO: fix me, this is wrong for now
		output := &AllDataOut{}
		for ii, fd := range data.FederationConsumers {
			if partnerApiKey, found := sharedData[fd.Name]; found {
				fd.ApiKey = partnerApiKey
			}
			_, st, err := mcClient.SetPartnerFederationAPIKey(uri, token, &fd)
			outMcErr(output, fmt.Sprintf("SetPartnerFederationAPIKey[%d]", ii), st, err)
		}
		PrintToYamlFile("api-output.yml", outputDir, output, true)
		errs = output.Errors
		*/
	case "share":
		fallthrough
	case "unshare":
		fallthrough
	case "register":
		fallthrough
	case "deregister":
		output := &AllDataOut{}
		manageFederatorZoneData(api, uri, token, tag, data, dataMap, output, &rc)
		PrintToYamlFile("api-output.yml", outputDir, output, true)
		errs = output.Errors
	case "create":
		output := &AllDataOut{}
		createMcData(uri, token, tag, data, dataMap, sharedData, output, &rc)
		PrintToYamlFile("api-output.yml", outputDir, output, true)
		errs = output.Errors
	case "delete":
		output := &AllDataOut{}
		deleteMcData(uri, token, tag, data, dataMap, sharedData, output, &rc)
		PrintToYamlFile("api-output.yml", outputDir, output, true)
		errs = output.Errors
	case "add":
		fallthrough
	case "remove":
		fallthrough
	case "update":
		output := &AllDataOut{}
		updateMcData(api, uri, token, tag, data, dataMap, output, &rc)
		PrintToYamlFile("api-output.yml", outputDir, output, true)
		errs = output.Errors
	case "showfiltered":
		objTypes := getVarsObjTypes(actionVars)
		dataOut, errs := showMcDataFiltered(uri, token, tag, objTypes, data, &rc)
		if tag == "" {
			cmpFilterAllData(dataOut)
		} else if tag == "noignore" {
			cmpFilterAllDataNoIgnore(dataOut)
		}
		cmpFilterErrs(errs)
		// write both files so we don't accidentally pick up older results
		if errs == nil || len(errs) == 0 {
			dataOut.Sort()
			PrintToYamlFile("show-commands.yml", outputDir, dataOut, true)
			PrintToYamlFile("api-output.yml", outputDir, "", true)
		} else {
			PrintToYamlFile("api-output.yml", outputDir, errs, true)
			PrintToYamlFile("show-commands.yml", outputDir, "", true)
		}
		if tag != "expecterr" {
			*retry = true
		}
	case "stream":
		dataOut := streamMcData(uri, token, tag, data, &rc)
		PrintToYamlFile("show-commands.yml", outputDir, dataOut, true)
	case "restrictedupdateorg":
		val, ok := dataMap["orgs"]
		if !ok {
			fmt.Fprintf(os.Stderr, "mcapi: no orgs in %v\n", dataMap)
			os.Exit(1)
		}
		arr, ok := val.([]interface{})
		if !ok {
			fmt.Fprintf(os.Stderr, "mcapi: orgs in map not []interface{}: %v\n", dataMap)
			os.Exit(1)
		}
		output := &AllDataOut{}
		for ii, orgIntf := range arr {
			var orgMap map[string]interface{}
			orgObj, err := json.Marshal(orgIntf)
			if err != nil {
				log.Printf("error in marshal org for %v: %v\n", orgIntf, err)
				return false
			}
			err = json.Unmarshal(orgObj, &orgMap)
			if err != nil {
				log.Printf("error in unmarshal org for %s: %v\n", string(orgObj), err)
				return false
			}
			// Data is really in Yaml namespace, because json
			// marshal/unmarshal is preserving the key names
			// because there's no object to use tag names from.
			// And we assume yaml and args are the same.
			mdata := &cli.MapData{
				Namespace: cli.ArgsNamespace,
				Data:      orgMap,
			}
			st, err := mcClient.RestrictedUpdateOrg(uri, token, mdata)
			outMcErr(output, fmt.Sprintf("RestrictedUpdateOrg[%d]", ii), st, err)
		}
		errs = output.Errors
	default:
		log.Printf("unrecognized api command %s\n", api)
		return false
	}
	if tag != "expecterr" && errs != nil {
		// no errors expected
		for _, err := range errs {
			log.Printf("\"%s\" %s failed %s/%d\n", api, err.Desc, err.Err, err.Status)
			rc = false
		}
	}
	return rc
}

func readUsersFiles(file string, vars map[string]string) []ormapi.User {
	users := []ormapi.User{}
	files := strings.Split(file, ",")
	for _, file := range files {
		fileusers := []ormapi.User{}
		err := ReadYamlFile(file, &fileusers, WithVars(vars), ValidateReplacedVars())
		if err != nil {
			if !IsYamlOk(err, "mcusers") {
				fmt.Fprintf(os.Stderr, "error in unmarshal for file %s\n", file)
				os.Exit(1)
			}
		}
		users = append(users, fileusers...)
	}
	return users
}

func readMCDataFile(file string, vars map[string]string) *ormapi.AllData {
	data := ormapi.AllData{}
	err := ReadYamlFile(file, &data, WithVars(vars), ValidateReplacedVars())
	if err != nil {
		if !IsYamlOk(err, "mcdata") {
			fmt.Fprintf(os.Stderr, "error in unmarshal for file %s\n", file)
			os.Exit(1)
		}
	}
	return &data
}

func readMCDataFileMap(file string, vars map[string]string) map[string]interface{} {
	dataMap := make(map[string]interface{})
	err := ReadYamlFile(file, &dataMap, WithVars(vars), ValidateReplacedVars())
	if err != nil {
		if !IsYamlOk(err, "mcdata") {
			fmt.Fprintf(os.Stderr, "error in unmarshal for file %s\n", file)
			os.Exit(1)
		}
	}
	return dataMap
}

func getRegionDataMap(dataMap map[string]interface{}, index int) interface{} {
	val, ok := dataMap["regiondata"]
	if !ok {
		fmt.Fprintf(os.Stderr, "mcapi: no regiondata in %v\n", dataMap)
		os.Exit(1)
	}
	arr, ok := val.([]interface{})
	if !ok {
		fmt.Fprintf(os.Stderr, "mcapi: regiondata in map not []interface{}: %v\n", dataMap)
		os.Exit(1)
	}
	if len(arr) <= index {
		fmt.Fprintf(os.Stderr, "mcapi: regiondata lookup index %d out of bounds in %v\n", index, dataMap)
		os.Exit(1)
	}
	return arr[index]
}

func readMCMetricTargetsFile(file string, vars map[string]string) *MetricTargets {
	targets := MetricTargets{}
	err := ReadYamlFile(file, &targets, WithVars(vars), ValidateReplacedVars())
	if err != nil {
		if !IsYamlOk(err, "mcdata") {
			fmt.Fprintf(os.Stderr, "error in unmarshal for file %s\n", file)
			os.Exit(1)
		}
	}
	return &targets
}

func readMcCustomMetricTargetsFile(file string, vars map[string]string) *ormapi.RegionCustomAppMetrics {
	filter := ormapi.RegionCustomAppMetrics{}
	err := ReadYamlFile(file, &filter, WithVars(vars), ValidateReplacedVars())
	if err != nil {
		if !IsYamlOk(err, "mcdata") {
			fmt.Fprintf(os.Stderr, "error in unmarshal for file %s\n", file)
			os.Exit(1)
		}
	}
	return &filter
}

func getLoginToken(curUserFile, outputDir string, actionVars, vars map[string]string) (string, bool) {
	username, ok := actionVars["username"]
	if !ok {
		if curUserFile == "" {
			log.Println("Error: Cannot run MC APIs without current user file or username actionVar")
			return "", false
		}
		users := readUsersFiles(curUserFile, vars)
		if len(users) == 0 {
			log.Printf("no user in %s to run MC api\n", curUserFile)
			return "", false
		}
		username = users[0].Name
	}
	fname := getTokenFile(username, outputDir)
	token, err := ioutil.ReadFile(fname)
	if err != nil {
		log.Printf("failed to read token file %s: %v\n", fname, err)
		return "", false
	}
	return string(token), true
}

func doLogin(uri, outputDir string, user *ormapi.User, otp string, rc *bool) {
	token, _, err := mcClient.DoLogin(uri, user.Name, user.Passhash, otp, orm.NoApiKeyId, orm.NoApiKey)
	checkMcErr("DoLogin", http.StatusOK, err, rc)
	if err == nil {
		fname := getTokenFile(user.Name, outputDir)
		err = ioutil.WriteFile(fname, []byte(token), 0666)
		if err != nil {
			log.Printf("failed to save token to file %s: %s\n", fname, err)
			*rc = false
		}
	}
}

func outMcErr(output *AllDataOut, desc string, status int, err error) {
	if err == nil && status != http.StatusOK {
		err = fmt.Errorf("status: %d\n", status)
	}
	if err != nil {
		mcerr := Err{
			Desc:   desc,
			Status: status,
			Err:    err.Error(),
		}
		output.Errors = append(output.Errors, mcerr)
	}
}

func checkMcErr(msg string, status int, err error, rc *bool) {
	if strings.HasPrefix(msg, "Show") || strings.HasPrefix(msg, "show") {
		if status == http.StatusForbidden {
			err = nil
			status = http.StatusOK
		}
	}
	if err != nil || status != http.StatusOK {
		log.Printf("%s failed %v/%d\n", msg, err, status)
		*rc = false
	}
}

func checkMcCtrlErr(msg string, status int, err error, rc *bool) {
	if err != nil && strings.Contains(err.Error(), "no such host") {
		// trying to show dummy controller that doesn't exist
		log.Printf("ignoring no host err for %s, %v\n", msg, err)
		return
	}
	if err != nil || status != http.StatusOK {
		log.Printf("%s failed %v/%d\n", msg, err, status)
		*rc = false
	}
}

func hasMod(mod string, mods []string) bool {
	for _, a := range mods {
		if a == mod {
			return true
		}
	}
	return false
}

func showMcData(uri, token, tag string, objTypes edgeproto.AllSelector, rc *bool) *ormapi.AllData {
	showFilter := &cli.MapData{
		Namespace: cli.StructNamespace,
		Data:      map[string]interface{}{},
	}
	showData := &ormapi.AllData{}
	ctrls, status, err := mcClient.ShowController(uri, token, showFilter)
	checkMcErr("ShowControllers", status, err, rc)
	if objTypes.Has("controllers") {
		showData.Controllers = ctrls
	}
	if objTypes.Has("orgs") {
		orgs, status, err := mcClient.ShowOrg(uri, token, showFilter)
		checkMcErr("ShowOrgs", status, err, rc)
		showData.Orgs = orgs
	}
	if objTypes.Has("billingorgs") {
		bOrgs, status, err := mcClient.ShowBillingOrg(uri, token, showFilter)
		checkMcErr("ShowBillingOrgs", status, err, rc)
		showData.BillingOrgs = bOrgs
	}
	if objTypes.Has("roles") {
		roles, status, err := mcClient.ShowUserRole(uri, token, showFilter)
		checkMcErr("ShowRoles", status, err, rc)
		showData.Roles = roles
	}
	if objTypes.Has("cloudletpoolaccessinvitations") {
		invites, status, err := mcClient.ShowCloudletPoolAccessInvitation(uri, token, showFilter)
		checkMcErr("ShowCloudletPoolAccessInvitations", status, err, rc)
		showData.CloudletPoolAccessInvitations = invites
	}
	if objTypes.Has("cloudletpoolaccessresponses") {
		responses, status, err := mcClient.ShowCloudletPoolAccessResponse(uri, token, showFilter)
		checkMcErr("ShowCloudletPoolAccessResponses", status, err, rc)
		showData.CloudletPoolAccessResponses = responses
	}

	for _, ctrl := range ctrls {
		client := testutil.TestClient{
			Region:          ctrl.Region,
			Uri:             uri,
			Token:           token,
			McClient:        mcClient,
			IgnoreForbidden: true, // avoid test failure for ShowSettings
		}
		filter := &edgeproto.AllData{}
		appdata := &edgeproto.AllData{}
		run := edgetestutil.NewRun(&client, context.Background(), "show", rc)
		edgetestutil.RunAllDataShowApis(run, filter, objTypes, appdata)
		run.CheckErrs(fmt.Sprintf("show region %s", ctrl.Region), tag)
		if appdata.IsEmpty() {
			continue
		}
		rd := ormapi.RegionData{
			Region:  ctrl.Region,
			AppData: *appdata,
		}
		showData.RegionData = append(showData.RegionData, rd)
	}
	return showData
}

func showMcDataFiltered(uri, token, tag string, objTypes edgeproto.AllSelector, data *ormapi.AllData, rc *bool) (*ormapi.AllData, []edgetestutil.Err) {
	dataOut := &ormapi.AllData{}

	// currently only controller APIs support filtering
	for ii, _ := range data.RegionData {
		region := data.RegionData[ii].Region
		filter := &data.RegionData[ii].AppData

		rd := ormapi.RegionData{}
		rd.Region = region

		client := testutil.TestClient{
			Region:          region,
			Uri:             uri,
			Token:           token,
			McClient:        mcClient,
			IgnoreForbidden: true,
		}
		run := edgetestutil.NewRun(&client, context.Background(), "showfiltered", rc)
		edgetestutil.RunAllDataShowApis(run, filter, objTypes, &rd.AppData)
		if tag == "expecterr" {
			return nil, run.Errs
		} else {
			run.CheckErrs(fmt.Sprintf("show-filtered region %s", region), tag)
		}
		dataOut.RegionData = append(dataOut.RegionData, rd)
	}
	return dataOut, nil
}

func getRegionAppDataFromMap(regionDataMap interface{}) map[string]interface{} {
	regionData, ok := regionDataMap.(map[string]interface{})
	if !ok {
		fmt.Fprintf(os.Stderr, "invalid data in regiondata: %v\n", regionDataMap)
		os.Exit(1)
	}
	appData, ok := regionData["appdata"].(map[string]interface{})
	if !ok {
		fmt.Fprintf(os.Stderr, "invalid data in appdata: %v\n", regionData["appdata"])
		os.Exit(1)
	}
	return appData
}

func runRegionDataApi(mcClient *mctestclient.Client, uri, token, tag string, rd *ormapi.RegionData, rdMap interface{}, rc *bool, mode string, apicb edgetestutil.RunAllDataApiCallback) *edgetestutil.AllDataOut {
	appDataMap := getRegionAppDataFromMap(rdMap)
	client := testutil.TestClient{
		Region:   rd.Region,
		Uri:      uri,
		Token:    token,
		McClient: mcClient,
	}
	output := &edgetestutil.AllDataOut{}
	run := edgetestutil.NewRun(&client, context.Background(), mode, rc)

	switch mode {
	case "create":
		fallthrough
	case "add":
		fallthrough
	case "update":
		edgetestutil.RunAllDataApis(run, &rd.AppData, appDataMap, output, apicb)
	case "remove":
		fallthrough
	case "delete":
		edgetestutil.RunAllDataReverseApis(run, &rd.AppData, appDataMap, output, apicb)
	}
	run.CheckErrs(fmt.Sprintf("%s region %s", mode, rd.Region), tag)
	return output
}

func createMcData(uri, token, tag string, data *ormapi.AllData, dataMap map[string]interface{}, sharedData map[string]string, output *AllDataOut, rc *bool) {
	for ii, ctrl := range data.Controllers {
		st, err := mcClient.CreateController(uri, token, &ctrl)
		outMcErr(output, fmt.Sprintf("CreateController[%d]", ii), st, err)
	}
	for ii, org := range data.Orgs {
		st, err := mcClient.CreateOrg(uri, token, &org)
		outMcErr(output, fmt.Sprintf("CreateOrg[%d]", ii), st, err)
	}
	for ii, bOrg := range data.BillingOrgs {
		st, err := mcClient.CreateBillingOrg(uri, token, &bOrg)
		outMcErr(output, fmt.Sprintf("CreateBillingOrg[%d]", ii), st, err)
	}
	for ii, role := range data.Roles {
		st, err := mcClient.AddUserRole(uri, token, &role)
		outMcErr(output, fmt.Sprintf("AddUserRole[%d]", ii), st, err)
	}
	// CloudletPoolAccess must be run after regional CloudletPools, because
	// they require the CloudletPools to exist, but before
	// AppInst/ClusterInst since they affect the RBAC for them.
	// We use a callback to intersperse their create in between the regional
	// data creates.
	// We also need to handle the case where there's no regional data,
	// so the callback func is not called.
	regions := getRegionsForCb(data)
	apiRegionCb := func(done, region string) {
		// this is done after cloudletpools are created
		if done == "cloudletpools" {
			for ii, oc := range data.CloudletPoolAccessInvitations {
				if oc.Region != region {
					continue
				}
				st, err := mcClient.CreateCloudletPoolAccessInvitation(uri, token, &oc)
				outMcErr(output, fmt.Sprintf("CreateCloudletPoolAccessInvitation[%d]", ii), st, err)
			}
			for ii, oc := range data.CloudletPoolAccessResponses {
				if oc.Region != region {
					continue
				}
				st, err := mcClient.CreateCloudletPoolAccessResponse(uri, token, &oc)
				outMcErr(output, fmt.Sprintf("CreateCloudletPoolAccessResponse[%d]", ii), st, err)
			}
		}
		delete(regions, region)
	}
	for ii, rd := range data.RegionData {
		apicb := func(done string) {
			apiRegionCb(done, rd.Region)
		}
		rdm := getRegionDataMap(dataMap, ii)
		rdout := runRegionDataApi(mcClient, uri, token, tag, &rd, rdm, rc, "create", apicb)
		output.RegionData = append(output.RegionData, *rdout)
	}
	for region, _ := range regions {
		// process MC data that was waiting on regional apis, but where
		// no regional data was present so no regional apis where called.
		apiRegionCb("cloudletpools", region)
	}
	for ii, ar := range data.AlertReceivers {
		st, err := mcClient.CreateAlertReceiver(uri, token, &ar)
		outMcErr(output, fmt.Sprintf("CreateAlertReceiver[%d]", ii), st, err)
	}
	for ii, fd := range data.FederationProviders {
		fedOut, st, err := mcClient.CreateFederationHost(uri, token, &fd)
		if err == nil {
			sharedData[fd.Name+"-id"] = fedOut.ClientId
			sharedData[fd.Name+"-key"] = fedOut.ClientKey
		}
		outMcErr(output, fmt.Sprintf("CreateFederationHost[%d]", ii), st, err)
	}
	for ii, fd := range data.ProviderZoneBases {
		_, st, err := mcClient.CreateHostZoneBase(uri, token, &fd)
		outMcErr(output, fmt.Sprintf("CreateHostZoneBase[%d]", ii), st, err)
	}
	for ii, fd := range data.FederationConsumers {
		if partnerApiId, found := sharedData[fd.Name+"-id"]; found {
			fd.ProviderClientId = partnerApiId
		}
		if partnerApiKey, found := sharedData[fd.Name+"-key"]; found {
			fd.ProviderClientKey = partnerApiKey
		}
		_, st, err := mcClient.CreateFederationGuest(uri, token, &fd)
		outMcErr(output, fmt.Sprintf("CreateFederationGuest[%d]", ii), st, err)
	}
	for ii, fd := range data.ConsumerImages {
		_, st, err := mcClient.CreateGuestImage(uri, token, &fd)
		outMcErr(output, fmt.Sprintf("CreateGuestImage[%d]", ii), st, err)
	}
	for ii, fd := range data.ConsumerApps {
		_, st, err := mcClient.OnboardGuestApp(uri, token, &fd)
		outMcErr(output, fmt.Sprintf("OnboardGuestApp[%d]", ii), st, err)
	}
}

func deleteMcData(uri, token, tag string, data *ormapi.AllData, dataMap map[string]interface{}, sharedData map[string]string, output *AllDataOut, rc *bool) {
	for ii, ar := range data.AlertReceivers {
		st, err := mcClient.DeleteAlertReceiver(uri, token, &ar)
		outMcErr(output, fmt.Sprintf("DeleteAlertReceiver[%d]", ii), st, err)
	}
	// see comments in createMcData
	regions := getRegionsForCb(data)
	apiRegionCb := func(next, region string) {
		// these must be done before CloudletPools
		if next == "cloudletpools" {
			for ii, oc := range data.CloudletPoolAccessResponses {
				if oc.Region != region {
					continue
				}
				st, err := mcClient.DeleteCloudletPoolAccessResponse(uri, token, &oc)
				outMcErr(output, fmt.Sprintf("DeleteCloudletPoolAccessResponse[%d]", ii), st, err)
			}
			for ii, oc := range data.CloudletPoolAccessInvitations {
				if oc.Region != region {
					continue
				}
				st, err := mcClient.DeleteCloudletPoolAccessInvitation(uri, token, &oc)
				outMcErr(output, fmt.Sprintf("DeleteCloudletPoolAccessInvitation[%d]", ii), st, err)
			}
		}
		delete(regions, region)
	}
	for ii, rd := range data.RegionData {
		apicb := func(next string) {
			apiRegionCb(next, rd.Region)
		}
		rdm := getRegionDataMap(dataMap, ii)
		rdout := runRegionDataApi(mcClient, uri, token, tag, &rd, rdm, rc, "delete", apicb)
		output.RegionData = append(output.RegionData, *rdout)
	}
	for region, _ := range regions {
		// unused callbacks
		apiRegionCb("cloudletpools", region)
	}
	for ii, fd := range data.ConsumerApps {
		_, st, err := mcClient.DeboardGuestApp(uri, token, &fd)
		outMcErr(output, fmt.Sprintf("DeboardGuestApp[%d]", ii), st, err)
	}
	for ii, fd := range data.ConsumerImages {
		_, st, err := mcClient.DeleteGuestImage(uri, token, &fd)
		outMcErr(output, fmt.Sprintf("DeleteGuestImage[%d]", ii), st, err)
	}
	for ii, fd := range data.FederationConsumers {
		_, st, err := mcClient.DeleteFederationGuest(uri, token, &fd)
		outMcErr(output, fmt.Sprintf("DeleteFederationGuest[%d]", ii), st, err)
	}
	for ii, fd := range data.ProviderZoneBases {
		_, st, err := mcClient.DeleteHostZoneBase(uri, token, &fd)
		outMcErr(output, fmt.Sprintf("DeleteHostZoneBase[%d]", ii), st, err)
	}
	for ii, fd := range data.FederationProviders {
		_, st, err := mcClient.DeleteFederationHost(uri, token, &fd)
		if err == nil {
			delete(sharedData, fd.Name+"-id")
			delete(sharedData, fd.Name+"-key")
		}
		outMcErr(output, fmt.Sprintf("DeleteFederationHost[%d]", ii), st, err)
	}
	for ii, bOrg := range data.BillingOrgs {
		st, err := mcClient.DeleteBillingOrg(uri, token, &bOrg)
		outMcErr(output, fmt.Sprintf("DeleteBillingOrg[%d]", ii), st, err)
	}
	for ii, org := range data.Orgs {
		st, err := mcClient.DeleteOrg(uri, token, &org)
		outMcErr(output, fmt.Sprintf("DeleteOrg[%d]", ii), st, err)
	}
	for ii, role := range data.Roles {
		st, err := mcClient.RemoveUserRole(uri, token, &role)
		outMcErr(output, fmt.Sprintf("RemoveUserRole[%d]", ii), st, err)
	}
	for ii, ctrl := range data.Controllers {
		st, err := mcClient.DeleteController(uri, token, &ctrl)
		outMcErr(output, fmt.Sprintf("DeleteController[%d]", ii), st, err)
	}
}

func manageFederatorZoneData(mode, uri, token, tag string, data *ormapi.AllData, dataMap map[string]interface{}, output *AllDataOut, rc *bool) {
	switch mode {
	case "share":
		for ii, fd := range data.ProviderZones {
			share := ormapi.FederatedZoneShareRequest{
				FedHost: fd.ProviderName,
				Zones:   []string{fd.ZoneId},
			}
			_, st, err := mcClient.ShareHostZone(uri, token, &share)
			outMcErr(output, fmt.Sprintf("ShareHostZone[%d]", ii), st, err)
		}
	case "unshare":
		for ii, fd := range data.ProviderZones {
			share := ormapi.FederatedZoneShareRequest{
				FedHost: fd.ProviderName,
				Zones:   []string{fd.ZoneId},
			}
			_, st, err := mcClient.UnshareHostZone(uri, token, &share)
			outMcErr(output, fmt.Sprintf("UnshareHostZone[%d]", ii), st, err)
		}
	case "register":
		for ii, fd := range data.ConsumerZones {
			req := ormapi.FederatedZoneRegRequest{
				FedGuest: fd.ConsumerName,
				Zones:    []string{fd.ZoneId},
			}
			_, st, err := mcClient.RegisterGuestZone(uri, token, &req)
			outMcErr(output, fmt.Sprintf("RegisterGuestZone[%d]", ii), st, err)
		}
	case "deregister":
		for ii, fd := range data.ConsumerZones {
			req := ormapi.FederatedZoneRegRequest{
				FedGuest: fd.ConsumerName,
				Zones:    []string{fd.ZoneId},
			}
			_, st, err := mcClient.DeregisterGuestZone(uri, token, &req)
			outMcErr(output, fmt.Sprintf("DeregisterGuestZone[%d]", ii), st, err)
		}
	}
}

func updateMcData(mode, uri, token, tag string, data *ormapi.AllData, dataMap map[string]interface{}, output *AllDataOut, rc *bool) {
	for ii, rd := range data.RegionData {
		rdm := getRegionDataMap(dataMap, ii)
		rdout := runRegionDataApi(mcClient, uri, token, tag, &rd, rdm, rc, mode, edgetestutil.NoApiCallback)
		output.RegionData = append(output.RegionData, *rdout)
	}
}

func getRegionsForCb(data *ormapi.AllData) map[string]struct{} {
	regions := make(map[string]struct{})
	for _, oc := range data.CloudletPoolAccessInvitations {
		regions[oc.Region] = struct{}{}
	}
	for _, oc := range data.CloudletPoolAccessResponses {
		regions[oc.Region] = struct{}{}
	}
	return regions
}

func showMcMetricsAll(uri, token string, targets *MetricTargets, rc *bool) *ormapi.AllMetrics {
	appQuery := ormapi.RegionAppInstMetrics{
		Region:   "local",
		AppInst:  targets.AppInstKey,
		Selector: "*",
		MetricsCommon: ormapi.MetricsCommon{
			Limit: 1,
		},
	}
	appMetrics, status, err := mcClient.ShowAppMetrics(uri, token, &appQuery)
	if err != nil {
		appMetrics = &ormapi.AllMetrics{}
	}
	checkMcErr("ShowAppMetrics", status, err, rc)
	clusterQuery := ormapi.RegionClusterInstMetrics{
		Region:      "local",
		ClusterInst: targets.ClusterInstKey,
		Selector:    "*",
		MetricsCommon: ormapi.MetricsCommon{
			Limit: 1,
		},
	}
	clusterMetrics, status, err := mcClient.ShowClusterMetrics(uri, token, &clusterQuery)
	checkMcErr("ShowClusterMetrics", status, err, rc)
	// combine them into one AllMetrics
	if err == nil {
		appMetrics.Data = append(appMetrics.Data, clusterMetrics.Data...)
	}
	return appMetrics
}

func showMcEvents(uri, token string, targets *MetricTargets, rc *bool) *ormapi.AllMetrics {
	appQuery := ormapi.RegionAppInstEvents{
		Region:  "local",
		AppInst: targets.AppInstKey,
		MetricsCommon: ormapi.MetricsCommon{
			Limit: 1,
		},
	}
	appMetrics, status, err := mcClient.ShowAppEvents(uri, token, &appQuery)
	checkMcErr("ShowAppEvents", status, err, rc)
	if err != nil {
		appMetrics = &ormapi.AllMetrics{}
	}
	clusterQuery := ormapi.RegionClusterInstEvents{
		Region:      "local",
		ClusterInst: targets.ClusterInstKey,
		MetricsCommon: ormapi.MetricsCommon{
			Limit: 1,
		},
	}
	clusterMetrics, status, err := mcClient.ShowClusterEvents(uri, token, &clusterQuery)
	checkMcErr("ShowClusterEvents", status, err, rc)
	if err == nil {
		appMetrics.Data = append(appMetrics.Data, clusterMetrics.Data...)
	}
	cloudletQuery := ormapi.RegionCloudletEvents{
		Region:   "local",
		Cloudlet: targets.CloudletKey,
		MetricsCommon: ormapi.MetricsCommon{
			Limit: 1,
		},
	}
	cloudletMetrics, status, err := mcClient.ShowCloudletEvents(uri, token, &cloudletQuery)
	checkMcErr("ShowCloudletEvents", status, err, rc)
	if err == nil {
		appMetrics.Data = append(appMetrics.Data, cloudletMetrics.Data...)
	}
	return appMetrics
}

// same end result as showMcMetricsAll, but gets each metric individually instead of in a batch
func showMcMetricsSep(uri, token string, targets *MetricTargets, rc *bool) *ormapi.AllMetrics {
	allMetrics := ormapi.AllMetrics{Data: make([]ormapi.MetricData, 0)}
	appQuery := ormapi.RegionAppInstMetrics{
		Region:  "local",
		AppInst: targets.AppInstKey,
		MetricsCommon: ormapi.MetricsCommon{
			Limit: 1,
		},
	}
	for _, selector := range E2eAppSelectors {
		appQuery.Selector = selector
		appMetric, status, err := mcClient.ShowAppMetrics(uri, token, &appQuery)
		checkMcErr("ShowApp"+strings.Title(selector), status, err, rc)
		if err == nil {
			allMetrics.Data = append(allMetrics.Data, appMetric.Data...)
		}
	}

	clusterQuery := ormapi.RegionClusterInstMetrics{
		Region:      "local",
		ClusterInst: targets.ClusterInstKey,
		MetricsCommon: ormapi.MetricsCommon{
			Limit: 1,
		},
	}
	for _, selector := range E2eClusterSelectors {
		clusterQuery.Selector = selector
		clusterMetric, status, err := mcClient.ShowClusterMetrics(uri, token, &clusterQuery)
		checkMcErr("ShowCluster"+strings.Title(selector), status, err, rc)
		if err == nil {
			allMetrics.Data = append(allMetrics.Data, clusterMetric.Data...)
		}
	}
	return &allMetrics
}

func showMcClientApiMetrics(uri, token string, targets *MetricTargets, rc *bool) *ormapi.AllMetrics {
	allMetrics := ormapi.AllMetrics{Data: make([]ormapi.MetricData, 0)}
	for _, method := range ApiMethods {
		clientApiUsageQuery := ormapi.RegionClientApiUsageMetrics{
			Region: "local",
			AppKey: targets.AppKey,
			Method: method,
			MetricsCommon: ormapi.MetricsCommon{
				Limit: 1,
			},
		}
		for _, selector := range ormapi.ClientApiUsageSelectors {
			clientApiUsageQuery.Selector = selector
			clientApiUsageMetric, status, err := mcClient.ShowClientApiUsageMetrics(uri, token, &clientApiUsageQuery)
			checkMcErr("ShowClientApiUsage"+strings.Title(selector), status, err, rc)
			if err == nil {
				allMetrics.Data = append(allMetrics.Data, clientApiUsageMetric.Data...)
			}
		}
	}
	return &allMetrics
}

func showMcClientAppMetrics(uri, token string, targets *MetricTargets, rc *bool) *ormapi.AllMetrics {
	allMetrics := ormapi.AllMetrics{Data: make([]ormapi.MetricData, 0)}
	clientAppUsageQuery := ormapi.RegionClientAppUsageMetrics{
		Region:     "local",
		AppInstKey: targets.AppInstKey,
		MetricsCommon: ormapi.MetricsCommon{
			Limit: 1,
		},
	}
	for _, selector := range ormapi.ClientAppUsageSelectors {
		if selector == "latency" {
			clientAppUsageQuery.LocationTile = targets.LocationTileLatency
		} else {
			clientAppUsageQuery.LocationTile = targets.LocationTileDeviceInfo
		}
		clientAppUsageQuery.Selector = selector
		clientAppUsageMetric, status, err := mcClient.ShowClientAppUsageMetrics(uri, token, &clientAppUsageQuery)
		checkMcErr("ShowClientAppUsage"+strings.Title(selector), status, err, rc)
		if err == nil {
			allMetrics.Data = append(allMetrics.Data, clientAppUsageMetric.Data...)
		}
	}
	return &allMetrics
}

func showMcClientCloudletMetrics(uri, token string, targets *MetricTargets, rc *bool) *ormapi.AllMetrics {
	allMetrics := ormapi.AllMetrics{Data: make([]ormapi.MetricData, 0)}
	clientCloudletUsageQuery := ormapi.RegionClientCloudletUsageMetrics{
		Region:   "local",
		Cloudlet: targets.CloudletKey,
		MetricsCommon: ormapi.MetricsCommon{
			Limit: 1,
		},
	}
	for _, selector := range ormapi.ClientCloudletUsageSelectors {
		if selector == "latency" {
			clientCloudletUsageQuery.LocationTile = targets.LocationTileLatency
		} else {
			clientCloudletUsageQuery.LocationTile = targets.LocationTileDeviceInfo
		}
		clientCloudletUsageQuery.Selector = selector
		clientCloudletUsageMetric, status, err := mcClient.ShowClientCloudletUsageMetrics(uri, token, &clientCloudletUsageQuery)
		checkMcErr("ShowClientCloudletUsage"+strings.Title(selector), status, err, rc)
		if err == nil {
			allMetrics.Data = append(allMetrics.Data, clientCloudletUsageMetric.Data...)
		}
	}
	return &allMetrics
}

type runCommandMCData struct {
	Request        ormapi.RegionExecRequest
	ExpectedOutput string
}

func runMcExec(api, uri, apiFile, curUserFile, outputDir string, mods []string, actionVars, vars, sharedData map[string]string) bool {
	token, rc := getLoginToken(curUserFile, outputDir, actionVars, vars)
	if !rc {
		return false
	}

	data := runCommandMCData{}
	err := ReadYamlFile(apiFile, &data, WithVars(vars), ValidateReplacedVars())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error in unmarshal for file %s, %v\n", apiFile, err)
		return false
	}

	log.Printf("Using MC URI %s", uri)
	// Regardless of hasMod, use `mcctl` to run exec api's, as exec output
	// requires additional connections to websocket to read output,
	// which is already done as part of mcctl run
	cliclient := cliwrapper.NewClient()
	cliclient.DebugLog = true
	cliclient.SkipVerify = true
	mcClient := mctestclient.NewClient(cliclient)

	var out string
	if api == "runcommand" {
		out, _, err = mcClient.RunCommandCli(uri, token, &data.Request)
	} else if api == "accesscloudlet" {
		out, _, err = mcClient.AccessCloudletCli(uri, token, &data.Request)
	} else {
		out, _, err = mcClient.ShowLogsCli(uri, token, &data.Request)
	}
	if err != nil {
		log.Printf("Error running %s API %v\n", api, err)
		return false
	}
	log.Printf("Exec %s output: %s\n", api, out)
	actual := strings.TrimSpace(out)
	if actual != data.ExpectedOutput {
		log.Printf("Did not get expected output: %s\n", data.ExpectedOutput)
		return false
	}
	return true
}

var eventsStartTimeFile = "events-starttime"

func getTokenFile(username, outputDir string) string {
	return outputDir + "/" + username + ".token"
}

func runMcEvents(api, uri, apiFile, curUserFile, outputDir string, mods []string, vars map[string]string, sharedData map[string]string, retry *bool) bool {
	log.Printf("Running %s MC events APIs for %s %v\n", api, apiFile, mods)

	if apiFile == "" {
		log.Println("Error: Cannot run MC events APIs without API file")
		return false
	}

	rc := true
	if api == "eventssetup" {
		// Set the current time for events and event terms queries
		// so previous iterations of tests don't affect the search.
		// need a tiny bit of time to not capture events from previous
		// command
		fname := getTokenFile(eventsStartTimeFile, outputDir)
		err := ioutil.WriteFile(fname, []byte(time.Now().Format(time.RFC3339Nano)), 0644)
		if err != nil {
			log.Printf("Write events start time file %s failed, %v\n", fname, err)
			rc = false
		}

		// Clear our edgeeventsfindcloudlet.yml, so that we upload deviceinfo stats on FindCloudlet each time
		// Otherwise mc apis will pull metrics from other findcloudlet calls
		err = ioutil.WriteFile(outputDir+"/"+"edgeeventfindcloudlet.yml", []byte{}, 0644)
		if err != nil {
			log.Printf("Failed to clear contents of edgeeventfindcloudlet.yml\n")
			rc = false
		}

		return rc
	}

	users := readUsersFiles(curUserFile, vars)
	if len(users) == 0 {
		log.Printf("no user to run MC audit api\n")
		return false
	}
	fname := getTokenFile(users[0].Name, outputDir)
	out, err := ioutil.ReadFile(fname)
	if err != nil {
		log.Printf("Read token file %s failed, %v\n", fname, err)
		return false
	}
	token := string(out)

	fname = getTokenFile(eventsStartTimeFile, outputDir)
	out, err = ioutil.ReadFile(fname)
	if err != nil {
		log.Printf("Read file %s failed, %v\n", fname, err)
		return false
	}
	starttime, err := time.Parse(time.RFC3339Nano, string(out))
	if err != nil {
		log.Printf("parse events start time %s failed, %v\n", string(out), err)
		return false
	}

	query := []node.EventSearch{}
	err = ReadYamlFile(apiFile, &query, WithVars(vars), ValidateReplacedVars())
	if err != nil {
		if !IsYamlOk(err, "events") {
			fmt.Fprintf(os.Stderr, "error in unmarshal for file %s\n", apiFile)
			os.Exit(1)
		}
	}
	switch api {
	case "eventsshow":
		var results []EventSearch
		for _, q := range query {
			if q.TimeRange.StartTime.IsZero() {
				q.TimeRange.StartTime = starttime
			}
			resp, status, err := mcClient.ShowEvents(uri, token, &q)
			checkMcErr("ShowEvents", status, err, &rc)
			results = append(results, EventSearch{
				Search:  q,
				Results: resp,
			})
		}
		cmpFilterEventData(results)
		PrintToYamlFile("show-commands.yml", outputDir, results, true)
	case "eventsfind":
		var results []EventSearch
		for _, q := range query {
			if q.TimeRange.StartTime.IsZero() {
				q.TimeRange.StartTime = starttime
			}
			resp, status, err := mcClient.FindEvents(uri, token, &q)
			checkMcErr("FindEvents", status, err, &rc)
			results = append(results, EventSearch{
				Search:  q,
				Results: resp,
			})
		}
		PrintToYamlFile("show-commands.yml", outputDir, results, true)
	case "eventsterms":
		var results []EventTerms
		for _, q := range query {
			if q.TimeRange.StartTime.IsZero() {
				q.TimeRange.StartTime = starttime
			}
			resp, status, err := mcClient.EventTerms(uri, token, &q)
			checkMcErr("EventTerms", status, err, &rc)
			results = append(results, EventTerms{
				Search: q,
				Terms:  resp,
			})
		}
		cmpFilterEventTerms(results)
		PrintToYamlFile("show-commands.yml", outputDir, results, true)
	default:
		log.Printf("invalid mcapi action %s\n", api)
		return false
	}
	*retry = true
	return rc
}

var spansEndTimeFile = "spans-endtime"

func runMcSpans(api, uri, apiFile, curUserFile, outputDir string, mods []string, vars map[string]string, retry *bool) bool {
	log.Printf("Running %s MC spans APIs for %s %v\n", api, apiFile, mods)

	if api == "spansendtime" {
		// It takes time for ES in docker on Mac to index
		// new spans for search. Instead of waiting, we set an end
		// time early in the test suite and then run a check at the
		// end of the test suite. This should leave enough time
		// in between for ES to finish indexing.
		fname := getTokenFile(spansEndTimeFile, outputDir)
		err := ioutil.WriteFile(fname, []byte(time.Now().Format(time.RFC3339Nano)), 0644)
		if err != nil {
			log.Printf("Write spans end time file %s failed, %v\n", fname, err)
			return false
		}
		return true
	}

	if apiFile == "" {
		log.Println("Error: Cannot run MC spans APIs without API file")
		return false
	}

	rc := true
	users := readUsersFiles(curUserFile, vars)
	if len(users) == 0 {
		log.Printf("no user to run MC spans api\n")
		return false
	}
	fname := getTokenFile(users[0].Name, outputDir)
	out, err := ioutil.ReadFile(fname)
	if err != nil {
		log.Printf("Read token file %s failed, %v\n", fname, err)
		return false
	}
	token := string(out)

	fname = getTokenFile(spansEndTimeFile, outputDir)
	out, err = ioutil.ReadFile(fname)
	if err != nil {
		log.Printf("Read file %s failed, %v\n", fname, err)
		return false
	}
	endtime, err := time.Parse(time.RFC3339Nano, string(out))
	if err != nil {
		log.Printf("parse spans end time %s failed, %v\n", string(out), err)
		return false
	}

	query := []node.SpanSearch{}
	err = ReadYamlFile(apiFile, &query, WithVars(vars), ValidateReplacedVars())
	if err != nil {
		if !IsYamlOk(err, "spans") {
			fmt.Fprintf(os.Stderr, "error in unmarshal for file %s\n", apiFile)
			os.Exit(1)
		}
	}
	switch api {
	case "spansshow":
		var results []SpanSearch
		for _, q := range query {
			if q.TimeRange.EndTime.IsZero() {
				q.TimeRange.EndTime = endtime
			}
			resp, status, err := mcClient.ShowSpans(uri, token, &q)
			checkMcErr("ShowSpans", status, err, &rc)
			results = append(results, SpanSearch{
				Search:  q,
				Results: resp,
			})
		}
		cmpFilterSpans(results)
		PrintToYamlFile("show-commands.yml", outputDir, results, true)
	case "spansshowverbose":
		var results []SpanSearchVerbose
		for _, q := range query {
			if q.TimeRange.EndTime.IsZero() {
				q.TimeRange.EndTime = endtime
			}
			resp, status, err := mcClient.ShowSpansVerbose(uri, token, &q)
			checkMcErr("ShowSpansVerbose", status, err, &rc)
			results = append(results, SpanSearchVerbose{
				Search:  q,
				Results: resp,
			})
		}
		PrintToYamlFile("show-commands.yml", outputDir, results, true)
	case "spansterms":
		// There are no tests for span terms in e2e because the
		// span results varies from run-to-run. This may be because of
		// dropped spans or timing causing certain things to happen,
		// but it makes it impossible to get a consistent result from
		// the terms query. It would probably take a decent amount of
		// effort to make sure the results are consistent.
		var results []SpanTerms
		for _, q := range query {
			if q.TimeRange.EndTime.IsZero() {
				q.TimeRange.EndTime = endtime
			}
			resp, status, err := mcClient.SpanTerms(uri, token, &q)
			checkMcErr("SpanTerms", status, err, &rc)
			results = append(results, SpanTerms{
				Search: q,
				Terms:  resp,
			})
		}
		cmpFilterSpanTerms(results)
		PrintToYamlFile("show-commands.yml", outputDir, results, true)
	default:
		log.Printf("invalid mcapi action %s\n", api)
		return false
	}
	*retry = true
	return rc
}

// Get a comparable metrics data type
func removeTimestampFromPromData(allMetrics *ormapi.AllMetrics) *[]MetricsCompare {
	result := make([]MetricsCompare, 0)
	for _, data := range allMetrics.Data {
		for _, series := range data.Series {
			measurement := MetricsCompare{Name: series.Name, Tags: make(map[string]string), Values: make(map[string]float64)}
			// prometheus returns two values - first is measurement and second is a timestamp(remove it)
			if len(series.Values) != 1 {
				return nil
			}
			// copy tags
			for k, v := range series.Tags {
				measurement.Tags[k] = v
			}

			// add the first value
			val := series.Values[0][0]
			if floatVal, ok := val.(float64); ok {
				measurement.Values[series.Name] = floatVal
				// if its an int cast it to a float to make comparing easier
			} else if intVal, ok := val.(int); ok {
				measurement.Values[series.Name] = float64(intVal)
			}
			result = append(result, measurement)
		}
	}
	return &result
}

func parseMetrics(allMetrics *ormapi.AllMetrics) *[]MetricsCompare {
	result := make([]MetricsCompare, 0)
	for _, data := range allMetrics.Data {
		for _, series := range data.Series {
			measurement := MetricsCompare{Name: series.Name, Tags: make(map[string]string), Values: make(map[string]float64)}
			// e2e tests only grabs the latest measurement so there should only be one
			if len(series.Values) != 1 {
				return nil
			}
			for i, val := range series.Values[0] {
				// ignore timestamps, metadata, or other
				if series.Columns[i] == "time" || series.Columns[i] == "metadata" || series.Columns[i] == "other" {
					continue
				}
				if str, ok := val.(string); ok {
					measurement.Tags[series.Columns[i]] = str
				} else if floatVal, ok := val.(float64); ok {
					measurement.Values[series.Columns[i]] = floatVal
					// if its an int cast it to a float to make comparing easier
				} else if intVal, ok := val.(int); ok {
					measurement.Values[series.Columns[i]] = float64(intVal)
				}
			}
			result = append(result, measurement)
		}
	}
	return &result
}

// Parse optimized metrics (each MetricSeries include Columns, Name, Tags, and Values)
func parseOptimizedMetrics(allMetrics *ormapi.AllMetrics) *[]OptimizedMetricsCompare {
	result := make([]OptimizedMetricsCompare, 0)
	for _, data := range allMetrics.Data {
		for _, series := range data.Series {
			measurement := OptimizedMetricsCompare{Name: series.Name, Columns: make([]string, 0), Tags: make(map[string]string), Values: make([][]string, 0)}
			// e2e tests only grabs the latest measurement so there should only be one
			if len(series.Values) != 1 {
				return nil
			}

			// add tags, ignore non-deterministic tags
			for tag, val := range series.Tags {
				if _, ignore := IgnoreTagValues[tag]; ignore {
					continue
				}
				measurement.Tags[tag] = val
			}

			// add values
			for i, val := range series.Values[0] {
				// ignore timestamps, metadata, or other
				if series.Columns[i] == "time" || series.Columns[i] == "metadata" || series.Columns[i] == "other" {
					continue
				}
				values := make([]string, 0)
				// add column associated with value
				measurement.Columns = append(measurement.Columns, series.Columns[i])
				// add value as a float64
				if floatVal, ok := val.(float64); ok {
					values = append(values, strconv.FormatFloat(floatVal, 'f', -1, 64))
				} else if intVal, ok := val.(int); ok {
					// if its an int cast it to a float to make comparing easier
					values = append(values, strconv.Itoa(intVal))
				} else if strVal, ok := val.(string); ok {
					values = append(values, strVal)
				}
				measurement.Values = append(measurement.Values, values)
			}
			result = append(result, measurement)
		}
	}
	return &result
}

func runMcShowNode(uri, curUserFile, outputDir string, actionVars, vars, sharedData map[string]string) bool {
	rc := true
	token, rc := getLoginToken(curUserFile, outputDir, actionVars, vars)
	if !rc {
		return false
	}

	nodes, status, err := mcClient.ShowNode(uri, token, &ormapi.RegionNode{})
	checkMcErr("ShowNode", status, err, &rc)

	appdata := edgeproto.NodeData{}
	appdata.Nodes = nodes
	FilterNodeData(&appdata)
	PrintToYamlFile("show-commands.yml", outputDir, appdata, true)
	return rc
}

func runMcAppUserAlertApi(api, uri, apiFile, curUserFile, outputDir string, mods []string, actionVars, vars, sharedData map[string]string, apiFunc func(string, string, *ormapi.RegionAppAlertPolicy, ...mctestclient.Op) (*edgeproto.Result, int, error)) bool {
	rc := true
	token, rc := getLoginToken(curUserFile, outputDir, actionVars, vars)
	if !rc {
		return false
	}
	userDefAlerts := []ormapi.RegionAppAlertPolicy{}
	err := ReadYamlFile(apiFile, &userDefAlerts, WithVars(vars), ValidateReplacedVars())
	if err != nil {
		log.Printf("error in unmarshal for file %s, %v\n", apiFile, err)
		return false
	}
	log.Printf("Found %d alerts, %v\n", len(userDefAlerts), userDefAlerts)
	for _, alert := range userDefAlerts {
		log.Printf("Processing userapp alert %v\n", alert)
		output, status, err := apiFunc(uri, token, &alert)
		PrintToYamlFile("api-output.yml", outputDir, output, true)
		checkMcErr("AddAppUserDefinedAlert", status, err, &rc)
	}
	return rc
}

func runMcAddUserAlertToApp(api, uri, apiFile, curUserFile, outputDir string, mods []string, actionVars, vars, sharedData map[string]string) bool {
	return runMcAppUserAlertApi(api, uri, apiFile, curUserFile, outputDir, mods, actionVars, vars, sharedData, mcClient.AddAppAlertPolicy)
}

func runMcRemoveUserAlertFromApp(api, uri, apiFile, curUserFile, outputDir string, mods []string, actionVars, vars, sharedData map[string]string) bool {
	return runMcAppUserAlertApi(api, uri, apiFile, curUserFile, outputDir, mods, actionVars, vars, sharedData, mcClient.RemoveAppAlertPolicy)
}

func runMcDebug(api, uri, apiFile, curUserFile, outputDir string, mods []string, actionVars, vars, sharedData map[string]string) bool {
	log.Printf("Running %s MC debug APIs for %s %v\n", api, apiFile, mods)

	if apiFile == "" {
		log.Println("Error: Cannot run MC audit APIs without API file")
		return false
	}

	rc := true
	token, rc := getLoginToken(curUserFile, outputDir, actionVars, vars)
	if !rc {
		return false
	}
	data := edgeproto.DebugData{}
	err := ReadYamlFile(apiFile, &data, WithVars(vars), ValidateReplacedVars())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error in unmarshal for file %s, %v\n", apiFile, err)
		os.Exit(1)
	}

	output := edgetestutil.DebugDataOut{}
	for _, r := range data.Requests {
		var replies []edgeproto.DebugReply
		var status int
		var err error
		req := ormapi.RegionDebugRequest{
			DebugRequest: r,
		}
		switch api {
		case "debugenable":
			replies, status, err = mcClient.EnableDebugLevels(uri, token, &req)
			checkMcErr("EnableDebugLevels", status, err, &rc)
		case "debugdisable":
			replies, status, err = mcClient.DisableDebugLevels(uri, token, &req)
			checkMcErr("DisableDebugLevels", status, err, &rc)
		case "debugshow":
			replies, status, err = mcClient.ShowDebugLevels(uri, token, &req)
			checkMcErr("ShowDebugLevels", status, err, &rc)
		case "debugrun":
			replies, status, err = mcClient.RunDebug(uri, token, &req)
			checkMcErr("RunDebug", status, err, &rc)
		}
		if err == nil && len(replies) > 0 {
			output.Requests = append(output.Requests, replies)
		}
	}
	output.Sort()
	clearTags := map[string]struct{}{
		"nocmp":     struct{}{},
		"timestamp": struct{}{},
	}
	for ii := range output.Requests {
		for jj := range output.Requests[ii] {
			output.Requests[ii][jj].ClearTagged(clearTags)
		}
	}
	PrintToYamlFile("api-output.yml", outputDir, output, true)
	return rc
}

func showMcAlerts(uri, apiFile, curUserFile, outputDir string, actionVars, vars, sharedData map[string]string) bool {
	if apiFile == "" {
		log.Println("Error: Cannot run MC audit APIs without API file")
		return false
	}
	log.Printf("Running MC showalert APIs for %s\n", apiFile)

	token, rc := getLoginToken(curUserFile, outputDir, actionVars, vars)
	if !rc {
		return false
	}
	filter := ormapi.RegionAlert{}
	err := ReadYamlFile(apiFile, &filter, WithVars(vars), ValidateReplacedVars())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error in unmarshal for file %s, %v\n", apiFile, err)
		os.Exit(1)
	}

	alerts, status, err := mcClient.ShowAlert(uri, token, &filter)
	checkMcErr("ShowAlert", status, err, &rc)

	FilterAlerts(alerts)
	PrintToYamlFile("show-commands.yml", outputDir, alerts, true)
	return rc
}

func showMcAlertReceivers(uri, curUserFile, outputDir string, actionVars, vars, sharedData map[string]string) bool {
	var err error
	var status int

	log.Printf("Running MC showalert receivers APIs\n")

	token, rc := getLoginToken(curUserFile, outputDir, actionVars, vars)
	if !rc {
		return false
	}
	showData := ormapi.AllData{}
	showData.AlertReceivers, status, err = mcClient.ShowAlertReceiver(uri, token, &ormapi.AlertReceiver{})
	checkMcErr("ShowAlertReceiver", status, err, &rc)

	cmpFilterAllData(&showData)
	PrintToYamlFile("show-commands.yml", outputDir, showData, true)
	return rc
}

type AllStreamOutData struct {
	RegionData []RegionStreamOutData `json:"regionstreamoutdata,omitempty"`
}

type RegionStreamOutData struct {
	Region        string                        `json:"region,omitempty"`
	StreamOutData edgetestutil.AllDataStreamOut `json:"streamoutdata,omitempty"`
}

func streamMcData(uri, token, tag string, data *ormapi.AllData, rc *bool) *AllStreamOutData {
	dataOut := &AllStreamOutData{}

	// currently only controller APIs support filtering
	for ii, _ := range data.RegionData {
		region := data.RegionData[ii].Region
		filter := &data.RegionData[ii].AppData

		rd := RegionStreamOutData{}
		rd.Region = region

		client := testutil.TestClient{
			Region:          region,
			Uri:             uri,
			Token:           token,
			McClient:        mcClient,
			IgnoreForbidden: true,
		}
		run := edgetestutil.NewRun(&client, context.Background(), "streammcdata", rc)
		edgetestutil.RunAllDataStreamApis(run, filter, &rd.StreamOutData)
		run.CheckErrs(fmt.Sprintf("streammcdata region %s", region), tag)
		dataOut.RegionData = append(dataOut.RegionData, rd)
	}
	return dataOut
}

func getVarsObjTypes(vars map[string]string) edgeproto.AllSelector {
	m := edgeproto.AllSelector{}
	list, ok := vars["objtypes"]
	if !ok {
		return m
	}
	if list == "nonpublic" {
		m.Select("orgs")
		m.Select("billingorgs")
		m.Select("cloudletpoolaccessinvitations")
		m.Select("cloudletpoolaccessresponses")
		m.Select("operatorcodes")
		m.Select("restagtables")
		m.Select("trustpolicies")
		m.Select("cloudletpools")
		m.Select("networks")
		m.Select("autoprovpolicies")
		m.Select("autoscalepolicies")
		m.Select("clusterinsts")
		m.Select("apps")
		m.Select("appinstances")
		m.Select("appinstrefs")
		m.Select("clusterrefs")
		m.Select("vmpools")
		m.Select("alertpolicies")
		m.Select("trustpolicyexceptions")
	} else {
		for _, val := range strings.Split(list, ",") {
			m.Select(strings.TrimSpace(val))
		}
	}
	return m
}
