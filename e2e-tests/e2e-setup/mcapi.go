package e2esetup

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	intprocess "github.com/mobiledgex/edge-cloud-infra/e2e-tests/int-process"
	"github.com/mobiledgex/edge-cloud-infra/mc/mcctl/cliwrapper"
	"github.com/mobiledgex/edge-cloud-infra/mc/orm/testutil"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormclient"
	"github.com/mobiledgex/edge-cloud/cloudcommon/node"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/setup-env/util"
	edgetestutil "github.com/mobiledgex/edge-cloud/testutil"
)

var mcClient ormclient.Api
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

func RunMcAPI(api, mcname, apiFile, curUserFile, outputDir string, mods []string, vars map[string]string, retry *bool) bool {
	mc := getMC(mcname)
	uri := "https://" + mc.Addr + "/api/v1"
	log.Printf("Using MC %s at %s", mc.Name, uri)

	if hasMod("cli", mods) {
		mcClient = &cliwrapper.Client{
			DebugLog:     true,
			SkipVerify:   true,
			SilenceUsage: true,
		}
	} else {
		mcClient = &ormclient.Client{
			SkipVerify: true,
		}
	}

	if strings.HasSuffix(api, "users") {
		return runMcUsersAPI(api, uri, apiFile, curUserFile, outputDir, mods, vars)
	} else if strings.HasPrefix(api, "audit") {
		return runMcAudit(api, uri, apiFile, curUserFile, outputDir, mods, vars, retry)
	} else if strings.HasPrefix(api, "config") {
		return runMcConfig(api, uri, apiFile, curUserFile, outputDir, mods, vars)
	} else if strings.HasPrefix(api, "events") {
		return runMcEvents(api, uri, apiFile, curUserFile, outputDir, mods, vars, retry)
	} else if api == "runcommand" {
		return runMcExec(api, uri, apiFile, curUserFile, outputDir, mods, vars)
	} else if api == "showlogs" {
		return runMcExec(api, uri, apiFile, curUserFile, outputDir, mods, vars)
	} else if api == "accesscloudlet" {
		return runMcExec(api, uri, apiFile, curUserFile, outputDir, mods, vars)
	} else if api == "nodeshow" {
		return runMcShowNode(uri, curUserFile, outputDir, vars)
	} else if api == "showalerts" {
		*retry = true
		return showMcAlerts(uri, apiFile, curUserFile, outputDir, vars)
	} else if strings.HasPrefix(api, "debug") {
		return runMcDebug(api, uri, apiFile, curUserFile, outputDir, mods, vars)
	} else if api == "showalertreceivers" {
		*retry = true
		return showMcAlertReceivers(uri, curUserFile, outputDir, vars)
	}
	return runMcDataAPI(api, uri, apiFile, curUserFile, outputDir, mods, vars, retry)
}

func getMC(name string) *intprocess.MC {
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

func runMcUsersAPI(api, uri, apiFile, curUserFile, outputDir string, mods []string, vars map[string]string) bool {
	log.Printf("Applying MC users via APIs for %s\n", apiFile)

	rc := true
	if api == "showusers" {
		token, rc := loginCurUser(uri, curUserFile, vars)
		if !rc {
			return false
		}
		users, status, err := mcClient.ShowUser(uri, token, &ormapi.Organization{})
		checkMcErr("ShowUser", status, err, &rc)
		util.PrintToYamlFile("show-commands.yml", outputDir, users, true)
		return rc
	}

	if apiFile == "" {
		log.Println("Error: Cannot run MC user APIs without API file")
		return false
	}
	users := readUsersFiles(apiFile, vars)

	switch api {
	case "createusers":
		for _, user := range users {
			status, err := mcClient.CreateUser(uri, &user)
			checkMcErr("CreateUser", status, err, &rc)
		}
	case "deleteusers":
		token, ok := loginCurUser(uri, curUserFile, vars)
		if !ok {
			return false
		}
		for _, user := range users {
			status, err := mcClient.DeleteUser(uri, token, &user)
			checkMcErr("DeleteUser", status, err, &rc)
		}
	}
	return rc
}

func runMcConfig(api, uri, apiFile, curUserFile, outputDir string, mods []string, vars map[string]string) bool {
	log.Printf("Applying MC config via APIs for %s\n", apiFile)

	token, rc := loginCurUser(uri, curUserFile, vars)
	if !rc {
		return false
	}

	switch api {
	case "configshow":
		config, st, err := mcClient.ShowConfig(uri, token)
		checkMcErr("ShowConfig", st, err, &rc)
		util.PrintToYamlFile("show-commands.yml", outputDir, config, true)
	case "configreset":
		st, err := mcClient.ResetConfig(uri, token)
		checkMcErr("ResetConfig", st, err, &rc)
	case "configupdate":
		if apiFile == "" {
			log.Println("Error: Cannot run MC config APIs without API file")
			return false
		}
		data := make(map[string]interface{})
		err := util.ReadYamlFile(apiFile, &data, util.WithVars(vars), util.ValidateReplacedVars())
		if err != nil && !util.IsYamlOk(err, "config") {
			log.Printf("error in unmarshal ormapi.Config for %s: %v\n", apiFile, err)
			return false
		}
		st, err := mcClient.UpdateConfig(uri, token, data)
		checkMcErr("UpdateConfig", st, err, &rc)
	}
	return rc
}

func runMcDataAPI(api, uri, apiFile, curUserFile, outputDir string, mods []string, vars map[string]string, retry *bool) bool {
	log.Printf("Applying MC data via APIs for %s mods %v vars %v\n", apiFile, mods, vars)
	// Data APIs are all run by a given user.
	// That user is specified in the current user file.
	// We need to log in as that user.
	rc := true
	token, rc := loginCurUser(uri, curUserFile, vars)
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
		var showData *ormapi.AllData
		showData = showMcData(uri, token, tag, &rc)
		util.PrintToYamlFile("show-commands.yml", outputDir, showData, true)
		*retry = true
		return rc
	}

	if api == "showevents" {
		var showEvents *ormapi.AllMetrics
		targets := readMCMetricTargetsFile(apiFile, vars)
		var parsedMetrics *[]MetricsCompare
		showEvents = showMcEvents(uri, token, targets, &rc)
		// convert showMetrics into something yml compatible
		parsedMetrics = parseMetrics(showEvents)
		util.PrintToYamlFile("show-commands.yml", outputDir, parsedMetrics, true)
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
		util.PrintToYamlFile("show-commands.yml", outputDir, parsedMetrics, true)
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
	case "create":
		output := &AllDataOut{}
		createMcData(uri, token, tag, data, dataMap, output, &rc)
		util.PrintToYamlFile("api-output.yml", outputDir, output, true)
		errs = output.Errors
	case "delete":
		output := &AllDataOut{}
		deleteMcData(uri, token, tag, data, dataMap, output, &rc)
		util.PrintToYamlFile("api-output.yml", outputDir, output, true)
		errs = output.Errors
	case "add":
		fallthrough
	case "remove":
		fallthrough
	case "update":
		output := &AllDataOut{}
		updateMcData(api, uri, token, tag, data, dataMap, output, &rc)
		util.PrintToYamlFile("api-output.yml", outputDir, output, true)
		errs = output.Errors
	case "showfiltered":
		dataOut := showMcDataFiltered(uri, token, tag, data, &rc)
		util.PrintToYamlFile("show-commands.yml", outputDir, dataOut, true)
		*retry = true
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
		err := util.ReadYamlFile(file, &fileusers, util.WithVars(vars), util.ValidateReplacedVars())
		if err != nil {
			if !util.IsYamlOk(err, "mcusers") {
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
	err := util.ReadYamlFile(file, &data, util.WithVars(vars), util.ValidateReplacedVars())
	if err != nil {
		if !util.IsYamlOk(err, "mcdata") {
			fmt.Fprintf(os.Stderr, "error in unmarshal for file %s\n", file)
			os.Exit(1)
		}
	}
	return &data
}

func readMCDataFileMap(file string, vars map[string]string) map[string]interface{} {
	dataMap := make(map[string]interface{})
	err := util.ReadYamlFile(file, &dataMap, util.WithVars(vars), util.ValidateReplacedVars())
	if err != nil {
		if !util.IsYamlOk(err, "mcdata") {
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
	err := util.ReadYamlFile(file, &targets, util.WithVars(vars), util.ValidateReplacedVars())
	if err != nil {
		if !util.IsYamlOk(err, "mcdata") {
			fmt.Fprintf(os.Stderr, "error in unmarshal for file %s\n", file)
			os.Exit(1)
		}
	}
	return &targets
}

func loginCurUser(uri, curUserFile string, vars map[string]string) (string, bool) {
	if curUserFile == "" {
		log.Println("Error: Cannot run MC APIs without current user file")
		return "", false
	}
	users := readUsersFiles(curUserFile, vars)
	if len(users) == 0 {
		log.Printf("no user to run MC api\n")
		return "", false
	}
	token, err := mcClient.DoLogin(uri, users[0].Name, users[0].Passhash)
	rc := true
	checkMcErr("DoLogin", http.StatusOK, err, &rc)
	return token, rc
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

func showMcData(uri, token, tag string, rc *bool) *ormapi.AllData {
	ctrls, status, err := mcClient.ShowController(uri, token)
	checkMcErr("ShowControllers", status, err, rc)
	orgs, status, err := mcClient.ShowOrg(uri, token)
	checkMcErr("ShowOrgs", status, err, rc)
	bOrgs, status, err := mcClient.ShowBillingOrg(uri, token)
	checkMcErr("ShowBillingOrgs", status, err, rc)
	roles, status, err := mcClient.ShowUserRole(uri, token)
	checkMcErr("ShowRoles", status, err, rc)
	ocs, status, err := mcClient.ShowOrgCloudletPool(uri, token)
	checkMcErr("ShowOrgCloudletPools", status, err, rc)

	showData := &ormapi.AllData{
		Controllers:      ctrls,
		Orgs:             orgs,
		BillingOrgs:      bOrgs,
		Roles:            roles,
		OrgCloudletPools: ocs,
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
		edgetestutil.RunAllDataShowApis(run, filter, appdata)
		run.CheckErrs(fmt.Sprintf("show region %s", ctrl.Region), tag)
		rd := ormapi.RegionData{
			Region:  ctrl.Region,
			AppData: *appdata,
		}
		showData.RegionData = append(showData.RegionData, rd)
	}
	return showData
}

func showMcDataFiltered(uri, token, tag string, data *ormapi.AllData, rc *bool) *ormapi.AllData {
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
		edgetestutil.RunAllDataShowApis(run, filter, &rd.AppData)
		run.CheckErrs(fmt.Sprintf("show-filtered region %s", region), tag)
		dataOut.RegionData = append(dataOut.RegionData, rd)
	}
	return dataOut
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

func runRegionDataApi(mcClient ormclient.Api, uri, token, tag string, rd *ormapi.RegionData, rdMap interface{}, rc *bool, mode string) *edgetestutil.AllDataOut {
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
		edgetestutil.RunAllDataApis(run, &rd.AppData, appDataMap, output)
	case "remove":
		fallthrough
	case "delete":
		edgetestutil.RunAllDataReverseApis(run, &rd.AppData, appDataMap, output)
	}
	run.CheckErrs(fmt.Sprintf("%s region %s", mode, rd.Region), tag)
	return output
}

func createMcData(uri, token, tag string, data *ormapi.AllData, dataMap map[string]interface{}, output *AllDataOut, rc *bool) {
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
	for ii, rd := range data.RegionData {
		rdm := getRegionDataMap(dataMap, ii)
		rdout := runRegionDataApi(mcClient, uri, token, tag, &rd, rdm, rc, "create")
		output.RegionData = append(output.RegionData, *rdout)
	}
	for ii, oc := range data.OrgCloudletPools {
		st, err := mcClient.CreateOrgCloudletPool(uri, token, &oc)
		outMcErr(output, fmt.Sprintf("CreateOrgCloudletPool[%d]", ii), st, err)
	}
	for ii, ar := range data.AlertReceivers {
		st, err := mcClient.CreateAlertReceiver(uri, token, &ar)
		outMcErr(output, fmt.Sprintf("CreateAlertReceiver[%d]", ii), st, err)
	}
}

func deleteMcData(uri, token, tag string, data *ormapi.AllData, dataMap map[string]interface{}, output *AllDataOut, rc *bool) {
	for ii, oc := range data.OrgCloudletPools {
		st, err := mcClient.DeleteOrgCloudletPool(uri, token, &oc)
		outMcErr(output, fmt.Sprintf("DeleteOrgCloudletPool[%d]", ii), st, err)
	}
	for ii, rd := range data.RegionData {
		rdm := getRegionDataMap(dataMap, ii)
		rdout := runRegionDataApi(mcClient, uri, token, tag, &rd, rdm, rc, "delete")
		output.RegionData = append(output.RegionData, *rdout)
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
	for ii, ar := range data.AlertReceivers {
		st, err := mcClient.DeleteAlertReceiver(uri, token, &ar)
		outMcErr(output, fmt.Sprintf("DeleteAlertReceiver[%d]", ii), st, err)
	}
}

func updateMcData(mode, uri, token, tag string, data *ormapi.AllData, dataMap map[string]interface{}, output *AllDataOut, rc *bool) {
	for ii, rd := range data.RegionData {
		rdm := getRegionDataMap(dataMap, ii)
		rdout := runRegionDataApi(mcClient, uri, token, tag, &rd, rdm, rc, mode)
		output.RegionData = append(output.RegionData, *rdout)
	}
}

func showMcMetricsAll(uri, token string, targets *MetricTargets, rc *bool) *ormapi.AllMetrics {
	appQuery := ormapi.RegionAppInstMetrics{
		Region:   "local",
		AppInst:  targets.AppInstKey,
		Selector: "*",
		Last:     1,
	}
	appMetrics, status, err := mcClient.ShowAppMetrics(uri, token, &appQuery)
	checkMcErr("ShowAppMetrics", status, err, rc)
	clusterQuery := ormapi.RegionClusterInstMetrics{
		Region:      "local",
		ClusterInst: targets.ClusterInstKey,
		Selector:    "*",
		Last:        1,
	}
	clusterMetrics, status, err := mcClient.ShowClusterMetrics(uri, token, &clusterQuery)
	checkMcErr("ShowClusterMetrics", status, err, rc)
	// combine them into one AllMetrics
	appMetrics.Data = append(appMetrics.Data, clusterMetrics.Data...)
	return appMetrics
}
func showMcEvents(uri, token string, targets *MetricTargets, rc *bool) *ormapi.AllMetrics {
	appQuery := ormapi.RegionAppInstEvents{
		Region:  "local",
		AppInst: targets.AppInstKey,
		Last:    1,
	}
	appMetrics, status, err := mcClient.ShowAppEvents(uri, token, &appQuery)
	checkMcErr("ShowAppEvents", status, err, rc)
	clusterQuery := ormapi.RegionClusterInstEvents{
		Region:      "local",
		ClusterInst: targets.ClusterInstKey,
		Last:        1,
	}
	clusterMetrics, status, err := mcClient.ShowClusterEvents(uri, token, &clusterQuery)
	checkMcErr("ShowClusterEvents", status, err, rc)
	cloudletQuery := ormapi.RegionCloudletEvents{
		Region:   "local",
		Cloudlet: targets.CloudletKey,
		Last:     1,
	}
	cloudletMetrics, status, err := mcClient.ShowCloudletEvents(uri, token, &cloudletQuery)
	checkMcErr("ShowCloudletEvents", status, err, rc)

	// combine them into one AllMetrics
	appMetrics.Data = append(appMetrics.Data, clusterMetrics.Data...)
	appMetrics.Data = append(appMetrics.Data, cloudletMetrics.Data...)
	return appMetrics
}

// same end result as showMcMetricsAll, but gets each metric individually instead of in a batch
func showMcMetricsSep(uri, token string, targets *MetricTargets, rc *bool) *ormapi.AllMetrics {
	allMetrics := ormapi.AllMetrics{Data: make([]ormapi.MetricData, 0)}
	appQuery := ormapi.RegionAppInstMetrics{
		Region:  "local",
		AppInst: targets.AppInstKey,
		Last:    1,
	}
	for _, selector := range E2eAppSelectors {
		appQuery.Selector = selector
		appMetric, status, err := mcClient.ShowAppMetrics(uri, token, &appQuery)
		checkMcErr("ShowApp"+strings.Title(selector), status, err, rc)
		allMetrics.Data = append(allMetrics.Data, appMetric.Data...)
	}

	clusterQuery := ormapi.RegionClusterInstMetrics{
		Region:      "local",
		ClusterInst: targets.ClusterInstKey,
		Last:        1,
	}
	for _, selector := range E2eClusterSelectors {
		clusterQuery.Selector = selector
		clusterMetric, status, err := mcClient.ShowClusterMetrics(uri, token, &clusterQuery)
		checkMcErr("ShowCluster"+strings.Title(selector), status, err, rc)
		allMetrics.Data = append(allMetrics.Data, clusterMetric.Data...)
	}
	return &allMetrics
}

type runCommandData struct {
	Request        ormapi.RegionExecRequest
	ExpectedOutput string
}

func runMcExec(api, uri, apiFile, curUserFile, outputDir string, mods []string, vars map[string]string) bool {
	token, rc := loginCurUser(uri, curUserFile, vars)
	if !rc {
		return false
	}

	data := runCommandData{}
	err := util.ReadYamlFile(apiFile, &data, util.WithVars(vars), util.ValidateReplacedVars())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error in unmarshal for file %s, %v\n", apiFile, err)
		return false
	}

	if hasMod("cli", mods) {
		log.Printf("Using MC URI %s", uri)
		client := &cliwrapper.Client{
			DebugLog:   true,
			SkipVerify: true,
		}

		// RunCommand is a special case only supported by mcctl CLI,
		// because it leverages the webrtc client code in mcctl.
		var out string
		if api == "runcommand" {
			out, err = client.RunCommandOut(uri, token, &data.Request)
		} else if api == "accesscloudlet" {
			out, err = client.AccessCloudletOut(uri, token, &data.Request)
		} else {
			out, err = client.ShowLogsOut(uri, token, &data.Request)
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
	} else {
		wsUri := strings.Replace(uri, "http", "ws", -1)
		wsUri = strings.Replace(wsUri, "api/v1", "ws/api/v1", -1)
		log.Printf("Using MC URI %s", wsUri)

		data.Request.ExecRequest.Webrtc = true

		client := &ormclient.Client{
			SkipVerify: true,
		}

		var streamOut []ormapi.WSStreamPayload
		var status int
		var err error
		if api == "runcommand" {
			streamOut, status, err = client.RunCommandStream(wsUri, token, &data.Request)
		} else if api == "accesscloudlet" {
			// this command is to be run internally, hence websocket support is not required
			return true
		} else {
			streamOut, status, err = client.ShowLogsStream(wsUri, token, &data.Request)
		}
		checkMcErr(api, status, err, &rc)
		log.Printf("Exec %s output: %v\n", api, streamOut)
		if len(streamOut) != 1 {
			log.Printf("Invalid output, expected 1 data, but recieved: %d\n", len(streamOut))
			return false
		}
		code := streamOut[0].Code
		if code != http.StatusOK {
			log.Printf("Did not get 200 status, got %d\n", code)
			return false
		}
		actual, ok := streamOut[0].Data.(string)
		if !ok {
			log.Printf("Did not get payload of type string\n")
			return false
		}
		actual = strings.TrimSpace(actual)
		if actual != data.ExpectedOutput {
			log.Printf("Did not get expected output: %s\n", data.ExpectedOutput)
			return false
		}
	}
	return true
}

var eventsStartTimeFile = "events-starttime"

func runMcAudit(api, uri, apiFile, curUserFile, outputDir string, mods []string, vars map[string]string, retry *bool) bool {
	log.Printf("Running %s MC audit APIs for %s %v\n", api, apiFile, mods)

	if apiFile == "" {
		log.Println("Error: Cannot run MC audit APIs without API file")
		return false
	}

	rc := true
	if api == "auditsetup" {
		// because the login command is recorded in the audit logs,
		// having to log in to switch between admin and user2 ends
		// up affecting the audit logs that we're trying to validate.
		// Instead, we log in during setup and record the tokens to
		// be used later.
		users := readUsersFiles(apiFile, vars)
		for _, user := range users {
			token, err := mcClient.DoLogin(uri, user.Name, user.Passhash)
			checkMcErr("DoLogin", http.StatusOK, err, &rc)
			if err == nil && rc {
				fname := getTokenFile(user.Name, outputDir)
				err = ioutil.WriteFile(fname, []byte(token), 0644)
				if err != nil {
					log.Printf("Write token file %s failed, %v\n", fname, err)
					rc = false
				}
			}
		}
		// also set the current time for events and event terms queries
		// so previous iterations of tests don't affect the search.
		// need a tiny bit of time to not capture events from previous
		// command
		fname := getTokenFile(eventsStartTimeFile, outputDir)
		err := ioutil.WriteFile(fname, []byte(time.Now().Format(time.RFC3339Nano)), 0644)
		if err != nil {
			log.Printf("Write events start time file %s failed, %v\n", fname, err)
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

	query := ormapi.AuditQuery{}
	err = util.ReadYamlFile(apiFile, &query, util.WithVars(vars), util.ValidateReplacedVars())
	if err != nil {
		if !util.IsYamlOk(err, "mcaudit") {
			fmt.Fprintf(os.Stderr, "error in unmarshal for file %s\n", apiFile)
			os.Exit(1)
		}
	}
	switch api {
	case "auditorg":
		resp, status, err := mcClient.ShowAuditOrg(uri, token, &query)
		checkMcErr("ShowAuditOrg", status, err, &rc)
		util.PrintToYamlFile("show-commands.yml", outputDir, resp, true)
	case "auditself":
		resp, status, err := mcClient.ShowAuditSelf(uri, token, &query)
		checkMcErr("ShowAuditSelf", status, err, &rc)
		util.PrintToYamlFile("show-commands.yml", outputDir, resp, true)
	}
	*retry = true
	return rc
}

func getTokenFile(username, outputDir string) string {
	return outputDir + "/" + username + ".token"
}

func runMcEvents(api, uri, apiFile, curUserFile, outputDir string, mods []string, vars map[string]string, retry *bool) bool {
	log.Printf("Running %s MC events APIs for %s %v\n", api, apiFile, mods)

	if apiFile == "" {
		log.Println("Error: Cannot run MC audit APIs without API file")
		return false
	}

	rc := true
	// this uses the same "auditsetup" that audit uses
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
	err = util.ReadYamlFile(apiFile, &query, util.WithVars(vars), util.ValidateReplacedVars())
	if err != nil {
		if !util.IsYamlOk(err, "events") {
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
		util.PrintToYamlFile("show-commands.yml", outputDir, results, true)
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
		util.PrintToYamlFile("show-commands.yml", outputDir, results, true)
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
		util.PrintToYamlFile("show-commands.yml", outputDir, results, true)
	default:
		log.Printf("invalid mcapi action %s\n", api)
		return false
	}
	*retry = true
	return rc
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
				// put non measurement info separate
				_, isTag := TagValues[series.Columns[i]]
				if str, ok := val.(string); ok && isTag {
					measurement.Tags[series.Columns[i]] = str
				}
				if floatVal, ok := val.(float64); ok {
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

func runMcShowNode(uri, curUserFile, outputDir string, vars map[string]string) bool {
	rc := true
	token, rc := loginCurUser(uri, curUserFile, vars)
	if !rc {
		return false
	}

	nodes, status, err := mcClient.ShowNode(uri, token, &ormapi.RegionNode{})
	checkMcErr("ShowNode", status, err, &rc)

	appdata := edgeproto.NodeData{}
	appdata.Nodes = nodes
	util.PrintToYamlFile("show-commands.yml", outputDir, appdata, true)
	return rc
}

func runMcDebug(api, uri, apiFile, curUserFile, outputDir string, mods []string, vars map[string]string) bool {
	log.Printf("Running %s MC debug APIs for %s %v\n", api, apiFile, mods)

	if apiFile == "" {
		log.Println("Error: Cannot run MC audit APIs without API file")
		return false
	}

	rc := true
	token, rc := loginCurUser(uri, curUserFile, vars)
	if !rc {
		return false
	}
	data := edgeproto.DebugData{}
	err := util.ReadYamlFile(apiFile, &data, util.WithVars(vars), util.ValidateReplacedVars())
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
	util.PrintToYamlFile("api-output.yml", outputDir, output, true)
	return rc
}

func showMcAlerts(uri, apiFile, curUserFile, outputDir string, vars map[string]string) bool {
	if apiFile == "" {
		log.Println("Error: Cannot run MC audit APIs without API file")
		return false
	}
	log.Printf("Running MC showalert APIs for %s\n", apiFile)

	token, rc := loginCurUser(uri, curUserFile, vars)
	if !rc {
		return false
	}
	filter := ormapi.RegionAlert{}
	err := util.ReadYamlFile(apiFile, &filter, util.WithVars(vars), util.ValidateReplacedVars())
	if err != nil {
		fmt.Fprintf(os.Stderr, "error in unmarshal for file %s, %v\n", apiFile, err)
		os.Exit(1)
	}

	alerts, status, err := mcClient.ShowAlert(uri, token, &filter)
	checkMcErr("ShowAlert", status, err, &rc)

	util.PrintToYamlFile("show-commands.yml", outputDir, alerts, true)
	return rc
}

func showMcAlertReceivers(uri, curUserFile, outputDir string, vars map[string]string) bool {
	var err error
	var status int

	log.Printf("Running MC showalert receivers APIs\n")

	token, rc := loginCurUser(uri, curUserFile, vars)
	if !rc {
		return false
	}
	showData := ormapi.AllData{}
	showData.AlertReceivers, status, err = mcClient.ShowAlertReceiver(uri, token)
	checkMcErr("ShowAlertReceiver", status, err, &rc)

	util.PrintToYamlFile("show-commands.yml", outputDir, showData, true)
	return rc
}
