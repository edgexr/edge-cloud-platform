package e2esetup

import (
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
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/setup-env/util"
)

var mcClient ormclient.Api

func RunMcAPI(api, mcname, apiFile, curUserFile, outputDir string, mods []string, vars map[string]string) bool {
	mc := getMC(mcname)
	uri := "https://" + mc.Addr + "/api/v1"
	log.Printf("Using MC %s at %s", mc.Name, uri)

	if hasMod("cli", mods) {
		mcClient = &cliwrapper.Client{
			DebugLog:   true,
			SkipVerify: true,
		}
	} else {
		mcClient = &ormclient.Client{
			SkipVerify: true,
		}
	}

	if strings.HasSuffix(api, "users") {
		return runMcUsersAPI(api, uri, apiFile, curUserFile, outputDir, mods, vars)
	} else if strings.HasPrefix(api, "audit") {
		return runMcAudit(api, uri, apiFile, curUserFile, outputDir, mods, vars)
	} else if api == "runcommand" {
		return runMcRunCommand(uri, apiFile, curUserFile, outputDir, mods, vars)
	}
	return runMcDataAPI(api, uri, apiFile, curUserFile, outputDir, mods, vars)
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

func runMcDataAPI(api, uri, apiFile, curUserFile, outputDir string, mods []string, vars map[string]string) bool {
	log.Printf("Applying MC data via APIs for %s mods %v vars %v\n", apiFile, mods, vars)
	sep := hasMod("sep", mods)

	// Data APIs are all run by a given user.
	// That user is specified in the current user file.
	// We need to log in as that user.
	rc := true
	token, rc := loginCurUser(uri, curUserFile, vars)
	if !rc {
		return false
	}

	if api == "show" {
		var showData *ormapi.AllData
		if sep {
			showData = showMcDataSep(uri, token, &rc)
		} else {
			showData = showMcDataAll(uri, token, &rc)
		}
		util.PrintToYamlFile("show-commands.yml", outputDir, showData, true)
		return rc
	}

	if api == "showmetrics" {
		var showMetrics *ormapi.AllMetrics
		targets := readMCMetricTargetsFile(apiFile, vars)
		var parsedMetrics *[]MetricsCompare
		// retry a couple times since prometheus takes a while on startup
		for i := 0; i < 100; i++ {
			if sep {
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
	regionDataMap := readMCRegionDataFileMap(apiFile, vars)
	switch api {
	case "create":
		if sep {
			createMcDataSep(uri, token, data, regionDataMap, &rc)
		} else {
			createMcDataAll(uri, token, data, &rc)
		}
	case "delete":
		if sep {
			deleteMcDataSep(uri, token, data, regionDataMap, &rc)
		} else {
			deleteMcDataAll(uri, token, data, &rc)
		}
	case "update":
		updateMcDataSep(uri, token, data, regionDataMap, &rc)
	case "showfiltered":
		dataOut := showMcDataFiltered(uri, token, data, &rc)
		util.PrintToYamlFile("show-commands.yml", outputDir, dataOut, true)
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

func readMCRegionDataFileMap(file string, vars map[string]string) *[]interface{} {
	dataMap := make(map[string]interface{})
	err := util.ReadYamlFile(file, &dataMap, util.WithVars(vars), util.ValidateReplacedVars())
	if err != nil {
		if !util.IsYamlOk(err, "mcdata") {
			fmt.Fprintf(os.Stderr, "error in unmarshal for file %s\n", file)
			os.Exit(1)
		}
	}
	if val, ok := dataMap["regiondata"]; ok {
		retval, ok := val.([]interface{})
		if ok {
			return &retval
		}
		fmt.Fprintf(os.Stderr, "error in unmarshal for file %s, invalid data in regiondata: %v\n", file, val)
		os.Exit(1)
	}
	return nil
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

func showMcDataAll(uri, token string, rc *bool) *ormapi.AllData {
	showData, status, err := mcClient.ShowData(uri, token)
	checkMcErr("ShowData", status, err, rc)
	return showData
}

func createMcDataAll(uri, token string, data *ormapi.AllData, rc *bool) {
	status, err := mcClient.CreateData(uri, token, data, func(res *ormapi.Result) {
		log.Printf("CreateData: %s\n", res.Message)
	})
	checkMcErr("CreateData", status, err, rc)
}

func deleteMcDataAll(uri, token string, data *ormapi.AllData, rc *bool) {
	status, err := mcClient.DeleteData(uri, token, data, func(res *ormapi.Result) {
		log.Printf("DeleteData: %s\n", res.Message)
	})
	checkMcErr("DeleteData", status, err, rc)
}

func showMcDataSep(uri, token string, rc *bool) *ormapi.AllData {
	ctrls, status, err := mcClient.ShowController(uri, token)
	checkMcErr("ShowControllers", status, err, rc)
	orgs, status, err := mcClient.ShowOrg(uri, token)
	checkMcErr("ShowOrgs", status, err, rc)
	roles, status, err := mcClient.ShowUserRole(uri, token)
	checkMcErr("ShowRoles", status, err, rc)
	ocs, status, err := mcClient.ShowOrgCloudletPool(uri, token)
	checkMcErr("ShowOrgCloudletPools", status, err, rc)

	showData := &ormapi.AllData{
		Controllers:      ctrls,
		Orgs:             orgs,
		Roles:            roles,
		OrgCloudletPools: ocs,
	}
	for _, ctrl := range ctrls {
		inSettings := &ormapi.RegionSettings{
			Region: ctrl.Region,
		}
		settings, status, err := mcClient.ShowSettings(uri, token, inSettings)
		if status == http.StatusForbidden {
			// avoid test failure when user doesn't have perms
			settings = nil
			status = http.StatusOK
			err = nil
		}
		checkMcCtrlErr("ShowSettings", status, err, rc)

		inFlavor := &ormapi.RegionFlavor{
			Region: ctrl.Region,
		}
		flavors, status, err := mcClient.ShowFlavor(uri, token, inFlavor)
		checkMcCtrlErr("ShowFlavors", status, err, rc)

		inCode := &ormapi.RegionOperatorCode{
			Region: ctrl.Region,
		}
		codes, status, err := mcClient.ShowOperatorCode(uri, token, inCode)
		checkMcCtrlErr("ShowOperatorCode", status, err, rc)

		inCloudlet := &ormapi.RegionCloudlet{
			Region: ctrl.Region,
		}
		cloudlets, status, err := mcClient.ShowCloudlet(uri, token, inCloudlet)
		checkMcCtrlErr("ShowCloudlet", status, err, rc)

		inCloudletPool := &ormapi.RegionCloudletPool{
			Region: ctrl.Region,
		}
		pools, status, err := mcClient.ShowCloudletPool(uri, token, inCloudletPool)
		checkMcCtrlErr("ShowCloudletPool", status, err, rc)

		inCloudletPoolMember := &ormapi.RegionCloudletPoolMember{
			Region: ctrl.Region,
		}
		members, status, err := mcClient.ShowCloudletPoolMember(uri, token, inCloudletPoolMember)
		checkMcCtrlErr("ShowCloudletPoolMember", status, err, rc)

		inAutoScalePolicy := &ormapi.RegionAutoScalePolicy{
			Region: ctrl.Region,
		}
		asPolicies, status, err := mcClient.ShowAutoScalePolicy(uri, token, inAutoScalePolicy)
		checkMcCtrlErr("ShowAutoScalePolicy", status, err, rc)

		inAutoProvPolicy := &ormapi.RegionAutoProvPolicy{
			Region: ctrl.Region,
		}
		apPolicies, status, err := mcClient.ShowAutoProvPolicy(uri, token, inAutoProvPolicy)
		checkMcCtrlErr("ShowAutoProvPolicy", status, err, rc)

		inClusterInst := &ormapi.RegionClusterInst{
			Region: ctrl.Region,
		}
		clusterInsts, status, err := mcClient.ShowClusterInst(uri, token, inClusterInst)
		checkMcCtrlErr("ShowClusterInst", status, err, rc)

		inApp := &ormapi.RegionApp{
			Region: ctrl.Region,
		}
		apps, status, err := mcClient.ShowApp(uri, token, inApp)
		checkMcCtrlErr("ShowApp", status, err, rc)

		inAppInst := &ormapi.RegionAppInst{
			Region: ctrl.Region,
		}
		appInsts, status, err := mcClient.ShowAppInst(uri, token, inAppInst)
		checkMcCtrlErr("ShowAppInst", status, err, rc)

		// match what alldata.go does.
		if len(flavors) == 0 && len(cloudlets) == 0 &&
			len(clusterInsts) == 0 && len(apps) == 0 &&
			len(appInsts) == 0 && len(codes) == 0 &&
			len(asPolicies) == 0 && len(apPolicies) == 0 {
			continue
		}

		rd := ormapi.RegionData{
			Region: ctrl.Region,
			AppData: edgeproto.ApplicationData{
				Flavors:             flavors,
				Cloudlets:           cloudlets,
				CloudletPools:       pools,
				CloudletPoolMembers: members,
				ClusterInsts:        clusterInsts,
				Applications:        apps,
				AppInstances:        appInsts,
				AutoScalePolicies:   asPolicies,
				AutoProvPolicies:    apPolicies,
				OperatorCodes:       codes,
				Settings:            settings,
			},
		}
		showData.RegionData = append(showData.RegionData, rd)
	}
	return showData
}

func showMcDataFiltered(uri, token string, data *ormapi.AllData, rc *bool) *ormapi.AllData {
	dataOut := &ormapi.AllData{}

	// currently only controller APIs support filtering
	for ii, _ := range data.RegionData {
		region := data.RegionData[ii].Region
		appdata := &data.RegionData[ii].AppData

		rd := ormapi.RegionData{}
		rd.Region = region
		ad := &rd.AppData

		for jj, _ := range appdata.Flavors {
			filter := &ormapi.RegionFlavor{
				Region: region,
				Flavor: appdata.Flavors[jj],
			}
			out, status, err := mcClient.ShowFlavor(uri, token, filter)
			checkMcCtrlErr("ShowFlavor", status, err, rc)
			ad.Flavors = append(ad.Flavors, out...)
		}
		for jj, _ := range appdata.OperatorCodes {
			filter := &ormapi.RegionOperatorCode{
				Region:       region,
				OperatorCode: appdata.OperatorCodes[jj],
			}
			out, status, err := mcClient.ShowOperatorCode(uri, token, filter)
			checkMcCtrlErr("ShowOperatorCode", status, err, rc)
			ad.OperatorCodes = append(ad.OperatorCodes, out...)
		}
		for jj, _ := range appdata.Cloudlets {
			filter := &ormapi.RegionCloudlet{
				Region:   region,
				Cloudlet: appdata.Cloudlets[jj],
			}
			out, status, err := mcClient.ShowCloudlet(uri, token, filter)
			checkMcCtrlErr("ShowCloudlet", status, err, rc)
			ad.Cloudlets = append(ad.Cloudlets, out...)
		}
		for jj, _ := range appdata.CloudletPools {
			filter := &ormapi.RegionCloudletPool{
				Region:       region,
				CloudletPool: appdata.CloudletPools[jj],
			}
			out, status, err := mcClient.ShowCloudletPool(uri, token, filter)
			checkMcCtrlErr("ShowCloudletPool", status, err, rc)
			ad.CloudletPools = append(ad.CloudletPools, out...)
		}
		for jj, _ := range appdata.CloudletPoolMembers {
			filter := &ormapi.RegionCloudletPoolMember{
				Region:             region,
				CloudletPoolMember: appdata.CloudletPoolMembers[jj],
			}
			out, status, err := mcClient.ShowCloudletPoolMember(uri, token, filter)
			checkMcCtrlErr("ShowCloudletPoolMember", status, err, rc)
			ad.CloudletPoolMembers = append(ad.CloudletPoolMembers, out...)
		}
		for jj, _ := range appdata.AutoScalePolicies {
			filter := &ormapi.RegionAutoScalePolicy{
				Region:          region,
				AutoScalePolicy: appdata.AutoScalePolicies[jj],
			}
			out, status, err := mcClient.ShowAutoScalePolicy(uri, token, filter)
			checkMcCtrlErr("ShowAutoScalePolicy", status, err, rc)
			ad.AutoScalePolicies = append(ad.AutoScalePolicies, out...)
		}
		for jj, _ := range appdata.AutoProvPolicies {
			filter := &ormapi.RegionAutoProvPolicy{
				Region:         region,
				AutoProvPolicy: appdata.AutoProvPolicies[jj],
			}
			out, status, err := mcClient.ShowAutoProvPolicy(uri, token, filter)
			checkMcCtrlErr("ShowAutoProvPolicy", status, err, rc)
			ad.AutoProvPolicies = append(ad.AutoProvPolicies, out...)
		}
		for jj, _ := range appdata.ClusterInsts {
			filter := &ormapi.RegionClusterInst{
				Region:      region,
				ClusterInst: appdata.ClusterInsts[jj],
			}
			out, status, err := mcClient.ShowClusterInst(uri, token, filter)
			checkMcCtrlErr("ShowClusterInst", status, err, rc)
			ad.ClusterInsts = append(ad.ClusterInsts, out...)
		}
		for jj, _ := range appdata.Applications {
			filter := &ormapi.RegionApp{
				Region: region,
				App:    appdata.Applications[jj],
			}
			out, status, err := mcClient.ShowApp(uri, token, filter)
			checkMcCtrlErr("ShowApp", status, err, rc)
			ad.Applications = append(ad.Applications, out...)
		}
		for jj, _ := range appdata.AppInstances {
			filter := &ormapi.RegionAppInst{
				Region:  region,
				AppInst: appdata.AppInstances[jj],
			}
			log.Printf("Show AppInstances filter %v\n", filter)
			out, status, err := mcClient.ShowAppInst(uri, token, filter)
			checkMcCtrlErr("ShowAppInst", status, err, rc)
			log.Printf("Show AppInstances got %v\n", out)
			ad.AppInstances = append(ad.AppInstances, out...)
		}
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

func runRegionDataApi(mcClient ormclient.Api, uri, token string, rd *ormapi.RegionData, rdMap interface{}, rc *bool, mode string) {
	appDataMap := getRegionAppDataFromMap(rdMap)
	switch mode {
	case "create":
		fallthrough
	case "update":
		testutil.RunMcSettingsApi(mcClient, uri, token, rd.Region, rd.AppData.Settings, appDataMap["settings"], rc, "update")
		testutil.RunMcFlavorApi(mcClient, uri, token, rd.Region, &rd.AppData.Flavors, appDataMap["flavors"], rc, mode)
		testutil.RunMcOperatorCodeApi(mcClient, uri, token, rd.Region, &rd.AppData.OperatorCodes, appDataMap["operatorcodes"], rc, mode)
		testutil.RunMcCloudletApi(mcClient, uri, token, rd.Region, &rd.AppData.Cloudlets, appDataMap["cloudlets"], rc, mode)
		testutil.RunMcCloudletPoolApi(mcClient, uri, token, rd.Region, &rd.AppData.CloudletPools, appDataMap["cloudletpools"], rc, mode)
		testutil.RunMcCloudletPoolMemberApi(mcClient, uri, token, rd.Region, &rd.AppData.CloudletPoolMembers, appDataMap["cloudletpoolmembers"], rc, mode)
		testutil.RunMcAutoScalePolicyApi(mcClient, uri, token, rd.Region, &rd.AppData.AutoScalePolicies, appDataMap["autoscalepolicies"], rc, mode)
		if _, ok := mcClient.(*cliwrapper.Client); ok {
			// cli can't handle list of Cloudlets in
			// AutoProvPolicy, so add them separately.
			policies := rd.AppData.AutoProvPolicies
			add := make([]edgeproto.AutoProvPolicyCloudlet, 0)
			for ii, _ := range policies {
				if policies[ii].Cloudlets == nil || len(policies[ii].Cloudlets) == 0 {
					continue
				}
				for jj, _ := range policies[ii].Cloudlets {
					a := edgeproto.AutoProvPolicyCloudlet{}
					a.Key = policies[ii].Key
					a.CloudletKey = policies[ii].Cloudlets[jj].Key
					add = append(add, a)
				}
				policies[ii].Cloudlets = nil
			}
			testutil.RunMcAutoProvPolicyApi(mcClient, uri, token, rd.Region, &policies, appDataMap["autoprovpolicies"], rc, mode)
			testutil.RunMcAutoProvPolicyApi_AutoProvPolicyCloudlet(mcClient, uri, token, rd.Region, &add, nil, rc, "add")
		} else {
			testutil.RunMcAutoProvPolicyApi(mcClient, uri, token, rd.Region, &rd.AppData.AutoProvPolicies, appDataMap["autoprovpolicies"], rc, mode)
		}
		testutil.RunMcClusterInstApi(mcClient, uri, token, rd.Region, &rd.AppData.ClusterInsts, appDataMap["clusterinsts"], rc, mode)
		testutil.RunMcAppApi(mcClient, uri, token, rd.Region, &rd.AppData.Applications, appDataMap["apps"], rc, mode)
		testutil.RunMcAppInstApi(mcClient, uri, token, rd.Region, &rd.AppData.AppInstances, appDataMap["appinstances"], rc, mode)
	case "delete":
		testutil.RunMcAppInstApi(mcClient, uri, token, rd.Region, &rd.AppData.AppInstances, appDataMap["appinstances"], rc, mode)
		testutil.RunMcAppApi(mcClient, uri, token, rd.Region, &rd.AppData.Applications, appDataMap["apps"], rc, mode)
		testutil.RunMcClusterInstApi(mcClient, uri, token, rd.Region, &rd.AppData.ClusterInsts, appDataMap["clusterinsts"], rc, mode)
		testutil.RunMcAutoScalePolicyApi(mcClient, uri, token, rd.Region, &rd.AppData.AutoScalePolicies, appDataMap["autoscalepolicies"], rc, mode)
		if _, ok := mcClient.(*cliwrapper.Client); ok {
			// cli can't handle list of Cloudlets,
			// but no need to specify them for delete
			policies := rd.AppData.AutoProvPolicies
			for ii, _ := range policies {
				policies[ii].Cloudlets = nil
			}
			testutil.RunMcAutoProvPolicyApi(mcClient, uri, token, rd.Region, &policies, appDataMap["autoprovpolicies"], rc, mode)
		} else {
			testutil.RunMcAutoProvPolicyApi(mcClient, uri, token, rd.Region, &rd.AppData.AutoProvPolicies, appDataMap["autoprovpolicies"], rc, mode)
		}
		testutil.RunMcCloudletPoolMemberApi(mcClient, uri, token, rd.Region, &rd.AppData.CloudletPoolMembers, appDataMap["cloudletpoolmembers"], rc, mode)
		testutil.RunMcCloudletPoolApi(mcClient, uri, token, rd.Region, &rd.AppData.CloudletPools, appDataMap["cloudletpools"], rc, mode)
		testutil.RunMcCloudletApi(mcClient, uri, token, rd.Region, &rd.AppData.Cloudlets, appDataMap["cloudlets"], rc, mode)
		testutil.RunMcOperatorCodeApi(mcClient, uri, token, rd.Region, &rd.AppData.OperatorCodes, appDataMap["operatorcodes"], rc, mode)
		testutil.RunMcFlavorApi(mcClient, uri, token, rd.Region, &rd.AppData.Flavors, appDataMap["flavors"], rc, mode)
		testutil.RunMcSettingsApi(mcClient, uri, token, rd.Region, rd.AppData.Settings, appDataMap["settings"], rc, "reset")
	}
}

func createMcDataSep(uri, token string, data *ormapi.AllData, regionDataMap *[]interface{}, rc *bool) {
	for _, ctrl := range data.Controllers {
		st, err := mcClient.CreateController(uri, token, &ctrl)
		checkMcErr("CreateController", st, err, rc)
	}
	for _, org := range data.Orgs {
		st, err := mcClient.CreateOrg(uri, token, &org)
		checkMcErr("CreateOrg", st, err, rc)
	}
	for _, role := range data.Roles {
		st, err := mcClient.AddUserRole(uri, token, &role)
		checkMcErr("AddUserRole", st, err, rc)
	}
	for ii, rd := range data.RegionData {
		runRegionDataApi(mcClient, uri, token, &rd, (*regionDataMap)[ii], rc, "create")
	}
	for _, oc := range data.OrgCloudletPools {
		st, err := mcClient.CreateOrgCloudletPool(uri, token, &oc)
		checkMcErr("CreateOrgCloudletPool", st, err, rc)
	}
}

func deleteMcDataSep(uri, token string, data *ormapi.AllData, regionDataMap *[]interface{}, rc *bool) {
	for _, oc := range data.OrgCloudletPools {
		st, err := mcClient.DeleteOrgCloudletPool(uri, token, &oc)
		checkMcErr("DeleteOrgCloudletPool", st, err, rc)
	}
	for ii, rd := range data.RegionData {
		runRegionDataApi(mcClient, uri, token, &rd, (*regionDataMap)[ii], rc, "delete")
	}
	for _, org := range data.Orgs {
		st, err := mcClient.DeleteOrg(uri, token, &org)
		checkMcErr("DeleteOrg", st, err, rc)
	}
	for _, role := range data.Roles {
		st, err := mcClient.RemoveUserRole(uri, token, &role)
		checkMcErr("RemoveUserRole", st, err, rc)
	}
	for _, ctrl := range data.Controllers {
		st, err := mcClient.DeleteController(uri, token, &ctrl)
		checkMcErr("DeleteController", st, err, rc)
	}
}

func updateMcDataSep(uri, token string, data *ormapi.AllData, regionDataMap *[]interface{}, rc *bool) {
	for ii, rd := range data.RegionData {
		runRegionDataApi(mcClient, uri, token, &rd, (*regionDataMap)[ii], rc, "update")
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

func runMcRunCommand(uri, apiFile, curUserFile, outputDir string, mods []string, vars map[string]string) bool {
	// test only runnable for mod CLI. Also avoid for mod sep just
	// because webrtc takes a while to setup and it slows down the tests.
	if !hasMod("cli", mods) || hasMod("sep", mods) {
		return true
	}
	client, ok := mcClient.(*cliwrapper.Client)
	if !ok {
		// should never happen because of check for "cli" mod above.
		panic("not cliwrapper client")
	}

	// RunCommand is a special case only supported by mcctl CLI,
	// because it leverages the webrtc client code in mcctl.
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
	out, err := client.RunCommandOut(uri, token, &data.Request)
	if err != nil {
		log.Printf("Error running RunCommand API %v\n", err)
		return false
	}
	log.Printf("RunCommand output: %s\n", out)
	actual := strings.TrimSpace(out)
	if actual != data.ExpectedOutput {
		log.Printf("Did not get expected output: %s\n", data.ExpectedOutput)
		return false
	}
	return true
}

func runMcAudit(api, uri, apiFile, curUserFile, outputDir string, mods []string, vars map[string]string) bool {
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
	return rc
}

func getTokenFile(username, outputDir string) string {
	return outputDir + "/" + username + ".token"
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
				// ignore timestamps
				if series.Columns[i] == "time" || series.Columns[i] == "metadata" {
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
