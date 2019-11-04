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
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormclient"
	"github.com/mobiledgex/edge-cloud/edgeproto"
	"github.com/mobiledgex/edge-cloud/setup-env/util"
)

var mcClient ormclient.Api

func RunMcAPI(api, mcname, apiFile, curUserFile, outputDir string, mods []string) bool {
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
		return runMcUsersAPI(api, uri, apiFile, curUserFile, outputDir, mods)
	} else if strings.HasPrefix(api, "audit") {
		return runMcAudit(api, uri, apiFile, curUserFile, outputDir, mods)
	} else if api == "runcommand" {
		return runMcRunCommand(uri, apiFile, curUserFile, outputDir, mods)
	}
	return runMcDataAPI(api, uri, apiFile, curUserFile, outputDir, mods)
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

func runMcUsersAPI(api, uri, apiFile, curUserFile, outputDir string, mods []string) bool {
	log.Printf("Applying MC users via APIs for %s\n", apiFile)

	rc := true
	if api == "showusers" {
		token, rc := loginCurUser(uri, curUserFile)
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
	users := readUsersFiles(apiFile)

	switch api {
	case "createusers":
		for _, user := range users {
			status, err := mcClient.CreateUser(uri, &user)
			checkMcErr("CreateUser", status, err, &rc)
		}
	case "deleteusers":
		token, ok := loginCurUser(uri, curUserFile)
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

func runMcDataAPI(api, uri, apiFile, curUserFile, outputDir string, mods []string) bool {
	log.Printf("Applying MC data via APIs for %s %v\n", apiFile, mods)
	sep := hasMod("sep", mods)

	// Data APIs are all run by a given user.
	// That user is specified in the current user file.
	// We need to log in as that user.
	rc := true
	token, rc := loginCurUser(uri, curUserFile)
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
		targets := readMCMetricTargetsFile(apiFile)
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
	data := readMCDataFile(apiFile)
	switch api {
	case "create":
		if sep {
			createMcDataSep(uri, token, data, &rc)
		} else {
			createMcDataAll(uri, token, data, &rc)
		}
	case "delete":
		if sep {
			deleteMcDataSep(uri, token, data, &rc)
		} else {
			deleteMcDataAll(uri, token, data, &rc)
		}
	}
	return rc
}

func readUsersFiles(file string) []ormapi.User {
	users := []ormapi.User{}
	files := strings.Split(file, ",")
	for _, file := range files {
		fileusers := []ormapi.User{}
		err := util.ReadYamlFile(file, &fileusers)
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

func readMCDataFile(file string) *ormapi.AllData {
	data := ormapi.AllData{}
	err := util.ReadYamlFile(file, &data)
	if err != nil {
		if !util.IsYamlOk(err, "mcdata") {
			fmt.Fprintf(os.Stderr, "error in unmarshal for file %s\n", file)
			os.Exit(1)
		}
	}
	return &data
}

func readMCMetricTargetsFile(file string) *MetricTargets {
	targets := MetricTargets{}
	err := util.ReadYamlFile(file, &targets)
	if err != nil {
		if !util.IsYamlOk(err, "mcdata") {
			fmt.Fprintf(os.Stderr, "error in unmarshal for file %s\n", file)
			os.Exit(1)
		}
	}
	return &targets
}

func loginCurUser(uri, curUserFile string) (string, bool) {
	if curUserFile == "" {
		log.Println("Error: Cannot run MC APIs without current user file")
		return "", false
	}
	users := readUsersFiles(curUserFile)
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
		inFlavor := &ormapi.RegionFlavor{
			Region: ctrl.Region,
		}
		flavors, status, err := mcClient.ShowFlavor(uri, token, inFlavor)
		checkMcCtrlErr("ShowFlavors", status, err, rc)

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
			len(appInsts) == 0 {
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
			},
		}
		showData.RegionData = append(showData.RegionData, rd)
	}
	return showData
}

func createMcDataSep(uri, token string, data *ormapi.AllData, rc *bool) {
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
	for _, rd := range data.RegionData {
		for _, flavor := range rd.AppData.Flavors {
			in := &ormapi.RegionFlavor{
				Region: rd.Region,
				Flavor: flavor,
			}
			_, st, err := mcClient.CreateFlavor(uri, token, in)
			checkMcErr("CreateFlavor", st, err, rc)
		}
		for _, cloudlet := range rd.AppData.Cloudlets {
			in := &ormapi.RegionCloudlet{
				Region:   rd.Region,
				Cloudlet: cloudlet,
			}
			_, st, err := mcClient.CreateCloudlet(uri, token, in)
			checkMcErr("CreateCloudlet", st, err, rc)
		}
		for _, pool := range rd.AppData.CloudletPools {
			in := &ormapi.RegionCloudletPool{
				Region:       rd.Region,
				CloudletPool: pool,
			}
			_, st, err := mcClient.CreateCloudletPool(uri, token, in)
			checkMcErr("CreateCloudletPool", st, err, rc)
		}
		for _, member := range rd.AppData.CloudletPoolMembers {
			in := &ormapi.RegionCloudletPoolMember{
				Region:             rd.Region,
				CloudletPoolMember: member,
			}
			_, st, err := mcClient.CreateCloudletPoolMember(uri, token, in)
			checkMcErr("CreateCloudletPoolMember", st, err, rc)
		}
		for _, policy := range rd.AppData.AutoScalePolicies {
			in := &ormapi.RegionAutoScalePolicy{
				Region:          rd.Region,
				AutoScalePolicy: policy,
			}
			_, st, err := mcClient.CreateAutoScalePolicy(uri, token, in)
			checkMcErr("CreateAutoScalePolicy", st, err, rc)
		}
		for _, cinst := range rd.AppData.ClusterInsts {
			in := &ormapi.RegionClusterInst{
				Region:      rd.Region,
				ClusterInst: cinst,
			}
			_, st, err := mcClient.CreateClusterInst(uri, token, in)
			checkMcErr("CreateClusterInst", st, err, rc)
		}
		for _, app := range rd.AppData.Applications {
			in := &ormapi.RegionApp{
				Region: rd.Region,
				App:    app,
			}
			_, st, err := mcClient.CreateApp(uri, token, in)
			checkMcErr("CreateApp", st, err, rc)
		}
		for _, appinst := range rd.AppData.AppInstances {
			in := &ormapi.RegionAppInst{
				Region:  rd.Region,
				AppInst: appinst,
			}
			_, st, err := mcClient.CreateAppInst(uri, token, in)
			checkMcErr("CreateAppInst", st, err, rc)
		}
	}
	for _, oc := range data.OrgCloudletPools {
		st, err := mcClient.CreateOrgCloudletPool(uri, token, &oc)
		checkMcErr("CreateOrgCloudletPool", st, err, rc)
	}
}

func deleteMcDataSep(uri, token string, data *ormapi.AllData, rc *bool) {
	for _, oc := range data.OrgCloudletPools {
		st, err := mcClient.DeleteOrgCloudletPool(uri, token, &oc)
		checkMcErr("DeleteOrgCloudletPool", st, err, rc)
	}
	for _, rd := range data.RegionData {
		for _, appinst := range rd.AppData.AppInstances {
			in := &ormapi.RegionAppInst{
				Region:  rd.Region,
				AppInst: appinst,
			}
			_, st, err := mcClient.DeleteAppInst(uri, token, in)
			checkMcErr("DeleteAppInst", st, err, rc)
		}
		for _, app := range rd.AppData.Applications {
			in := &ormapi.RegionApp{
				Region: rd.Region,
				App:    app,
			}
			_, st, err := mcClient.DeleteApp(uri, token, in)
			checkMcErr("DeleteApp", st, err, rc)
		}
		for _, cinst := range rd.AppData.ClusterInsts {
			in := &ormapi.RegionClusterInst{
				Region:      rd.Region,
				ClusterInst: cinst,
			}
			_, st, err := mcClient.DeleteClusterInst(uri, token, in)
			checkMcErr("DeleteClusterInst", st, err, rc)
		}
		for _, policy := range rd.AppData.AutoScalePolicies {
			in := &ormapi.RegionAutoScalePolicy{
				Region:          rd.Region,
				AutoScalePolicy: policy,
			}
			_, st, err := mcClient.DeleteAutoScalePolicy(uri, token, in)
			checkMcErr("DeleteAutoScalePolicy", st, err, rc)
		}
		for _, member := range rd.AppData.CloudletPoolMembers {
			in := &ormapi.RegionCloudletPoolMember{
				Region:             rd.Region,
				CloudletPoolMember: member,
			}
			_, st, err := mcClient.DeleteCloudletPoolMember(uri, token, in)
			checkMcErr("DeleteCloudletPoolMember", st, err, rc)
		}
		for _, pool := range rd.AppData.CloudletPools {
			in := &ormapi.RegionCloudletPool{
				Region:       rd.Region,
				CloudletPool: pool,
			}
			_, st, err := mcClient.DeleteCloudletPool(uri, token, in)
			checkMcErr("DeleteCloudletPool", st, err, rc)
		}
		for _, cloudlet := range rd.AppData.Cloudlets {
			in := &ormapi.RegionCloudlet{
				Region:   rd.Region,
				Cloudlet: cloudlet,
			}
			_, st, err := mcClient.DeleteCloudlet(uri, token, in)
			checkMcErr("DeleteCloudlet", st, err, rc)
		}
		for _, flavor := range rd.AppData.Flavors {
			in := &ormapi.RegionFlavor{
				Region: rd.Region,
				Flavor: flavor,
			}
			_, st, err := mcClient.DeleteFlavor(uri, token, in)
			checkMcErr("DeleteFlavor", st, err, rc)
		}
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

func runMcRunCommand(uri, apiFile, curUserFile, outputDir string, mods []string) bool {
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
	token, rc := loginCurUser(uri, curUserFile)
	if !rc {
		return false
	}
	data := runCommandData{}
	err := util.ReadYamlFile(apiFile, &data)
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

func runMcAudit(api, uri, apiFile, curUserFile, outputDir string, mods []string) bool {
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
		users := readUsersFiles(apiFile)
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
	users := readUsersFiles(curUserFile)
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
	err = util.ReadYamlFile(apiFile, &query)
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
