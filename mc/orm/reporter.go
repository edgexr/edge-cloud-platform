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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	influxdb "github.com/influxdata/influxdb/client/v2"
	"github.com/labstack/echo"
	"github.com/edgexr/edge-cloud-infra/mc/ctrlclient"
	"github.com/edgexr/edge-cloud-infra/mc/ormapi"
	"github.com/edgexr/edge-cloud-infra/mc/ormutil"
	"github.com/edgexr/edge-cloud/cloudcommon"
	"github.com/edgexr/edge-cloud/cloudcommon/node"
	dme "github.com/edgexr/edge-cloud/d-match-engine/dme-proto"
	"github.com/edgexr/edge-cloud/edgeproto"
	"github.com/edgexr/edge-cloud/gcs"
	"github.com/edgexr/edge-cloud/log"
	"github.com/edgexr/edge-cloud/util"
)

var (
	reportTrigger chan bool

	ReportTimeout       = 1 * time.Hour
	NoCloudlet          = ""
	ReportRetryCount    = 5
	ReportRetryInterval = 5 * time.Minute

	OutputDataNoPDF = true
	OutputPDF       = false
)

func getOperatorReportsBucketName(deploymentTag string) string {
	return fmt.Sprintf("mobiledgex-%s-operator-reports", deploymentTag)
}

func getScheduleDayMonthCount(schedule edgeproto.ReportSchedule) (int, int, error) {
	var err error
	dayCount := 0
	monthCount := 0
	switch schedule {
	case edgeproto.ReportSchedule_EveryWeek:
		dayCount = 7
	case edgeproto.ReportSchedule_Every15Days:
		dayCount = 15
	case edgeproto.ReportSchedule_EveryMonth:
		monthCount = 1
	default:
		err = fmt.Errorf("Invalid report schedule: %v", schedule)
	}
	return dayCount, monthCount, err
}

func getNextReportTimeUTC(retryCount *int) time.Time {
	utcNow := time.Now().UTC()
	nextReportTime := time.Time{}
	if retryCount != nil && *retryCount > 0 {
		nextReportTime = utcNow.Add(ReportRetryInterval)
		*retryCount = *retryCount - 1
	} else {
		// report once a day at the start of the day 12am UTC
		nextReportTime = time.Date(utcNow.Year(), utcNow.Month(), utcNow.Day()+1, 0, 0, 0, 0, time.UTC)
	}
	return nextReportTime
}

func updateReporterData(ctx context.Context, reporterName, reporterOrg string, newDate time.Time, errStrs []string) (reterr error) {
	lookup := ormapi.Reporter{
		Org:  reporterOrg,
		Name: reporterName,
	}

	defer func() {
		if reterr != nil {
			log.SpanLog(ctx, log.DebugLevelInfo, "failed to update schedule data for reporter", "name", reporterName, "org", reporterOrg, "err", reterr)
		}
	}()

	db := loggedDB(ctx)
	tx := db.BeginTx(ctx, nil)
	defer tx.RollbackUnlessCommitted()

	updateReporter := ormapi.Reporter{}
	res := tx.Where(&lookup).First(&updateReporter)
	if res.RecordNotFound() {
		// reporter got deleted in meantime, ignore
		return nil
	}
	if res.Error != nil {
		return ormutil.DbErr(res.Error)
	}
	applyUpdate := false
	if !newDate.IsZero() {
		updateReporter.NextScheduleDate = ormapi.TimeToStr(newDate)
		updateReporter.Status = "success"
		applyUpdate = true
	}
	if len(errStrs) > 0 {
		errStr := strings.Join(errStrs, ";")
		updateReporter.Status = errStr
		applyUpdate = true
	}
	if applyUpdate {
		err := tx.Save(&updateReporter).Error
		if err != nil {
			return ormutil.DbErr(err)
		}
	}
	err := tx.Commit().Error
	if err != nil {
		return ormutil.DbErr(err)
	}
	return nil
}

func getAllRegions(ctx context.Context) ([]string, error) {
	controllers, err := ShowControllerObj(ctx, NoUserClaims, NoShowFilter)
	if err != nil {
		return nil, fmt.Errorf("Unable to get regions: %v", err)
	}

	regions := []string{}
	for _, controller := range controllers {
		regions = append(regions, controller.Region)
	}
	return regions, nil
}

// Start report generation thread to run every day 12AM UTC
func GenerateReports() {
	retryCount := ReportRetryCount
	reportTime := time.Now().UTC()
	for {
		select {
		case <-time.After(reportTime.Sub(time.Now().UTC())):
		case <-reportTrigger:
		}
		span := log.StartSpan(log.DebugLevelInfo, "Operator report generation thread")
		ctx := log.ContextWithSpan(context.Background(), span)
		// get list of all reporters
		db := loggedDB(ctx)
		reporters := []ormapi.Reporter{}
		err := db.Find(&reporters).Error
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfo, "Unable to get list of reporters", "err", err)
			// retry again in few minutes
			reportTime = getNextReportTimeUTC(&retryCount)
			span.Finish()
			continue
		}
		regions, err := getAllRegions(ctx)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfo, "Unable to get regions", "err", err)
			// retry again in few minutes
			reportTime = getNextReportTimeUTC(&retryCount)
			span.Finish()
			continue
		}

		storageClient, err := getGCSStorageClient(ctx)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelInfo, "Unable to setup GCS storage client", "err", err)
			// retry again in few minutes
			reportTime = getNextReportTimeUTC(&retryCount)
			span.Finish()
			continue
		}
		// reset retryCount
		retryCount = ReportRetryCount

		wgDone := make(chan bool)
		var wg sync.WaitGroup
		// For each reporter
		for _, reporter := range reporters {
			scheduleDate, err := ormapi.StrToTime(reporter.NextScheduleDate)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfo, "Invalid nextscheduledate", "reporter", reporter.Name, "nextscheduledate", reporter.NextScheduleDate, "error", err)
				continue
			}
			//   check if report time matches schedule date
			//      * get start & end date from schedule date & schedule interval
			//      * verify it reportTime
			if ormapi.DateCmp(scheduleDate, time.Now()) > 0 {
				// not scheduled to generate report
				continue
			}
			dayCount, monthCount, err := getScheduleDayMonthCount(reporter.Schedule)
			if err != nil {
				log.SpanLog(ctx, log.DebugLevelInfo, "failed to get day/month count for report schedule", "err", err)
				continue
			}
			StartTime := ormapi.StripTime(scheduleDate.AddDate(0, -monthCount, -dayCount))
			EndTime := ormapi.StripTime(scheduleDate).Add(-1 * time.Second)

			// generate report in a separate thread
			genReport := ormapi.GenerateReport{
				Org:       reporter.Org,
				StartTime: StartTime,
				EndTime:   EndTime,
				Timezone:  reporter.Timezone,
			}
			wg.Add(1)
			go func(inReporter ormapi.Reporter, genReport ormapi.GenerateReport, wg *sync.WaitGroup) {
				log.SpanLog(ctx, log.DebugLevelInfo, "Generate operator report", "reporter", inReporter.Name, "args", genReport)
				tags := map[string]string{"cloudletorg": genReport.Org}
				defer wg.Done()
				var output bytes.Buffer
				_, err = GenerateCloudletReport(ctx, inReporter.Username, regions, &genReport, &output, OutputPDF)
				if err != nil {
					log.SpanLog(ctx, log.DebugLevelInfo, "failed to generate cloudlet report", "org", genReport.Org, "err", err)
					nodeMgr.Event(ctx, "Cloudlet report generation failure", genReport.Org, tags, err)
					updateReporterData(
						ctx, inReporter.Name,
						genReport.Org, time.Time{},
						[]string{fmt.Sprintf("Failed to generate report: %v", err)},
					)
					return
				}
				errStrs := []string{}
				// Upload PDF report to cloudlet
				filename := ormapi.GetReporterFileName(inReporter.Name, &genReport)
				err = storageClient.UploadObject(ctx, filename, "", &output)
				if err != nil {
					nodeMgr.Event(ctx, "Cloudlet report upload failure", genReport.Org, tags, err)
					log.SpanLog(ctx, log.DebugLevelInfo, "failed to upload cloudlet report to cloudlet", "org", genReport.Org, "err", err)
					// if file upload failed, continue
					errStrs = append(errStrs, fmt.Sprintf("Failed to upload report to cloudlet: %v", err))
				}
				// Trigger email
				err = sendOperatorReportEmail(ctx, inReporter.Username, inReporter.Email, inReporter.Name, &genReport, filename, output.Bytes())
				if err != nil {
					nodeMgr.Event(ctx, "Send Cloudlet report email", genReport.Org, tags, err)
					log.SpanLog(ctx, log.DebugLevelInfo, "failed to send cloudlet report email", "org", genReport.Org, "email", inReporter.Email, "err", err)
					// if send email failed, continue
					errStrs = append(errStrs, fmt.Sprintf("Failed to send report to configured email: %v", err))
				}
				// Update next schedule date
				newDate := ormapi.StripTime(genReport.EndTime.AddDate(0, monthCount, dayCount))
				updateReporterData(ctx, inReporter.Name, genReport.Org, newDate, errStrs)
			}(reporter, genReport, &wg)
		}
		go func() {
			wg.Wait()
			close(wgDone)
		}()
		// wait for all threads to exit
		select {
		case <-wgDone:
			log.SpanLog(ctx, log.DebugLevelInfo, "Done Generating operator reports")
		case <-time.After(ReportTimeout):
			log.SpanLog(ctx, log.DebugLevelInfo, "Timed out generating operator reports")
		}
		storageClient.Close()
		reportTime = getNextReportTimeUTC(nil)
		log.SpanLog(ctx, log.DebugLevelInfo, "Next operator report generation run info", "date", reportTime)
		span.Finish()
	}
}

func InitReporter() {
	reportTrigger = make(chan bool, 10)
}

func triggerReporter() {
	select {
	case reportTrigger <- true:
	default:
	}
}

func validScheduleDate(scheduleDate time.Time, schedule edgeproto.ReportSchedule) error {
	if ormapi.DateCmp(scheduleDate, time.Now()) < 0 {
		return fmt.Errorf("Schedule date must not be historical date")
	}
	if schedule == edgeproto.ReportSchedule_EveryMonth {
		// if reporter is scheduled for EveryMonth, then ensure
		// that start schedule day is <= 28, so that we have consistent
		// next schedule day
		if scheduleDate.Day() > 28 {
			return fmt.Errorf("For reporter schedule 'EveryMonth', StartScheduleDate's day " +
				"should be less than 28 so that we have consistent schedule period")
		}
	}

	return nil
}

func tzMatch(timezone string, reportTime time.Time) (bool, error) {
	location, err := time.LoadLocation(timezone)
	if err != nil {
		return false, fmt.Errorf("Invalid timezone %s, %v", timezone, err)
	}
	_, tzOffset := time.Now().In(location).Zone()
	_, reportTimeOffset := reportTime.Zone()
	return tzOffset == reportTimeOffset, nil
}

// Create reporter to generate usage reports
func CreateReporter(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	reporter := ormapi.Reporter{}
	if err := c.Bind(&reporter); err != nil {
		return ormutil.BindErr(err)
	}
	// sanity check
	if reporter.Name == "" {
		return fmt.Errorf("Name not specified")
	}
	err = ValidNameNoUnderscore(reporter.Name)
	if err != nil {
		return err
	}
	if reporter.Org == "" {
		return fmt.Errorf("Org name has to be specified")
	}
	// get org details
	orgCheck, err := orgExists(ctx, reporter.Org)
	if err != nil {
		return err
	}
	if orgCheck.Type != OrgTypeOperator {
		return fmt.Errorf("Reporter can only be created for Operator org")
	}

	// check if user is authorized to create reporter
	if err := authorized(ctx, claims.Username, reporter.Org, ResourceCloudlets, ActionManage); err != nil {
		return err
	}

	// if an email is not specified send to an email on file
	if reporter.Email == "" {
		reporter.Email = claims.Email
	} else {
		// validate email
		if !util.ValidEmail(reporter.Email) {
			return fmt.Errorf("Reporter email is invalid")
		}
	}
	// validate report schedule
	if _, ok := edgeproto.ReportSchedule_name[int32(reporter.Schedule)]; !ok {
		return fmt.Errorf("Invalid reporter schedule")
	}
	if reporter.Timezone == "" {
		reporter.Timezone = "UTC"
	}
	// StartScheduleDate defaults to now
	if reporter.StartScheduleDate == "" {
		location, err := time.LoadLocation(reporter.Timezone)
		if err != nil {
			return fmt.Errorf("Invalid timezone %s, %v", reporter.Timezone, err)
		}
		reporter.StartScheduleDate = ormapi.TimeToStr(time.Now().In(location))
	}
	scheduleDate, err := ormapi.StrToTime(reporter.StartScheduleDate)
	if err != nil {
		return err
	}
	if err := validScheduleDate(scheduleDate, reporter.Schedule); err != nil {
		return err
	}

	if reporter.NextScheduleDate != "" {
		return fmt.Errorf("NextScheduleDate is for internal-use only")
	}

	match, err := tzMatch(reporter.Timezone, scheduleDate)
	if err != nil {
		return err
	}
	if !match {
		return fmt.Errorf("Timezone must match start schedule date timezone")
	}

	// Schedule date should only be date with no time value
	reporter.StartScheduleDate = ormapi.TimeToStr(ormapi.StripTime(scheduleDate))
	reporter.NextScheduleDate = reporter.StartScheduleDate
	reporter.Username = claims.Username

	// store in db
	db := loggedDB(ctx)
	err = db.Create(&reporter).Error
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key value violates unique constraint \"reporters_pkey") {
			return fmt.Errorf("Reporter for org %s with name %s already exists", reporter.Org, reporter.Name)
		}
		return ormutil.DbErr(err)
	}
	// trigger report generation if schedule date is today as it may have passed our internal report schedule
	if ormapi.DateCmp(scheduleDate, time.Now()) == 0 {
		triggerReporter()
	}
	return c.JSON(http.StatusOK, ormutil.Msg("Reporter created"))
}

func UpdateReporter(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	// Pull json directly so we can unmarshal twice.
	// First time is to do lookup, second time is to apply
	// modified fields.
	body, err := ioutil.ReadAll(c.Request().Body)
	in := ormapi.Reporter{}
	err = BindJson(body, &in)
	if err != nil {
		return ormutil.BindErr(err)
	}
	if in.Name == "" {
		return fmt.Errorf("Reporter name not specified")
	}
	if in.Org == "" {
		return fmt.Errorf("Reporter org not specified")
	}
	lookup := ormapi.Reporter{
		Name: in.Name,
		Org:  in.Org,
	}

	db := loggedDB(ctx)
	tx := db.BeginTx(ctx, nil)
	defer tx.RollbackUnlessCommitted()

	reporter := ormapi.Reporter{}
	res := tx.Where(&lookup).First(&reporter)
	if res.RecordNotFound() {
		return fmt.Errorf("Reporter not found")
	}
	if res.Error != nil {
		return ormutil.NewHTTPError(http.StatusInternalServerError, ormutil.DbErr(res.Error).Error())
	}

	// check if user is authorized to update reporter
	if err := authorized(ctx, claims.Username, reporter.Org, ResourceCloudlets, ActionManage); err != nil {
		return err
	}

	oldReporter := reporter
	// apply specified fields
	err = BindJson(body, &reporter)
	if err != nil {
		return ormutil.BindErr(err)
	}
	applyUpdate := false
	if reporter.Email != oldReporter.Email {
		// validate email
		if !util.ValidEmail(reporter.Email) {
			return fmt.Errorf("Reporter email is invalid")
		}
		applyUpdate = true
	}

	if reporter.Org != oldReporter.Org {
		return fmt.Errorf("Cannot change org")
	}

	if reporter.Username != oldReporter.Username {
		return fmt.Errorf("Cannot change username")
	}
	if reporter.Timezone == "" {
		reporter.Timezone = "UTC"
	}

	schedDateUpdated := false
	if reporter.Schedule != oldReporter.Schedule {
		// validate report schedule
		if _, ok := edgeproto.ReportSchedule_name[int32(reporter.Schedule)]; !ok {
			return fmt.Errorf("invalid schedule")
		}
		if reporter.StartScheduleDate == oldReporter.StartScheduleDate {
			// user has not specified start schedule date, reset it to today
			location, err := time.LoadLocation(reporter.Timezone)
			if err != nil {
				return fmt.Errorf("Invalid timezone %s, %v", reporter.Timezone, err)
			}
			reporter.StartScheduleDate = ormapi.TimeToStr(time.Now().In(location))
			schedDateUpdated = true
		}
		applyUpdate = true
	}
	scheduleDate, err := ormapi.StrToTime(reporter.StartScheduleDate)
	if err != nil {
		return err
	}

	validateTZ := false
	if reporter.StartScheduleDate != oldReporter.StartScheduleDate {
		if err := validScheduleDate(scheduleDate, reporter.Schedule); err != nil {
			return err
		}
		// Schedule date should only be date with no time value
		reporter.StartScheduleDate = ormapi.TimeToStr(ormapi.StripTime(scheduleDate))
		reporter.NextScheduleDate = reporter.StartScheduleDate
		validateTZ = true
		applyUpdate = true
		schedDateUpdated = true
	}

	if reporter.Timezone != oldReporter.Timezone {
		validateTZ = true
	}
	if validateTZ {
		match, err := tzMatch(reporter.Timezone, scheduleDate)
		if err != nil {
			return err
		}
		if !match {
			return fmt.Errorf("Timezone must match start schedule date timezone")
		}
	}

	if !applyUpdate {
		return fmt.Errorf("nothing to update")
	}

	err = tx.Save(&reporter).Error
	if err != nil {
		return ormutil.NewHTTPError(http.StatusInternalServerError, ormutil.DbErr(err).Error())
	}
	err = tx.Commit().Error
	if err != nil {
		return ormutil.NewHTTPError(http.StatusInternalServerError, ormutil.DbErr(err).Error())
	}
	if schedDateUpdated {
		// trigger report generation if schedule date is today as it may have passed our internal report schedule
		if ormapi.DateCmp(scheduleDate, time.Now()) == 0 {
			triggerReporter()
		}
	}
	return c.JSON(http.StatusOK, ormutil.Msg("reporter updated"))
}

func DeleteReporter(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	reporter := ormapi.Reporter{}
	if err := c.Bind(&reporter); err != nil {
		return ormutil.BindErr(err)
	}
	if reporter.Name == "" {
		return fmt.Errorf("Reporter name not specified")
	}
	if reporter.Org == "" {
		return fmt.Errorf("Reporter org not specified")
	}

	db := loggedDB(ctx)
	tx := db.BeginTx(ctx, nil)
	defer tx.RollbackUnlessCommitted()

	lookup := ormapi.Reporter{
		Name: reporter.Name,
		Org:  reporter.Org,
	}
	res := tx.Where(&lookup).First(&reporter)
	if res.RecordNotFound() {
		return fmt.Errorf("Reporter not found")
	}
	if res.Error != nil {
		return ormutil.NewHTTPError(http.StatusInternalServerError, ormutil.DbErr(res.Error).Error())
	}
	// check if user is authorized to delete reporter
	if err := authorized(ctx, claims.Username, reporter.Org, ResourceCloudlets, ActionManage); err != nil {
		return err
	}
	err = tx.Delete(&reporter).Error
	if err != nil {
		return err
	}
	err = tx.Commit().Error
	if err != nil {
		return ormutil.NewHTTPError(http.StatusInternalServerError, ormutil.DbErr(err).Error())
	}
	return c.JSON(http.StatusOK, ormutil.Msg("reporter deleted"))
}

func ShowReporter(c echo.Context) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	db := loggedDB(ctx)

	filter := ormapi.Reporter{}
	if c.Request().ContentLength > 0 {
		if err := c.Bind(&filter); err != nil {
			return ormutil.BindErr(err)
		}
	}
	authOrgs, err := enforcer.GetAuthorizedOrgs(ctx, claims.Username, ResourceCloudletAnalytics, ActionView)
	if err != nil {
		return ormutil.DbErr(err)
	}
	if len(authOrgs) == 0 {
		return echo.ErrForbidden
	}
	_, admin := authOrgs[""]
	_, orgFound := authOrgs[filter.Org]
	if filter.Org != "" && !admin && !orgFound {
		// no perms for specified org
		return echo.ErrForbidden
	}

	reporters := []ormapi.Reporter{}
	err = db.Where(&filter).Find(&reporters).Error
	if err != nil {
		return ormutil.DbErr(err)
	}
	showOutput := []ormapi.Reporter{}
	if admin {
		showOutput = reporters
	} else {
		for _, reporter := range reporters {
			if _, found := authOrgs[reporter.Org]; !found {
				continue
			}
			showOutput = append(showOutput, reporter)
		}
	}
	return c.JSON(http.StatusOK, showOutput)
}

// For testing only
func GenerateReportData(c echo.Context) error {
	return GenerateReportObj(c, OutputDataNoPDF)
}

func GenerateReport(c echo.Context) error {
	return GenerateReportObj(c, OutputPDF)
}

func GenerateReportObj(c echo.Context, dataOnly bool) error {
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	report := ormapi.GenerateReport{}
	if err := c.Bind(&report); err != nil {
		return ormutil.BindErr(err)
	}
	org := report.Org
	if org == "" {
		return fmt.Errorf("org not specified")
	}
	// auth for Operator access only
	// get org details
	orgCheck, err := orgExists(ctx, org)
	if err != nil {
		return err
	}
	if orgCheck.Type != OrgTypeOperator {
		return fmt.Errorf("report can only be generated for Operator org")
	}

	// check if user is authorized to generate cloudlet reports
	if err := authorized(ctx, claims.Username, report.Org, ResourceCloudletAnalytics, ActionView); err != nil {
		return err
	}

	_, startTimeZoneOffset := report.StartTime.Zone()
	_, endTimeZoneOffset := report.EndTime.Zone()
	if startTimeZoneOffset != endTimeZoneOffset {
		return fmt.Errorf("StartTime and EndTime must be in same timezone")
	}

	if report.Timezone == "" {
		report.Timezone = "UTC"
	}
	match, err := tzMatch(report.Timezone, report.StartTime)
	if err != nil {
		return err
	}
	if !match {
		return fmt.Errorf("Timezone must match start time's timezone")
	}

	if !report.StartTime.Before(report.EndTime) {
		return fmt.Errorf("start time must be before end time")
	}

	if !report.EndTime.Before(time.Now().In(report.EndTime.Location())) {
		return fmt.Errorf("end time must be historical time")
	}

	if report.EndTime.Sub(report.StartTime).Hours() < (7 * 24) {
		return fmt.Errorf("time range must be at least 7 days")
	}

	if report.EndTime.Sub(report.StartTime).Hours() > (31 * 24) {
		return fmt.Errorf("time range must not be more than 31 days")
	}

	regions, err := getAllRegions(ctx)
	if err != nil {
		return err
	}

	var output bytes.Buffer
	data, err := GenerateCloudletReport(ctx, claims.Username, regions, &report, &output, dataOnly)
	if err != nil {
		return err
	}

	if dataOnly {
		if data == nil {
			return fmt.Errorf("No report data")
		}
		return c.JSON(http.StatusOK, data)
	}

	return c.HTMLBlob(http.StatusOK, output.Bytes())
}

func GetCloudletSummaryData(ctx context.Context, username string, report *ormapi.GenerateReport) ([][]string, error) {
	rc := &ormutil.RegionContext{
		Region:   report.Region,
		Username: username,
		Database: database,
	}
	obj := edgeproto.Cloudlet{
		Key: edgeproto.CloudletKey{
			Organization: report.Org,
		},
	}
	cloudlets := [][]string{}
	cloudletsPresent := make(map[string]struct{})
	err := ctrlclient.ShowCloudletStream(ctx, rc, &obj, connCache, nil, func(res *edgeproto.Cloudlet) error {
		platformTypeStr := edgeproto.PlatformType_CamelName[int32(res.PlatformType)]
		platformTypeStr = strings.TrimPrefix(platformTypeStr, "PlatformType")
		// Better to show platform type as "simulated", instead of "fake"
		platformTypeStr = strings.Replace(platformTypeStr, "Fake", "Simulated", -1)
		stateStr := edgeproto.TrackedState_CamelName[int32(res.State)]
		cloudletData := []string{res.Key.Name, platformTypeStr, stateStr}

		cloudlets = append(cloudlets, cloudletData)
		cloudletsPresent[res.Key.Name] = struct{}{}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(cloudlets, func(i, j int) bool {
		return cloudlets[i][0] < cloudlets[j][0]
	})
	return cloudlets, nil
}

func GetCloudletPoolSummaryData(ctx context.Context, username string, report *ormapi.GenerateReport) ([][]string, error) {
	// get pools associated with orgs
	filter := map[string]interface{}{
		"region":            report.Region,
		"cloudlet_pool_org": report.Org,
	}
	poolAcceptedDevelopers := make(map[string][]string)
	poolPendingDevelopers := make(map[string][]string)
	acceptedOps, err := showCloudletPoolAccessObj(ctx, username, filter, accessTypeGranted)
	if err != nil {
		return nil, err
	}
	pendingOps, err := showCloudletPoolAccessObj(ctx, username, filter, accessTypePending)
	if err != nil {
		return nil, err
	}
	for _, op := range acceptedOps {
		if poolDevs, ok := poolAcceptedDevelopers[op.CloudletPool]; ok {
			poolDevs = append(poolDevs, op.Org)
			poolAcceptedDevelopers[op.CloudletPool] = poolDevs
		} else {
			poolAcceptedDevelopers[op.CloudletPool] = []string{op.Org}
		}
	}
	for _, op := range pendingOps {
		if poolDevs, ok := poolPendingDevelopers[op.CloudletPool]; ok {
			poolDevs = append(poolDevs, op.Org)
			poolPendingDevelopers[op.CloudletPool] = poolDevs
		} else {
			poolPendingDevelopers[op.CloudletPool] = []string{op.Org}
		}
	}
	rc := ormutil.RegionContext{
		Region:   report.Region,
		Username: username,
		Database: database,
	}
	poolKey := edgeproto.CloudletPoolKey{Organization: report.Org}
	poolCloudlets := make(map[string][]string)
	err = ctrlclient.ShowCloudletPoolStream(ctx, &rc, &edgeproto.CloudletPool{Key: poolKey}, connCache, nil, func(pool *edgeproto.CloudletPool) error {
		for _, clKey := range pool.Cloudlets {
			if cloudlets, ok := poolCloudlets[pool.Key.Name]; ok {
				cloudlets = append(cloudlets, clKey.Name)
				poolCloudlets[pool.Key.Name] = cloudlets
			} else {
				poolCloudlets[pool.Key.Name] = []string{clKey.Name}
			}
		}
		return nil
	})

	cloudletpools := [][]string{}
	for poolName, poolCloudlets := range poolCloudlets {
		// get accepted developers
		poolAcceptedDevs, _ := poolAcceptedDevelopers[poolName]
		poolPendingDevs, _ := poolPendingDevelopers[poolName]
		entry := []string{
			poolName,
			strings.Join(poolCloudlets, "\n"),
			strings.Join(poolAcceptedDevs, "\n"),
			strings.Join(poolPendingDevs, "\n"),
		}
		cloudletpools = append(cloudletpools, entry)
	}
	sort.Slice(cloudletpools, func(i, j int) bool {
		return cloudletpools[i][0] > cloudletpools[j][0]
	})
	return cloudletpools, nil
}

func GetCloudletResourceUsageData(ctx context.Context, username string, report *ormapi.GenerateReport) (map[string]TimeChartDataMap, error) {
	rc := &InfluxDBContext{}
	dbNames := []string{cloudcommon.CloudletResourceUsageDbName}
	in := ormapi.RegionCloudletMetrics{
		Region: report.Region,
		Cloudlet: edgeproto.CloudletKey{
			Organization: report.Org,
		},
		Selector: "resourceusage",
		MetricsCommon: ormapi.MetricsCommon{
			TimeRange: edgeproto.TimeRange{
				StartTime: report.StartTime,
				EndTime:   report.EndTime,
			},
		},
	}
	rc.region = in.Region

	platformTypes, err := getCloudletPlatformTypes(ctx, username, report.Region, []edgeproto.CloudletKey{in.Cloudlet})
	if err != nil {
		return nil, err
	}
	cmd := CloudletUsageMetricsQuery(&in, platformTypes)

	// Check the operator against the username
	if err := authorized(ctx, username, report.Org, ResourceCloudletAnalytics, ActionView); err != nil {
		return nil, err
	}

	chartMap := make(map[string]TimeChartDataMap)
	err = influxStream(ctx, rc, dbNames, cmd, func(res interface{}) error {
		results, ok := res.([]influxdb.Result)
		if !ok {
			return fmt.Errorf("result not expected type")
		}
		for _, result := range results {
			for _, row := range result.Series {
				if len(row.Columns) < 4 {
					// not enough data
					continue
				}
				// get column indices
				timeIndex := -1
				cloudletIndex := -1
				cloudletOrgIndex := -1
				resIndices := []int{}
				for ii, col := range row.Columns {
					switch col {
					case "time":
						timeIndex = ii
					case "cloudlet":
						cloudletIndex = ii
					case "cloudletorg":
						cloudletOrgIndex = ii
					default:
						resIndices = append(resIndices, ii)
					}
				}
				if timeIndex < 0 || cloudletIndex < 0 || cloudletOrgIndex < 0 || len(resIndices) == 0 {
					// not enough data
					continue
				}
				for _, val := range row.Values {
					timeStr, ok := val[timeIndex].(string)
					if !ok {
						log.SpanLog(ctx, log.DebugLevelInfo, "failed to fetch resource time", "time", val[timeIndex])
						continue
					}
					time, err := ormapi.StrToTime(timeStr)
					if err != nil {
						log.SpanLog(ctx, log.DebugLevelInfo, "failed to parse resource time", "time", timeStr)
						continue
					}
					cloudlet, ok := val[cloudletIndex].(string)
					if !ok {
						log.SpanLog(ctx, log.DebugLevelInfo, "failed to fetch cloudlet name", "cloudlet", val[cloudletIndex])
						continue
					}
					if _, ok := chartMap[cloudlet]; !ok {
						chartMap[cloudlet] = make(TimeChartDataMap)
					}
					for _, resIndex := range resIndices {
						if val[resIndex] == nil {
							continue
						}
						resName := row.Columns[resIndex]
						if resDesc, ok := cloudcommon.ResourceMetricsDesc[resName]; ok {
							resName = resDesc
						}
						if _, ok := chartMap[cloudlet][resName]; !ok {
							chartMap[cloudlet][resName] = []TimeChartData{TimeChartData{}}
						}
						clData := chartMap[cloudlet][resName][0]

						resVal, err := val[resIndex].(json.Number).Float64()
						if err != nil {
							log.SpanLog(ctx, log.DebugLevelInfo, "failed to parse resource value", "value", val[resIndex])
							continue
						}

						clData.XValues = append(clData.XValues, time)
						clData.YValues = append(clData.YValues, float64(resVal))
						chartMap[cloudlet][resName][0] = clData
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return chartMap, nil
}

func GetCloudletFlavorUsageData(ctx context.Context, username string, report *ormapi.GenerateReport) (map[string]PieChartDataMap, error) {
	rc := &InfluxDBContext{}
	dbNames := []string{cloudcommon.CloudletResourceUsageDbName}
	in := ormapi.RegionCloudletMetrics{
		Region: report.Region,
		Cloudlet: edgeproto.CloudletKey{
			Organization: report.Org,
		},
		Selector: "flavorusage",
		MetricsCommon: ormapi.MetricsCommon{
			TimeRange: edgeproto.TimeRange{
				StartTime: report.StartTime,
				EndTime:   report.EndTime,
			},
		},
	}
	rc.region = in.Region
	cmd := CloudletUsageMetricsQuery(&in, nil)

	// Check the operator against the username
	if err := authorized(ctx, username, report.Org, ResourceCloudletAnalytics, ActionView); err != nil {
		return nil, err
	}

	flavorMap := make(map[string]PieChartDataMap)
	err := influxStream(ctx, rc, dbNames, cmd, func(res interface{}) error {
		results, ok := res.([]influxdb.Result)
		if !ok {
			return fmt.Errorf("result not expected type")
		}
		for _, result := range results {
			for _, row := range result.Series {
				if len(row.Columns) < 5 {
					// not enough data
					continue
				}
				// get column indices
				timeIndex := -1
				cloudletIndex := -1
				cloudletOrgIndex := -1
				countIndex := -1
				flavorIndex := -1
				for ii, col := range row.Columns {
					switch col {
					case "time":
						timeIndex = ii
					case "cloudlet":
						cloudletIndex = ii
					case "cloudletorg":
						cloudletOrgIndex = ii
					case "count":
						countIndex = ii
					case "flavor":
						flavorIndex = ii
					}
				}
				if timeIndex < 0 ||
					cloudletIndex < 0 ||
					cloudletOrgIndex < 0 ||
					countIndex < 0 ||
					flavorIndex < 0 {
					// not enough data
					continue
				}
				for _, val := range row.Values {
					cloudlet, ok := val[cloudletIndex].(string)
					if !ok {
						log.SpanLog(ctx, log.DebugLevelInfo, "failed to fetch cloudlet name", "cloudlet", val[cloudletIndex])
						continue
					}
					if val[countIndex] == nil || val[flavorIndex] == nil {
						continue
					}
					countVal, err := val[countIndex].(json.Number).Float64()
					if err != nil {
						log.SpanLog(ctx, log.DebugLevelInfo, "failed to parse flavor count", "value", val[countIndex])
						continue
					}
					flavor, ok := val[flavorIndex].(string)
					if !ok {
						log.SpanLog(ctx, log.DebugLevelInfo, "failed to fetch flavor name", "flavor", val[flavorIndex])
						continue
					}
					if _, ok := flavorMap[cloudlet]; !ok {
						flavorMap[cloudlet] = make(PieChartDataMap)
					}
					if curVal, ok := flavorMap[cloudlet][flavor]; ok {
						if countVal <= curVal {
							continue
						}
					}
					flavorMap[cloudlet][flavor] = countVal
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return flavorMap, nil
}

func GetCloudletEvents(ctx context.Context, username string, report *ormapi.GenerateReport) (map[string][][]string, error) {
	search := node.EventSearch{
		Match: node.EventMatch{
			Orgs:    []string{report.Org},
			Types:   []string{node.EventType},
			Regions: []string{report.Region},
		},
		TimeRange: edgeproto.TimeRange{
			StartTime: report.StartTime,
			EndTime:   report.EndTime,
		},
	}

	events, err := nodeMgr.ShowEvents(ctx, &search)
	if err != nil {
		return nil, err
	}
	eventsData := make(map[string][][]string)
	for _, event := range events {
		cloudlet, ok := event.Mtags["cloudlet"]
		if !ok {
			log.SpanLog(ctx, log.DebugLevelInfo, "missing cloudlet name in event, skipping", "event", event)
			continue
		}
		timestamp := event.Timestamp.In(report.StartTime.Location()).Format(ormapi.TimeFormatDayDateTime)
		entry := []string{timestamp, event.Name}
		if _, ok := eventsData[cloudlet]; !ok {
			eventsData[cloudlet] = [][]string{}
		}
		eventsData[cloudlet] = append(eventsData[cloudlet], entry)
	}
	return eventsData, nil
}

func inTimeSpan(start, end, check time.Time) bool {
	startUTC := start.UTC()
	endUTC := end.UTC()
	checkUTC := check.UTC()
	if startUTC.Before(endUTC) {
		return !checkUTC.Before(startUTC) && !checkUTC.After(endUTC)
	}
	if startUTC.Equal(endUTC) {
		return checkUTC.Equal(startUTC)
	}
	return !startUTC.After(checkUTC) || !endUTC.Before(checkUTC)
}

func GetCloudletAlerts(ctx context.Context, username string, report *ormapi.GenerateReport) (map[string][][]string, error) {
	alertsData := make(map[string][][]string)
	rc := &ormutil.RegionContext{
		Region:   report.Region,
		Username: username,
		Database: database,
	}
	obj := &edgeproto.Alert{
		Labels: map[string]string{
			edgeproto.CloudletKeyTagOrganization: report.Org,
			cloudcommon.AlertScopeTypeTag:        cloudcommon.AlertScopeCloudlet,
		},
	}
	err := ctrlclient.ShowAlertStream(ctx, rc, obj, connCache, nil, func(alert *edgeproto.Alert) error {
		alertTime := dme.TimestampToTime(alert.ActiveAt).In(report.StartTime.Location())
		if !inTimeSpan(report.StartTime, report.EndTime, alertTime) {
			return nil
		}
		cloudlet, ok := alert.Labels[edgeproto.CloudletKeyTagName]
		if !ok {
			log.SpanLog(ctx, log.DebugLevelInfo, "missing cloudlet name in alert labels, skipping", "labels", alert.Labels)
		}
		desc, ok := alert.Annotations[cloudcommon.AlertAnnotationDescription]
		if !ok {
			log.SpanLog(ctx, log.DebugLevelInfo, "missing description in alert annotations, skipping", "annotations", alert.Annotations)
		}
		alertTimeStr := alertTime.Format(ormapi.TimeFormatDayDateTime)
		entry := []string{alertTimeStr, desc, alert.State}
		if _, ok := alertsData[cloudlet]; !ok {
			alertsData[cloudlet] = [][]string{}
		}
		alertsData[cloudlet] = append(alertsData[cloudlet], entry)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return alertsData, nil
}

func GetCloudletAppUsageData(ctx context.Context, username string, report *ormapi.GenerateReport) (map[string]PieChartDataMap, error) {
	rc := &ormutil.RegionContext{
		Region:   report.Region,
		Username: username,
		Database: database,
	}
	obj := &edgeproto.AppInst{
		Key: edgeproto.AppInstKey{
			ClusterInstKey: edgeproto.VirtualClusterInstKey{
				CloudletKey: edgeproto.CloudletKey{
					Organization: report.Org,
				},
			},
		},
		State:    edgeproto.TrackedState_READY,
		Liveness: edgeproto.Liveness_LIVENESS_STATIC,
	}
	appsCount := make(map[string]PieChartDataMap)
	err := ctrlclient.ShowAppInstStream(ctx, rc, obj, connCache, nil, func(appInst *edgeproto.AppInst) error {
		cloudletName := appInst.Key.ClusterInstKey.CloudletKey.Name
		appOrg := appInst.Key.AppKey.Organization
		if _, ok := appsCount[cloudletName]; !ok {
			appsCount[cloudletName] = make(PieChartDataMap)
		}
		if _, ok := appsCount[cloudletName][appOrg]; ok {
			appsCount[cloudletName][appOrg]++
		} else {
			appsCount[cloudletName][appOrg] = 1
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return appsCount, nil
}

func GetAppResourceUsageData(ctx context.Context, username string, report *ormapi.GenerateReport) (map[string]map[string]TimeChartDataMap, error) {
	rc := &InfluxDBContext{}
	dbNames := []string{cloudcommon.DeveloperMetricsDbName}
	in := ormapi.RegionAppInstMetrics{
		Region: report.Region,
		AppInst: edgeproto.AppInstKey{
			ClusterInstKey: edgeproto.VirtualClusterInstKey{
				CloudletKey: edgeproto.CloudletKey{
					Organization: report.Org,
				},
			},
		},
		Selector: "cpu,mem,disk,network",
		MetricsCommon: ormapi.MetricsCommon{
			TimeRange: edgeproto.TimeRange{
				StartTime: report.StartTime,
				EndTime:   report.EndTime,
			},
		},
	}
	rc.region = in.Region
	claims := &UserClaims{Username: username}
	cloudletList, err := checkPermissionsAndGetCloudletList(ctx, claims.Username, in.Region, []string{in.AppInst.AppKey.Organization},
		ResourceAppAnalytics, []edgeproto.CloudletKey{in.AppInst.ClusterInstKey.CloudletKey})
	if err != nil {
		return nil, err
	}
	cmd := AppInstMetricsQuery(&in, cloudletList)

	/*
	 * map structure:
	 *     cloudlet:
	 *         apporg:
	 *             cpu: resourcedata
	 *             mem: resourcedata
	 *             disk: resourcedata
	 */
	cpuKey := "cpu"
	memKey := "mem"
	diskKey := "disk"
	sendBytesKey := "sendBytes"
	recvBytesKey := "recvBytes"
	resIndexMap := map[string]int{
		cpuKey:       9,
		memKey:       10,
		diskKey:      11,
		sendBytesKey: 12,
		recvBytesKey: 13,
	}
	appMap := make(map[edgeproto.AppInstKey]map[string]TimeChartData)
	err = influxStream(ctx, rc, dbNames, cmd, func(res interface{}) error {
		results, ok := res.([]influxdb.Result)
		if !ok {
			return fmt.Errorf("result not expected type")
		}
		for _, result := range results {
			for _, row := range result.Series {
				/*
					columns[0] -> time
					columns[1] -> appname
					columns[2] -> appvers
					columns[3] -> clustername
					columns[4] -> clusterorg
					columns[5] -> cloudlet
					columns[6] -> cloudletorg
					columns[7] -> apporg
					columns[8] -> pod
					columns[9:] -> cpu,mem,disk,sendBytes,recvBytes
				*/
				for _, val := range row.Values {
					if len(val) < 10 {
						// not enough data
						continue
					}
					timeStr, ok := val[0].(string)
					if !ok {
						log.SpanLog(ctx, log.DebugLevelInfo, "failed to fetch resource time", "time", val[0])
					}
					time, err := ormapi.StrToTime(timeStr)
					if err != nil {
						log.SpanLog(ctx, log.DebugLevelInfo, "failed to parse resource time", "time", timeStr)
						continue
					}
					appname, ok := val[1].(string)
					if !ok {
						log.SpanLog(ctx, log.DebugLevelInfo, "failed to fetch app name", "app", val[1])
					}
					appvers, ok := val[2].(string)
					if !ok {
						log.SpanLog(ctx, log.DebugLevelInfo, "failed to fetch app version", "appvers", val[2])
					}
					apporg, ok := val[7].(string)
					if !ok {
						log.SpanLog(ctx, log.DebugLevelInfo, "failed to fetch app org", "apporg", val[7])
					}
					clustername, ok := val[3].(string)
					if !ok {
						log.SpanLog(ctx, log.DebugLevelInfo, "failed to fetch cluster name", "clustername", val[3])
					}
					clusterorg, ok := val[4].(string)
					if !ok {
						log.SpanLog(ctx, log.DebugLevelInfo, "failed to fetch cluster org", "clusterorg", val[4])
					}
					cloudlet, ok := val[5].(string)
					if !ok {
						log.SpanLog(ctx, log.DebugLevelInfo, "failed to fetch cloudlet name", "cloudlet", val[5])
					}
					appInstKey := edgeproto.AppInstKey{
						AppKey: edgeproto.AppKey{
							Name:         appname,
							Organization: apporg,
							Version:      appvers,
						},
						ClusterInstKey: edgeproto.VirtualClusterInstKey{
							ClusterKey: edgeproto.ClusterKey{
								Name: clustername,
							},
							Organization: clusterorg,
							CloudletKey: edgeproto.CloudletKey{
								Name:         cloudlet,
								Organization: report.Org,
							},
						},
					}
					appId := fmt.Sprintf("%s|%s|%s|%s", appname, appvers, clustername, clusterorg)
					if _, ok := appMap[appInstKey]; !ok {
						appMap[appInstKey] = make(map[string]TimeChartData)
						for resName, _ := range resIndexMap {
							appMap[appInstKey][resName] = TimeChartData{Name: appId}
						}
					}
					// parse resource fields
					for resName, resIndex := range resIndexMap {
						if resIndex >= len(val) {
							break
						}
						if val[resIndex] != nil {
							resVal, err := val[resIndex].(json.Number).Float64()
							if err != nil {
								log.SpanLog(ctx, log.DebugLevelInfo, "failed to parse resource value", "resource", resName, "value", val[resIndex])
								continue
							}

							clData := appMap[appInstKey][resName]
							clData.XValues = append(clData.XValues, time)
							clData.YValues = append(clData.YValues, float64(resVal))
							appMap[appInstKey][resName] = clData
						}
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	chartMap := make(map[string]map[string]TimeChartDataMap)

	for appInstKey, resChartData := range appMap {
		cloudlet := appInstKey.ClusterInstKey.CloudletKey.Name
		apporg := appInstKey.AppKey.Organization
		for resName, resData := range resChartData {
			if _, ok := chartMap[cloudlet]; !ok {
				chartMap[cloudlet] = make(map[string]TimeChartDataMap)
			}
			if _, ok := chartMap[cloudlet][apporg]; !ok {
				chartMap[cloudlet][apporg] = make(TimeChartDataMap)
			}
			resTitle := apporg + " " + resName
			if _, ok := chartMap[cloudlet][apporg][resTitle]; !ok {
				chartMap[cloudlet][apporg][resTitle] = []TimeChartData{}
			}
			chartMap[cloudlet][apporg][resTitle] = append(chartMap[cloudlet][apporg][resTitle], resData)
		}
	}
	return chartMap, nil
}

func GetAppStateEvents(ctx context.Context, username string, report *ormapi.GenerateReport) (map[string][][]string, error) {
	search := node.EventSearch{
		Match: node.EventMatch{
			Names:   []string{"AppInst online", "AppInst offline"},
			Types:   []string{node.EventType},
			Regions: []string{report.Region},
			Tags: map[string]string{
				"cloudletorg": report.Org,
			},
		},
		TimeRange: edgeproto.TimeRange{
			StartTime: report.StartTime,
			EndTime:   report.EndTime,
		},
	}

	events, err := nodeMgr.ShowEvents(ctx, &search)
	if err != nil {
		return nil, err
	}
	reqdTags := map[string]string{
		"app":        "",
		"apporg":     "",
		"appver":     "",
		"cloudlet":   "",
		"cluster":    "",
		"clusterorg": "",
	}
	eventsData := make(map[string][][]string)
	for _, event := range events {
		found := true
		for tag, _ := range reqdTags {
			tagVal, ok := event.Mtags[tag]
			if !ok {
				log.SpanLog(ctx, log.DebugLevelInfo, "missing tag in event, skipping", "tag", tag, "event", event)
				found = false
				break
			}
			reqdTags[tag] = tagVal
		}
		if !found {
			continue
		}
		timestamp := event.Timestamp.In(report.StartTime.Location()).Format(ormapi.TimeFormatDayDateTime)
		entry := []string{
			timestamp,
			reqdTags["app"] + " | " + reqdTags["appver"],         // App Identifier
			reqdTags["apporg"],                                   // Developer Org
			reqdTags["cluster"] + " | " + reqdTags["clusterorg"], // Cluster Identifier
			event.Name, // Event name
		}
		cloudlet := reqdTags["cloudlet"]
		if _, ok := eventsData[cloudlet]; !ok {
			eventsData[cloudlet] = [][]string{}
		}
		eventsData[cloudlet] = append(eventsData[cloudlet], entry)
	}
	return eventsData, nil
}

func GenerateCloudletReport(ctx context.Context, username string, regions []string, report *ormapi.GenerateReport, pdfOut *bytes.Buffer, dataOnly bool) (map[string]map[string]interface{}, error) {
	// fetch logo path
	logoPath := serverConfig.StaticDir + "/MobiledgeX_Logo.png"
	if _, err := os.Stat(logoPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("Missing logo")
	}
	pdfReport, err := NewReport(report)
	if err != nil {
		return nil, err
	}
	reportData := make(map[string]map[string]interface{})
	for _, region := range regions {
		report.Region = region
		// Get cloudlet summary
		cloudlets_summary, err := GetCloudletSummaryData(ctx, username, report)
		if err != nil {
			return nil, fmt.Errorf("failed to get cloudlet summary: %v", err)
		}
		if len(cloudlets_summary) == 0 {
			// Skip as Operator has no cloudlets in this region
			continue
		}
		reportData[region] = make(map[string]interface{})
		reportData[region]["cloudlets"] = cloudlets_summary

		log.SpanLog(ctx, log.DebugLevelInfo, "Generate operator report for region", "region", region)
		// start new page for every region
		pdfReport.ResetHeader()
		pdfReport.AddPage()

		pdfReport.AddReportTitle(logoPath)
		pdfReport.AddHeader(report, logoPath, NoCloudlet)
		pdfReport.AddFooter()
		pdfReport.AddOperatorInfo(report)
		pdfReport.AddHorizontalLine()

		// Step-1: Gather all data
		// -------------------------
		// Get list of cloudletpools
		cloudletpools, err := GetCloudletPoolSummaryData(ctx, username, report)
		if err != nil {
			return nil, fmt.Errorf("failed to get cloudlet pool summary: %v", err)
		}
		reportData[region]["cloudletpools"] = cloudletpools

		cloudlets := make(map[string]struct{})
		// Get cloudlet resource usage metrics
		resourceUsageCharts, err := GetCloudletResourceUsageData(ctx, username, report)
		if err != nil {
			return nil, fmt.Errorf("failed to get cloudlet resource usage data: %v", err)
		}
		for cloudletName, _ := range resourceUsageCharts {
			cloudlets[cloudletName] = struct{}{}
		}
		reportData[region]["resourcesused"] = resourceUsageCharts

		// Get top flavors used per Cloudlet
		flavorData, err := GetCloudletFlavorUsageData(ctx, username, report)
		if err != nil {
			return nil, fmt.Errorf("failed to get cloudlet flavor usage data: %v", err)
		}
		for cloudletName, _ := range flavorData {
			cloudlets[cloudletName] = struct{}{}
		}
		reportData[region]["flavorsused"] = flavorData

		// Get cloudlet events
		eventsData, err := GetCloudletEvents(ctx, username, report)
		if err != nil {
			return nil, fmt.Errorf("failed to get cloudlet events: %v", err)
		}
		for cloudletName, _ := range eventsData {
			cloudlets[cloudletName] = struct{}{}
		}
		reportData[region]["cloudletevents"] = eventsData

		// Get cloudlet alerts
		alertsData, err := GetCloudletAlerts(ctx, username, report)
		if err != nil {
			return nil, fmt.Errorf("failed to get cloudlet alerts: %v", err)
		}
		for cloudletName, _ := range alertsData {
			cloudlets[cloudletName] = struct{}{}
		}
		reportData[region]["cloudletalerts"] = alertsData

		// Get app count by developer on cloudlet
		appCountData, err := GetCloudletAppUsageData(ctx, username, report)
		if err != nil {
			if strings.Contains(err.Error(), "Forbidden") {
				// ignore as user is not authorized to perform this action
				appCountData = make(map[string]PieChartDataMap)
			} else {
				return nil, fmt.Errorf("failed to get cloudlet app count data: %v", err)
			}
		}
		for cloudletName, _ := range appCountData {
			cloudlets[cloudletName] = struct{}{}
		}
		reportData[region]["appcounts"] = appCountData

		// Get app state events
		appEventsData, err := GetAppStateEvents(ctx, username, report)
		if err != nil {
			if strings.Contains(err.Error(), "Forbidden") {
				// ignore as user is not authorized to perform this action
				appEventsData = make(map[string][][]string)
			} else {
				return nil, fmt.Errorf("failed to get app events: %v", err)
			}
		}
		for cloudletName, _ := range appEventsData {
			cloudlets[cloudletName] = struct{}{}
		}
		reportData[region]["appevents"] = appEventsData

		// Step-2: Render data
		// -------------------------
		// Get list of cloudlets
		header := []string{"Name", "Platform Type", "Last Known State"}
		columnsWidth := []float64{60, 30, 35}
		pdfReport.AddTable("Cloudlets", header, cloudlets_summary, columnsWidth)

		// Get list of cloudletpools
		if len(cloudletpools) > 0 {
			header = []string{"Name", "Associated Cloudlets", "Accepted Developers", "Pending Developers"}
			columnsWidth = []float64{30, 60, 50, 50}
			pdfReport.AddTable("CloudletPools - Last Known Details", header, cloudletpools, columnsWidth)
		}

		// Sort cloudlet by name
		cloudletNames := []string{}
		for k := range cloudlets {
			cloudletNames = append(cloudletNames, k)
		}
		sort.Strings(cloudletNames)

		// Show per cloudlet reports
		for _, cloudletName := range cloudletNames {
			// Start new page
			pdfReport.AddHeader(report, logoPath, cloudletName)
			pdfReport.AddPage()

			pdfReport.AddPageTitle(cloudletName)

			// Get cloudlet resource usage metrics
			if data, ok := resourceUsageCharts[cloudletName]; ok {
				err = pdfReport.AddResourceTimeCharts(cloudletName, data, ChartSpec{FillColor: true})
				if err != nil {
					return nil, err
				}
			}

			// Get top flavors used per Cloudlet
			if data, ok := flavorData[cloudletName]; ok {
				err = pdfReport.AddPieChart(cloudletName, "Flavor Usage - Count of maximum flavors used", data)
				if err != nil {
					return nil, err
				}
			}
			// Get cloudlet events
			if data, ok := eventsData[cloudletName]; ok {
				header = []string{"Timestamp", "Description"}
				columnsWidth = []float64{50, 120}
				pdfReport.AddTable("Cloudlet Events", header, data, columnsWidth)
			}

			// Get cloudlet alerts
			if data, ok := alertsData[cloudletName]; ok {
				header = []string{"Timestamp", "Description", "State"}
				columnsWidth = []float64{40, 100, 30}
				pdfReport.AddTable("Cloudlet Alerts", header, data, columnsWidth)
			}

			// Get app count by developer on cloudlet
			if data, ok := appCountData[cloudletName]; ok {
				err = pdfReport.AddPieChart(cloudletName, "Developer App Deployments - Count of maximum apps deployed by developers", data)
				if err != nil {
					return nil, err
				}
			}

			// Get app state events
			if data, ok := appEventsData[cloudletName]; ok {
				header = []string{"Timestamp", "App Info", "Developer", "Cluster Info", "State"}
				columnsWidth = []float64{30, 40, 40, 40, 30}
				pdfReport.AddTable("Developer App State", header, data, columnsWidth)
			}
		}
	}
	if dataOnly {
		return reportData, nil
	}
	if err = pdfReport.Err(); err != nil {
		return nil, fmt.Errorf("failed to create PDF report: %s\n", err.Error())
	}
	err = pdfReport.Output(pdfOut)
	if err != nil {
		return nil, fmt.Errorf("cannot get PDF output: %v", err)
	}
	return nil, nil
}

// Must call GCSClient.Close() when done
func getGCSStorageClient(ctx context.Context) (*gcs.GCSClient, error) {
	bucketName := getOperatorReportsBucketName(serverConfig.DeploymentTag)
	credsObj, err := gcs.GetGCSCreds(ctx, serverConfig.vaultConfig)
	if err != nil {
		return nil, err
	}
	storageClient, err := gcs.NewClient(ctx, credsObj, bucketName, gcs.ShortTimeout)
	if err != nil {
		return nil, fmt.Errorf("Unable to setup GCS client: %v", err)
	}
	return storageClient, nil
}

func ShowReport(c echo.Context) error {
	// get list of generated reports from cloud
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	reportQuery := ormapi.DownloadReport{}
	if err := c.Bind(&reportQuery); err != nil {
		return ormutil.BindErr(err)
	}
	// sanity check
	if reportQuery.Org == "" {
		return fmt.Errorf("Org name has to be specified")
	}
	// check if user is authorized to view reports
	if err := authorized(ctx, claims.Username, reportQuery.Org, ResourceCloudletAnalytics, ActionView); err != nil {
		return err
	}

	storageClient, err := getGCSStorageClient(ctx)
	if err != nil {
		return err
	}
	defer storageClient.Close()
	objs, err := storageClient.ListObjects(ctx)
	if err != nil {
		return fmt.Errorf("Unable to get reports from GCS: %v", err)
	}
	out := []string{}
	for _, obj := range objs {
		orgName, reporterName := ormapi.GetInfoFromReportFileName(obj)
		if orgName == "" || reporterName == "" {
			continue
		}
		if orgName != reportQuery.Org &&
			orgName != strings.ToLower(reportQuery.Org) {
			continue
		}
		if reportQuery.Reporter != "" &&
			reporterName != reportQuery.Reporter {
			continue
		}
		out = append(out, obj)
	}
	return c.JSON(http.StatusOK, out)
}

func DownloadReport(c echo.Context) error {
	// download report from cloud with given filename
	ctx := ormutil.GetContext(c)
	claims, err := getClaims(c)
	if err != nil {
		return err
	}
	reportQuery := ormapi.DownloadReport{}
	if err := c.Bind(&reportQuery); err != nil {
		return ormutil.BindErr(err)
	}
	// sanity check
	if reportQuery.Org == "" {
		return fmt.Errorf("Org name has to be specified")
	}
	if reportQuery.Filename == "" {
		return fmt.Errorf("Report filename has to be specified")
	}
	orgName, _ := ormapi.GetInfoFromReportFileName(reportQuery.Filename)
	if orgName == "" {
		return fmt.Errorf("Unable to get org name from filename: %s", reportQuery.Filename)
	}
	if orgName != reportQuery.Org &&
		orgName != strings.ToLower(reportQuery.Org) {
		return fmt.Errorf("Only org %s related reports can be accessed", reportQuery.Org)
	}
	// check if user is authorized to view reports
	if err := authorized(ctx, claims.Username, reportQuery.Org, ResourceCloudletAnalytics, ActionView); err != nil {
		return err
	}

	storageClient, err := getGCSStorageClient(ctx)
	if err != nil {
		return err
	}
	defer storageClient.Close()
	objs, err := storageClient.ListObjects(ctx)
	if err != nil {
		return fmt.Errorf("Unable to get reports from GCS: %v", err)
	}
	found := false
	for _, obj := range objs {
		if reportQuery.Filename == obj {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("Report with name %s does not exist", reportQuery.Filename)
	}
	outFilePath := "/tmp/" + strings.ReplaceAll(reportQuery.Filename, "/", "_")
	err = storageClient.DownloadObject(ctx, reportQuery.Filename, outFilePath)
	if err != nil {
		return fmt.Errorf("Unable to download report %s to %s: %v", reportQuery.Filename, outFilePath, err)
	}
	defer cloudcommon.DeleteFile(outFilePath)
	data, err := ioutil.ReadFile(outFilePath)
	if err != nil {
		return fmt.Errorf("Failed to read from downloaded report %s: %v", outFilePath, err)
	}

	return c.HTMLBlob(http.StatusOK, data)
}
