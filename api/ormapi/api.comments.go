package ormapi

// This is an auto-generated file. DO NOT EDIT directly.

var UserComments = map[string]string{
	"name":             `User name. Can only contain letters, digits, underscore, period, hyphen. It cannot have leading or trailing spaces or period. It cannot start with hyphen`,
	"email":            `User email`,
	"emailverified":    `Email address has been verified`,
	"familyname":       `Family Name`,
	"givenname":        `Given Name`,
	"picture":          `Picture (currently not used)`,
	"nickname":         `Nick Name`,
	"createdat":        `Time created`,
	"updatedat":        `Time last updated`,
	"locked":           `Account is locked`,
	"passcracktimesec": `Password strength in terms of brute-force cracking time`,
	"enabletotp":       `Enable or disable temporary one-time passwords for the account`,
	"metadata":         `Metadata`,
	"lastlogin":        `Last successful login time`,
	"lastfailedlogin":  `Last failed login time`,
	"failedlogins":     `Number of failed login attempts since last successful login`,
}

var CreateUserApiKeyComments = map[string]string{
	"userapikey.id":          `API key ID used as an identifier for API keys`,
	"userapikey.description": `Description of the purpose of this API key`,
	"userapikey.org":         `Org to which API key has permissions to access its objects`,
	"userapikey.createdat":   `Time created`,
	"apikey":                 `API key`,
	"permissions:#.role":     `Role defines a collection of permissions, which are resource-action pairs`,
	"permissions:#.resource": `Resource defines a resource to act upon`,
	"permissions:#.action":   `Action defines what type of action can be performed on a resource`,
}

var UserApiKeyComments = map[string]string{
	"id":          `API key ID used as an identifier for API keys`,
	"description": `Description of the purpose of this API key`,
	"org":         `Org to which API key has permissions to access its objects`,
	"createdat":   `Time created`,
}

var UserResponseComments = map[string]string{
	"message":       `Message`,
	"totpsharedkey": `TOTP shared key`,
	"totpqrimage":   `TOTP QR image`,
}

var OrganizationComments = map[string]string{
	"name":             `Organization name. Can only contain letters, digits, underscore, period, hyphen. It cannot have leading or trailing spaces or period. It cannot start with hyphen`,
	"type":             `Organization type: "developer" or "operator"`,
	"address":          `Organization address`,
	"phone":            `Organization phone number`,
	"createdat":        `Time created`,
	"updatedat":        `Time last updated`,
	"publicimages":     `Images are made available to other organization`,
	"deleteinprogress": `Delete of this organization is in progress`,
	"parent":           `This organization's parent organization for billing, if any`,
	"edgeboxonly":      `Edgebox only operator organization`,
}

var InvoiceRequestComments = map[string]string{
	"name":      `Billing Organization name to retrieve invoices for`,
	"startdate": `Date filter for invoice selection, YYYY-MM-DD format`,
	"enddate":   `Date filter for invoice selection, YYYY-MM-DD format`,
}

var BillingOrganizationComments = map[string]string{
	"name":             `BillingOrganization name. Can only contain letters, digits, underscore, period, hyphen. It cannot have leading or trailing spaces or period. It cannot start with hyphen`,
	"type":             `Organization type: "parent" or "self"`,
	"firstname":        `Billing info first name`,
	"lastname":         `Billing info last name`,
	"email":            `Organization email`,
	"address":          `Organization address`,
	"address2":         `Organization address2`,
	"city":             `Organization city`,
	"country":          `Organization country`,
	"state":            `Organization state`,
	"postalcode":       `Organization postal code`,
	"phone":            `Organization phone number`,
	"children":         `Children belonging to this BillingOrganization`,
	"createdat":        `Time created`,
	"updatedat":        `Time last updated`,
	"deleteinprogress": `Delete of this BillingOrganization is in progress`,
}

var AccountInfoComments = map[string]string{
	"orgname":        `Billing Organization name to commit`,
	"accountid":      `Account ID given by the billing platform`,
	"subscriptionid": `Subscription ID given by the billing platform`,
	"parentid":       `Parent ID`,
	"type":           `Type, either parent, child, or self`,
}

var PaymentProfileDeletionComments = map[string]string{
	"org": `Billing Organization Name associated with the payment profile`,
	"id":  `Payment Profile Id`,
}

var ControllerComments = map[string]string{
	"region":        `Controller region name`,
	"address":       `Controller API address or URL`,
	"notifyaddr":    `Controller notify address or URL`,
	"influxdb":      `InfluxDB address`,
	"thanosmetrics": `Thanos Query URL`,
	"dnsregion":     `Unique DNS label for the region`,
	"createdat":     `Time created`,
	"updatedat":     `Time last updated`,
}

var ConfigComments = map[string]string{
	"locknewaccounts":               `Lock new accounts (must be unlocked by admin)`,
	"notifyemailaddress":            `Email to notify when locked account is created, defaults to SupportEmail`,
	"skipverifyemail":               `Skip email verification for new accounts (testing only)`,
	"passwordmincracktimesec":       `User accounts min password crack time seconds (a measure of strength)`,
	"adminpasswordmincracktimesec":  `Admin accounts min password crack time seconds (a measure of strength)`,
	"maxmetricsdatapoints":          `InfluxDB max number of data points returned`,
	"userapikeycreatelimit":         `Max number of API keys a user can create`,
	"billingenable":                 `Toggle for enabling billing (primarily for testing purposes)`,
	"disableratelimit":              `Toggle to enable and disable MC API rate limiting`,
	"ratelimitmaxtrackedips":        `Maximum number of IPs tracked per API group for rate limiting at MC`,
	"ratelimitmaxtrackedusers":      `Maximum number of users tracked per API group for rate limiting at MC`,
	"failedloginlockoutthreshold1":  `Failed login lockout threshold 1, after this count, lockout time 1 is enabled (default 3)`,
	"failedloginlockouttimesec1":    `Number of seconds to lock account from logging in after threshold 1 is hit (default 60)`,
	"failedloginlockoutthreshold2":  `Failed login lockout threshold 2, after this count, lockout time 2 is enabled (default 10)`,
	"failedloginlockouttimesec2":    `Number of seconds to lock account from logging in after threshold 2 is hit (default 300)`,
	"userlogintokenvalidduration":   `User login token valid duration (in format 2h30m10s, default 24h)`,
	"apikeylogintokenvalidduration": `API key login token valid duration (in format 2h30m10s, default 4h)`,
	"websockettokenvalidduration":   `Websocket auth token valid duration (in format 2h30m10s, default 2m)`,
	"supportemail":                  `Support email address shown to users, i.e. support@edgecloud.net`,
	"slackiconurl":                  `Slack icon URL used for alert manager slack receivers`,
}

var McRateLimitFlowSettingsComments = map[string]string{
	"flowsettingsname": `Unique name for FlowSettings`,
	"apiname":          `Name of API Path (eg. /api/v1/usercreate)`,
	"ratelimittarget":  `RateLimitTarget (AllRequests, PerIp, or PerUser)`,
	"flowalgorithm":    `Flow Algorithm (TokenBucketAlgorithm or LeakyBucketAlgorithm)`,
	"reqspersecond":    `Number of requests per second`,
	"burstsize":        `Number of requests allowed at once`,
}

var McRateLimitMaxReqsSettingsComments = map[string]string{
	"maxreqssettingsname": `Unique name for MaxReqsSettings`,
	"apiname":             `Name of API Path (eg. /api/v1/usercreate)`,
	"ratelimittarget":     `RateLimitTarget (AllRequests, PerIp, or PerUser)`,
	"maxreqsalgorithm":    `MaxReqs Algorithm (FixedWindowAlgorithm)`,
	"maxrequests":         `Maximum number of requests for the specified interval`,
	"interval":            `Time interval`,
}

var McRateLimitSettingsComments = map[string]string{
	"apiname":         `Name of API Path (eg. /api/v1/usercreate)`,
	"ratelimittarget": `RateLimitTarget (AllRequests, PerIp, or PerUser)`,
	"flowsettings":    `Map of Flow Settings name to FlowSettings`,
	"maxreqssettings": `Map of MaxReqs Settings name to MaxReqsSettings`,
}

var OrgCloudletPoolComments = map[string]string{
	"org":             `Developer Organization`,
	"region":          `Region`,
	"cloudletpool":    `Operator's CloudletPool name`,
	"cloudletpoolorg": `Operator's Organization`,
	"type":            `Type is an internal-only field which is either invitation or response`,
	"decision":        `Decision is to either accept or reject an invitation`,
}

var RolePermComments = map[string]string{
	"role":     `Role defines a collection of permissions, which are resource-action pairs`,
	"resource": `Resource defines a resource to act upon`,
	"action":   `Action defines what type of action can be performed on a resource`,
}

var RoleComments = map[string]string{
	"org":      `Organization name`,
	"username": `User name`,
	"role":     `Role which defines the set of permissions`,
}

var OrgCloudletComments = map[string]string{
	"region": `Region name`,
	"org":    `Org that has permissions for cloudlets`,
}

var ShowUserComments = map[string]string{
	"user.name":             `User name. Can only contain letters, digits, underscore, period, hyphen. It cannot have leading or trailing spaces or period. It cannot start with hyphen`,
	"user.email":            `User email`,
	"user.emailverified":    `Email address has been verified`,
	"user.familyname":       `Family Name`,
	"user.givenname":        `Given Name`,
	"user.picture":          `Picture (currently not used)`,
	"user.nickname":         `Nick Name`,
	"user.createdat":        `Time created`,
	"user.updatedat":        `Time last updated`,
	"user.locked":           `Account is locked`,
	"user.passcracktimesec": `Password strength in terms of brute-force cracking time`,
	"user.enabletotp":       `Enable or disable temporary one-time passwords for the account`,
	"user.metadata":         `Metadata`,
	"user.lastlogin":        `Last successful login time`,
	"user.lastfailedlogin":  `Last failed login time`,
	"user.failedlogins":     `Number of failed login attempts since last successful login`,
	"org":                   `Organization name`,
	"role":                  `Role name`,
}

var UserLoginComments = map[string]string{
	"username": `User's name or email address`,
	"password": `User's password`,
	"totp":     `Temporary one-time password if 2-factor authentication is enabled`,
	"apikeyid": `API key ID if logging in using API key`,
	"apikey":   `API key if logging in using API key`,
}

var NewPasswordComments = map[string]string{
	"currentpassword": `User's current password`,
	"password":        `User's new password`,
}

var CreateUserComments = map[string]string{
	"user.name":             `User name. Can only contain letters, digits, underscore, period, hyphen. It cannot have leading or trailing spaces or period. It cannot start with hyphen`,
	"user.email":            `User email`,
	"user.emailverified":    `Email address has been verified`,
	"user.familyname":       `Family Name`,
	"user.givenname":        `Given Name`,
	"user.picture":          `Picture (currently not used)`,
	"user.nickname":         `Nick Name`,
	"user.createdat":        `Time created`,
	"user.updatedat":        `Time last updated`,
	"user.locked":           `Account is locked`,
	"user.passcracktimesec": `Password strength in terms of brute-force cracking time`,
	"user.enabletotp":       `Enable or disable temporary one-time passwords for the account`,
	"user.metadata":         `Metadata`,
	"user.lastlogin":        `Last successful login time`,
	"user.lastfailedlogin":  `Last failed login time`,
	"user.failedlogins":     `Number of failed login attempts since last successful login`,
	"verify.email":          `User's email address`,
}

var EmailRequestComments = map[string]string{
	"email": `User's email address`,
}

var PasswordResetComments = map[string]string{
	"token":    `Authentication token`,
	"password": `User's new password`,
}

var TokenComments = map[string]string{
	"token": `Authentication token`,
}

var ResultComments = map[string]string{
	"message": `Informational message`,
	"code":    `Error code`,
}

var VersionComments = map[string]string{
	"buildmaster": `Master build version`,
	"buildhead":   `Head build version`,
	"buildauthor": `Build author`,
	"hostname":    `Hostname that performed build`,
}

var StreamPayloadComments = map[string]string{
	"result.message": `Informational message`,
	"result.code":    `Error code`,
}

var AllDataComments = map[string]string{
	"controllers:#.region":                            `Controller region name`,
	"controllers:#.address":                           `Controller API address or URL`,
	"controllers:#.notifyaddr":                        `Controller notify address or URL`,
	"controllers:#.influxdb":                          `InfluxDB address`,
	"controllers:#.thanosmetrics":                     `Thanos Query URL`,
	"controllers:#.dnsregion":                         `Unique DNS label for the region`,
	"controllers:#.createdat":                         `Time created`,
	"controllers:#.updatedat":                         `Time last updated`,
	"billingorgs:#.name":                              `BillingOrganization name. Can only contain letters, digits, underscore, period, hyphen. It cannot have leading or trailing spaces or period. It cannot start with hyphen`,
	"billingorgs:#.type":                              `Organization type: "parent" or "self"`,
	"billingorgs:#.firstname":                         `Billing info first name`,
	"billingorgs:#.lastname":                          `Billing info last name`,
	"billingorgs:#.email":                             `Organization email`,
	"billingorgs:#.address":                           `Organization address`,
	"billingorgs:#.address2":                          `Organization address2`,
	"billingorgs:#.city":                              `Organization city`,
	"billingorgs:#.country":                           `Organization country`,
	"billingorgs:#.state":                             `Organization state`,
	"billingorgs:#.postalcode":                        `Organization postal code`,
	"billingorgs:#.phone":                             `Organization phone number`,
	"billingorgs:#.children":                          `Children belonging to this BillingOrganization`,
	"billingorgs:#.createdat":                         `Time created`,
	"billingorgs:#.updatedat":                         `Time last updated`,
	"billingorgs:#.deleteinprogress":                  `Delete of this BillingOrganization is in progress`,
	"alertreceivers:#.name":                           `Receiver Name`,
	"alertreceivers:#.type":                           `Receiver type. Eg. email, slack, pagerduty`,
	"alertreceivers:#.severity":                       `Alert severity filter`,
	"alertreceivers:#.region":                         `Region for the alert receiver`,
	"alertreceivers:#.user":                           `User that created this receiver`,
	"alertreceivers:#.email":                          `Custom receiving email`,
	"alertreceivers:#.slackchannel":                   `Custom slack channel`,
	"alertreceivers:#.slackwebhook":                   `Custom slack webhook`,
	"alertreceivers:#.pagerdutyintegrationkey":        `PagerDuty integration key`,
	"alertreceivers:#.pagerdutyapiversion":            `PagerDuty API version`,
	"alertreceivers:#.cloudlet":                       `Cloudlet spec for alerts`,
	"alertreceivers:#.appinst":                        `AppInst spec for alerts`,
	"orgs:#.name":                                     `Organization name. Can only contain letters, digits, underscore, period, hyphen. It cannot have leading or trailing spaces or period. It cannot start with hyphen`,
	"orgs:#.type":                                     `Organization type: "developer" or "operator"`,
	"orgs:#.address":                                  `Organization address`,
	"orgs:#.phone":                                    `Organization phone number`,
	"orgs:#.createdat":                                `Time created`,
	"orgs:#.updatedat":                                `Time last updated`,
	"orgs:#.publicimages":                             `Images are made available to other organization`,
	"orgs:#.deleteinprogress":                         `Delete of this organization is in progress`,
	"orgs:#.parent":                                   `This organization's parent organization for billing, if any`,
	"orgs:#.edgeboxonly":                              `Edgebox only operator organization`,
	"roles:#.org":                                     `Organization name`,
	"roles:#.username":                                `User name`,
	"roles:#.role":                                    `Role which defines the set of permissions`,
	"cloudletpoolaccessinvitations:#.org":             `Developer Organization`,
	"cloudletpoolaccessinvitations:#.region":          `Region`,
	"cloudletpoolaccessinvitations:#.cloudletpool":    `Operator's CloudletPool name`,
	"cloudletpoolaccessinvitations:#.cloudletpoolorg": `Operator's Organization`,
	"cloudletpoolaccessinvitations:#.type":            `Type is an internal-only field which is either invitation or response`,
	"cloudletpoolaccessinvitations:#.decision":        `Decision is to either accept or reject an invitation`,
	"cloudletpoolaccessresponses:#.org":               `Developer Organization`,
	"cloudletpoolaccessresponses:#.region":            `Region`,
	"cloudletpoolaccessresponses:#.cloudletpool":      `Operator's CloudletPool name`,
	"cloudletpoolaccessresponses:#.cloudletpoolorg":   `Operator's Organization`,
	"cloudletpoolaccessresponses:#.type":              `Type is an internal-only field which is either invitation or response`,
	"cloudletpoolaccessresponses:#.decision":          `Decision is to either accept or reject an invitation`,
	"regiondata:#.region":                             `Region name`,
}

var RegionDataComments = map[string]string{
	"region": `Region name`,
}

var MetricsCommonComments = map[string]string{
	"numsamples": `Display X samples spaced out evenly over start and end times`,
	"limit":      `Display the last X metrics`,
}

var AllMetricsComments = map[string]string{
	"data:#.series:#.columns": `Column names`,
	"data:#.series:#.name":    `Series name`,
	"data:#.series:#.tags":    `Tags, value is key=value format`,
	"data:#.series:#.values":  `2D Array of column values by time`,
}

var MetricDataComments = map[string]string{
	"series:#.columns": `Column names`,
	"series:#.name":    `Series name`,
	"series:#.tags":    `Tags, value is key=value format`,
	"series:#.values":  `2D Array of column values by time`,
}

var MetricSeriesComments = map[string]string{
	"columns": `Column names`,
	"name":    `Series name`,
	"tags":    `Tags, value is key=value format`,
	"values":  `2D Array of column values by time`,
}

var RegionAppInstMetricsComments = map[string]string{
	"metricscommon.numsamples": `Display X samples spaced out evenly over start and end times`,
	"metricscommon.limit":      `Display the last X metrics`,
	"region":                   `Region name`,
	"selector":                 `Comma separated list of metrics to view. Available metrics: utilization, network, ipusage`,
	"appinst":                  `Application instance to filter for metrics`,
	"appinsts":                 `Application instances to filter for metrics`,
}

var RegionCustomAppMetricsComments = map[string]string{
	"metricscommon.numsamples": `Display X samples spaced out evenly over start and end times`,
	"metricscommon.limit":      `Display the last X metrics`,
	"region":                   `Region name`,
	"measurement":              `Pre-built queries, one of: connections`,
	"appinst":                  `Application instance to filter for metrics`,
	"port":                     `Port on AppInst (optional)`,
	"aggrfunction":             `Aggregation function (optional)`,
}

var RegionClusterInstMetricsComments = map[string]string{
	"metricscommon.numsamples": `Display X samples spaced out evenly over start and end times`,
	"metricscommon.limit":      `Display the last X metrics`,
	"region":                   `Region name`,
	"clusterinst":              `Cluster instance key for metrics`,
	"clusterinsts":             `Cluster instance keys for metrics`,
	"selector":                 `Comma separated list of metrics to view. Available metrics: utilization, network, ipusage`,
}

var RegionCloudletMetricsComments = map[string]string{
	"metricscommon.numsamples": `Display X samples spaced out evenly over start and end times`,
	"metricscommon.limit":      `Display the last X metrics`,
	"region":                   `Region name`,
	"cloudlet":                 `Cloudlet key for metrics`,
	"cloudlets":                `Cloudlet keys for metrics`,
	"selector":                 `Comma separated list of metrics to view. Available metrics: utilization, network, ipusage`,
}

var RegionClientApiUsageMetricsComments = map[string]string{
	"metricscommon.numsamples": `Display X samples spaced out evenly over start and end times`,
	"metricscommon.limit":      `Display the last X metrics`,
	"region":                   `Region name`,
	"appinst":                  `Application instance key for usage`,
	"method":                   `API call method, one of: FindCloudlet, PlatformFindCloudlet, RegisterClient, VerifyLocation`,
	"dmecloudlet":              `Cloudlet name where DME is running`,
	"dmecloudletorg":           `Operator organization where DME is running`,
	"selector":                 `Comma separated list of metrics to view. Available metrics: utilization, network, ipusage`,
}

var RegionClientAppUsageMetricsComments = map[string]string{
	"metricscommon.numsamples": `Display X samples spaced out evenly over start and end times`,
	"metricscommon.limit":      `Display the last X metrics`,
	"region":                   `Region name`,
	"appinst":                  `Application instance key for usage`,
	"selector":                 `Comma separated list of metrics to view. Available metrics: utilization, network, ipusage`,
	"devicecarrier":            `Device carrier. Can be used for selectors: latency, deviceinfo`,
	"datanetworktype":          `Data network type used by client device. Can be used for selectors: latency`,
	"devicemodel":              `Device model. Can be used for selectors: deviceinfo`,
	"deviceos":                 `Device operating system. Can be used for selectors: deviceinfo`,
	"signalstrength":           `Signal strength`,
	"locationtile":             `Provides the range of GPS coordinates for the location tile/square. Format is: 'LocationUnderLongitude,LocationUnderLatitude_LocationOverLongitude,LocationOverLatitude_LocationTileLength'. LocationUnder are the GPS coordinates of the corner closest to (0,0) of the location tile. LocationOver are the GPS coordinates of the corner farthest from (0,0) of the location tile. LocationTileLength is the length (in kilometers) of one side of the location tile square`,
}

var RegionClientCloudletUsageMetricsComments = map[string]string{
	"metricscommon.numsamples": `Display X samples spaced out evenly over start and end times`,
	"metricscommon.limit":      `Display the last X metrics`,
	"region":                   `Region name`,
	"cloudlet":                 `Cloudlet key for metrics`,
	"selector":                 `Comma separated list of metrics to view. Available metrics: utilization, network, ipusage`,
	"devicecarrier":            `Device carrier. Can be used for selectors: latency, deviceinfo`,
	"datanetworktype":          `Data network type used by client device. Can be used for selectors: latency`,
	"devicemodel":              `Device model. Can be used for selectors: deviceinfo`,
	"deviceos":                 `Device operating system. Can be used for selectors: deviceinfo`,
	"signalstrength":           `Signal strength`,
	"locationtile":             `Provides the range of GPS coordinates for the location tile/square. Format is: 'LocationUnderLongitude,LocationUnderLatitude_LocationOverLongitude,LocationOverLatitude_LocationTileLength'. LocationUnder are the GPS coordinates of the corner closest to (0,0) of the location tile. LocationOver are the GPS coordinates of the corner farthest from (0,0) of the location tile. LocationTileLength is the length (in kilometers) of one side of the location tile square`,
}

var RegionAppInstEventsComments = map[string]string{
	"metricscommon.numsamples": `Display X samples spaced out evenly over start and end times`,
	"metricscommon.limit":      `Display the last X metrics`,
	"region":                   `Region name`,
	"appinst":                  `Application instance key for events`,
}

var RegionClusterInstEventsComments = map[string]string{
	"metricscommon.numsamples": `Display X samples spaced out evenly over start and end times`,
	"metricscommon.limit":      `Display the last X metrics`,
	"region":                   `Region name`,
	"clusterinst":              `Cluster instance key for events`,
}

var RegionCloudletEventsComments = map[string]string{
	"metricscommon.numsamples": `Display X samples spaced out evenly over start and end times`,
	"metricscommon.limit":      `Display the last X metrics`,
	"region":                   `Region name`,
	"cloudlet":                 `Cloudlet key for events`,
}

var RegionAppInstUsageComments = map[string]string{
	"region":    `Region name`,
	"appinst":   `Application instance key for usage`,
	"starttime": `Time to start displaying stats from`,
	"endtime":   `Time up to which to display stats`,
	"vmonly":    `Show only VM-based apps`,
}

var RegionClusterInstUsageComments = map[string]string{
	"region":      `Region name`,
	"clusterinst": `Cluster instances key for usage`,
	"starttime":   `Time to start displaying stats from`,
	"endtime":     `Time up to which to display stats`,
}

var RegionCloudletPoolUsageComments = map[string]string{
	"region":         `Region name`,
	"cloudletpool":   `Cloudlet pool key for usage`,
	"starttime":      `Time to start displaying stats from`,
	"endtime":        `Time up to which to display stats`,
	"showvmappsonly": `Show only VM-based apps`,
}

var RegionCloudletPoolUsageRegisterComments = map[string]string{
	"region": `Region name`,
}

var AlertReceiverComments = map[string]string{
	"name":                    `Receiver Name`,
	"type":                    `Receiver type. Eg. email, slack, pagerduty`,
	"severity":                `Alert severity filter`,
	"region":                  `Region for the alert receiver`,
	"user":                    `User that created this receiver`,
	"email":                   `Custom receiving email`,
	"slackchannel":            `Custom slack channel`,
	"slackwebhook":            `Custom slack webhook`,
	"pagerdutyintegrationkey": `PagerDuty integration key`,
	"pagerdutyapiversion":     `PagerDuty API version`,
	"cloudlet":                `Cloudlet spec for alerts`,
	"appinst":                 `AppInst spec for alerts`,
}

var ReporterComments = map[string]string{
	"name":              `Reporter name. Can only contain letters, digits, period, hyphen. It cannot have leading or trailing spaces or period. It cannot start with hyphen`,
	"org":               `Organization name`,
	"email":             `Email to send generated reports`,
	"schedule":          `Indicates how often a report should be generated, one of EveryWeek, Every15Days, EveryMonth`,
	"startscheduledate": `Start date (in RFC3339 format with intended timezone) when the report is scheduled to be generated (Default: today)`,
	"nextscheduledate":  `Date when the next report is scheduled to be generated (for internal use only)`,
	"username":          `User name (for internal use only)`,
	"timezone":          `Timezone in which to show the reports, defaults to UTC`,
	"status":            `Last report status`,
}

var DownloadReportComments = map[string]string{
	"org":      `Organization name`,
	"reporter": `Reporter name`,
	"filename": `Name of the report file to be downloaded`,
}

var GenerateReportComments = map[string]string{
	"org":       `Organization name`,
	"starttime": `Absolute time (in RFC3339 format with intended timezone) to start report capture`,
	"endtime":   `Absolute time (in RFC3339 format with intended timezone) to end report capture`,
	"region":    `Region name (for internal use only)`,
	"timezone":  `Timezone in which to show the reports, defaults to UTC`,
}

var FederatorComments = map[string]string{
	"federationid":    `Globally unique string used to indentify a federation with partner federation`,
	"operatorid":      `Globally unique string to identify an operator platform`,
	"countrycode":     `ISO 3166-1 Alpha-2 code for the country where operator platform is located`,
	"federationaddr":  `Federation access point address`,
	"region":          `Region to which this federator is associated with`,
	"mcc":             `Mobile country code of operator sending the request`,
	"mnc":             `List of mobile network codes of operator sending the request`,
	"locatorendpoint": `IP and Port of discovery service URL of operator platform`,
	"revision":        `Revision ID to track object changes. We use jaeger traceID for easy debugging but this can differ with what partner federator uses`,
	"apikey":          `API Key used for authentication (stored in secure storage)`,
}

var FederationComments = map[string]string{
	"federator.federationid":        `Globally unique string used to indentify a federation with partner federation`,
	"federator.operatorid":          `Globally unique string to identify an operator platform`,
	"federator.countrycode":         `ISO 3166-1 Alpha-2 code for the country where operator platform is located`,
	"federator.federationaddr":      `Federation access point address`,
	"federator.region":              `Region to which this federator is associated with`,
	"federator.mcc":                 `Mobile country code of operator sending the request`,
	"federator.mnc":                 `List of mobile network codes of operator sending the request`,
	"federator.locatorendpoint":     `IP and Port of discovery service URL of operator platform`,
	"federator.revision":            `Revision ID to track object changes. We use jaeger traceID for easy debugging but this can differ with what partner federator uses`,
	"federator.apikey":              `API Key used for authentication (stored in secure storage)`,
	"name":                          `Name to uniquely identify a federation`,
	"selffederationid":              `Self federation ID`,
	"selfoperatorid":                `Self operator ID`,
	"partnerrolesharezoneswithself": `Partner shares its zones with self federator as part of federation`,
	"partnerroleaccesstoselfzones":  `Partner is allowed access to self federator zones as part of federation`,
}

var FederatorZoneComments = map[string]string{
	"zoneid":      `Globally unique string used to authenticate operations over federation interface`,
	"operatorid":  `Globally unique string to identify an operator platform`,
	"countrycode": `ISO 3166-1 Alpha-2 code for the country where operator platform is located`,
	"geolocation": `GPS co-ordinates associated with the zone (in decimal format)`,
	"city":        `Comma seperated list of cities under this zone`,
	"state":       `Comma seperated list of states under this zone`,
	"locality":    `Type of locality eg rural, urban etc.`,
	"region":      `Region in which cloudlets reside`,
	"cloudlets":   `List of cloudlets part of this zone`,
	"revision":    `Revision ID to track object changes. We use jaeger traceID for easy debugging but this can differ with what partner federator uses`,
}

var FederatedSelfZoneComments = map[string]string{
	"zoneid":         `Globally unique identifier of the federator zone`,
	"selfoperatorid": `Self operator ID`,
	"federationname": `Name of the Federation`,
	"registered":     `Zone registered by partner federator`,
	"revision":       `Revision ID to track object changes. We use jaeger traceID for easy debugging but this can differ with what partner federator uses`,
}

var FederatedPartnerZoneComments = map[string]string{
	"federatorzone.zoneid":      `Globally unique string used to authenticate operations over federation interface`,
	"federatorzone.operatorid":  `Globally unique string to identify an operator platform`,
	"federatorzone.countrycode": `ISO 3166-1 Alpha-2 code for the country where operator platform is located`,
	"federatorzone.geolocation": `GPS co-ordinates associated with the zone (in decimal format)`,
	"federatorzone.city":        `Comma seperated list of cities under this zone`,
	"federatorzone.state":       `Comma seperated list of states under this zone`,
	"federatorzone.locality":    `Type of locality eg rural, urban etc.`,
	"federatorzone.region":      `Region in which cloudlets reside`,
	"federatorzone.cloudlets":   `List of cloudlets part of this zone`,
	"federatorzone.revision":    `Revision ID to track object changes. We use jaeger traceID for easy debugging but this can differ with what partner federator uses`,
	"selfoperatorid":            `Self operator ID`,
	"federationname":            `Name of the Federation`,
	"registered":                `Zone registered by self federator`,
}

var FederatedZoneRegRequestComments = map[string]string{
	"selfoperatorid": `Self operator ID`,
	"federationname": `Name of the Federation`,
	"zones":          `Partner federator zones to be registered/deregistered`,
}
