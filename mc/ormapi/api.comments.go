package ormapi

// This is an auto-generated file. DO NOT EDIT directly.

var UserComments = map[string]string{
	"name":          `User name. Can only contain letters, digits, underscore, period, hyphen. It cannot have leading or trailing spaces or period. It cannot start with hyphen`,
	"email":         `User email`,
	"emailverified": `Email address has been verified`,
	"familyname":    `Family Name`,
	"givenname":     `Given Name`,
	"nickname":      `Nick Name`,
	"locked":        `Account is locked`,
	"enabletotp":    `Enable or disable temporary one-time passwords for the account`,
	"metadata":      `Metadata`,
}

var CreateUserApiKeyComments = map[string]string{
	"userapikey.id":          `API key ID used as an identifier for API keys`,
	"userapikey.description": `Description of the purpose of this API key`,
	"userapikey.org":         `Org to which API key has permissions to access its objects`,
	"apikey":                 `API key`,
	"permissions:#.role":     `Role defines a collection of permissions, which are resource-action pairs`,
	"permissions:#.resource": `Resource defines a resource to act upon`,
	"permissions:#.action":   `Action defines what type of action can be performed on a resource`,
}

var UserApiKeyComments = map[string]string{
	"id":          `API key ID used as an identifier for API keys`,
	"description": `Description of the purpose of this API key`,
	"org":         `Org to which API key has permissions to access its objects`,
}

var OrganizationComments = map[string]string{
	"name":             `Organization name. Can only contain letters, digits, underscore, period, hyphen. It cannot have leading or trailing spaces or period. It cannot start with hyphen`,
	"type":             `Organization type: "developer" or "operator"`,
	"address":          `Organization address`,
	"phone":            `Organization phone number`,
	"publicimages":     `Images are made available to other organization`,
	"deleteinprogress": `Delete of this organization is in progress`,
	"edgeboxonly":      `Edgebox only operator organization`,
}

var InvoiceRequestComments = map[string]string{
	"name":      `Billing Organization name to retrieve invoices for`,
	"startdate": `Date filter for invoice selection, YYYY-MM-DD format`,
	"enddate":   `Date filter for invoice selection, YYYY-MM-DD format`,
}

var BillingOrganizationComments = map[string]string{
	"name":       `BillingOrganization name. Can only contain letters, digits, underscore, period, hyphen. It cannot have leading or trailing spaces or period. It cannot start with hyphen`,
	"type":       `Organization type: "parent" or "self"`,
	"firstname":  `Billing info first name`,
	"lastname":   `Billing info last name`,
	"email":      `Organization email`,
	"address":    `Organization address`,
	"address2":   `Organization address2`,
	"city":       `Organization city`,
	"country":    `Organization country`,
	"state":      `Organization state`,
	"postalcode": `Organization postal code`,
	"phone":      `Organization phone number`,
	"children":   `Children belonging to this BillingOrganization`,
}

var AccountInfoComments = map[string]string{
	"orgname":        `Billing Organization name to commit`,
	"accountid":      `Account ID given by the billing platform`,
	"subscriptionid": `Subscription ID given by the billing platform`,
}

var PaymentProfileDeletionComments = map[string]string{
	"org": `Billing Organization Name associated with the payment profile`,
	"id":  `Payment Profile Id`,
}

var ControllerComments = map[string]string{
	"region":     `Controller region name`,
	"address":    `Controller API address or URL`,
	"notifyaddr": `Controller notify address or URL`,
	"influxdb":   `InfluxDB address`,
}

var ConfigComments = map[string]string{
	"locknewaccounts":              `Lock new accounts (must be unlocked by admin)`,
	"notifyemailaddress":           `Email to notify when locked account is created`,
	"skipverifyemail":              `Skip email verification for new accounts (testing only)`,
	"passwordmincracktimesec":      `User accounts min password crack time seconds (a measure of strength)`,
	"adminpasswordmincracktimesec": `Admin accounts min password crack time seconds (a measure of strength)`,
	"maxmetricsdatapoints":         `InfluxDB max number of data points returned`,
	"userapikeycreatelimit":        `Max number of API keys a user can create`,
	"billingenable":                `Toggle for enabling billing (primarily for testing purposes)`,
	"disableratelimit":             `Toggle to enable and disable MC API rate limiting`,
	"ratelimitmaxtrackedips":       `Maximum number of IPs tracked per API group for rate limiting at MC`,
	"ratelimitmaxtrackedusers":     `Maximum number of users tracked per API group for rate limiting at MC`,
}

var McRateLimitFlowSettingsComments = map[string]string{
	"flowsettingsname": `Unique name for FlowSettings`,
	"apiname":          `Name of API Path (eg. /api/v1/usercreate)`,
	"reqspersecond":    `Number of requests per second`,
	"burstsize":        `Number of requests allowed at once`,
}

var McRateLimitMaxReqsSettingsComments = map[string]string{
	"maxreqssettingsname": `Unique name for MaxReqsSettings`,
	"apiname":             `Name of API Path (eg. /api/v1/usercreate)`,
	"maxrequests":         `Maximum number of requests for the specified interval`,
}

var McRateLimitSettingsComments = map[string]string{
	"apiname": `Name of API Path (eg. /api/v1/usercreate)`,
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

var ShowUserComments = map[string]string{
	"user.name":          `User name. Can only contain letters, digits, underscore, period, hyphen. It cannot have leading or trailing spaces or period. It cannot start with hyphen`,
	"user.email":         `User email`,
	"user.emailverified": `Email address has been verified`,
	"user.familyname":    `Family Name`,
	"user.givenname":     `Given Name`,
	"user.nickname":      `Nick Name`,
	"user.locked":        `Account is locked`,
	"user.enabletotp":    `Enable or disable temporary one-time passwords for the account`,
	"user.metadata":      `Metadata`,
	"org":                `Organization name`,
	"role":               `Role name`,
}

var UserLoginComments = map[string]string{
	"username": `User's name or email address`,
	"password": `User's password`,
}

var CreateUserComments = map[string]string{
	"user.name":          `User name. Can only contain letters, digits, underscore, period, hyphen. It cannot have leading or trailing spaces or period. It cannot start with hyphen`,
	"user.email":         `User email`,
	"user.emailverified": `Email address has been verified`,
	"user.familyname":    `Family Name`,
	"user.givenname":     `Given Name`,
	"user.nickname":      `Nick Name`,
	"user.locked":        `Account is locked`,
	"user.enabletotp":    `Enable or disable temporary one-time passwords for the account`,
	"user.metadata":      `Metadata`,
}

var EmailRequestComments = map[string]string{
	"callbackurl": `Callback URL to verify user email`,
}

var PasswordResetComments = map[string]string{
	"token":    `Authentication token`,
	"password": `User's new password`,
}

var TokenComments = map[string]string{
	"token": `Authentication token`,
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
	"operatorid":      `Globally unique string to identify an operator platform`,
	"countrycode":     `ISO 3166-1 Alpha-2 code for the country where operator platform is located`,
	"federationkey":   `Globally unique string used to authenticate operations over federation interface`,
	"federationaddr":  `Federation access point address`,
	"mcc":             `Mobile country code of operator sending the request`,
	"locatorendpoint": `IP and Port of discovery service URL of operator platform`,
}

var FederationComments = map[string]string{
	"federator.operatorid":          `Globally unique string to identify an operator platform`,
	"federator.countrycode":         `ISO 3166-1 Alpha-2 code for the country where operator platform is located`,
	"federator.federationkey":       `Globally unique string used to authenticate operations over federation interface`,
	"federator.federationaddr":      `Federation access point address`,
	"federator.mcc":                 `Mobile country code of operator sending the request`,
	"federator.locatorendpoint":     `IP and Port of discovery service URL of operator platform`,
	"id":                            `Internal ID to reference a federation read_only: true`,
	"selfoperatorid":                `Self federator operator ID`,
	"selfcountrycode":               `Self federator country code`,
	"partnerrolesharezoneswithself": `Partner shares its zones with self federator as part of federation read_only: true`,
	"partnerroleaccesstoselfzones":  `Partner is allowed access to self federator zones as part of federation read_only: true`,
}

var FederatorZoneComments = map[string]string{
	"operatorid":  `Globally unique string to identify an operator platform`,
	"countrycode": `ISO 3166-1 Alpha-2 code for the country where operator platform is located`,
	"zoneid":      `Globally unique string used to authenticate operations over federation interface`,
	"geolocation": `GPS co-ordinates associated with the zone (in decimal format)`,
	"city":        `Comma seperated list of cities under this zone`,
	"state":       `Comma seperated list of states under this zone`,
	"locality":    `Type of locality eg rural, urban etc.`,
	"region":      `Region in which cloudlets reside`,
}

var FederatedSelfZoneComments = map[string]string{
	"zoneid":             `Globally unique identifier of the federator zone`,
	"selfoperatorid":     `Self federator operator ID`,
	"selfcountrycode":    `Self federator country code`,
	"partneroperatorid":  `Partner federator operator ID`,
	"partnercountrycode": `Partner federator country code`,
	"registered":         `Zone registered by partner federator read_only: true`,
}

var FederatedPartnerZoneComments = map[string]string{
	"federatorzone.operatorid":  `Globally unique string to identify an operator platform`,
	"federatorzone.countrycode": `ISO 3166-1 Alpha-2 code for the country where operator platform is located`,
	"federatorzone.zoneid":      `Globally unique string used to authenticate operations over federation interface`,
	"federatorzone.geolocation": `GPS co-ordinates associated with the zone (in decimal format)`,
	"federatorzone.city":        `Comma seperated list of cities under this zone`,
	"federatorzone.state":       `Comma seperated list of states under this zone`,
	"federatorzone.locality":    `Type of locality eg rural, urban etc.`,
	"federatorzone.region":      `Region in which cloudlets reside`,
	"selfoperatorid":            `Self federator operator ID`,
	"selfcountrycode":           `Self federator country code`,
	"registered":                `Zone registered by self federator read_only: true`,
}
