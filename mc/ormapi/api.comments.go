package ormapi

var UserComments = map[string]string{
	"name":       `User name. Can only contain letters, digits, underscore, period, hyphen. It cannot have leading or trailing spaces or period. It cannot start with hyphen`,
	"email":      `User email`,
	"familyname": `Family Name`,
	"givenname":  `Given Name`,
	"nickname":   `Nick Name`,
	"enabletotp": `Enable or disable temporary one-time passwords for the account`,
	"metadata":   `Metadata`,
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
	"name":    `Organization name. Can only contain letters, digits, underscore, period, hyphen. It cannot have leading or trailing spaces or period. It cannot start with hyphen`,
	"type":    `Organization type: "developer" or "operator"`,
	"address": `Organization address`,
	"phone":   `Organization phone number`,
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
}

var OrgCloudletPoolComments = map[string]string{
	"org":             `Developer Organization`,
	"region":          `Region`,
	"cloudletpool":    `Operator's CloudletPool name`,
	"cloudletpoolorg": `Operator's Organization`,
	"type":            `Type is an internal-only field which is either invitation or confirmation`,
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
	"user.name":       `User name. Can only contain letters, digits, underscore, period, hyphen. It cannot have leading or trailing spaces or period. It cannot start with hyphen`,
	"user.email":      `User email`,
	"user.familyname": `Family Name`,
	"user.givenname":  `Given Name`,
	"user.nickname":   `Nick Name`,
	"user.enabletotp": `Enable or disable temporary one-time passwords for the account`,
	"user.metadata":   `Metadata`,
}

var UserLoginComments = map[string]string{
	"username": `User's name or email address`,
	"password": `User's password`,
}

var CreateUserComments = map[string]string{
	"user.name":       `User name. Can only contain letters, digits, underscore, period, hyphen. It cannot have leading or trailing spaces or period. It cannot start with hyphen`,
	"user.email":      `User email`,
	"user.familyname": `Family Name`,
	"user.givenname":  `Given Name`,
	"user.nickname":   `Nick Name`,
	"user.enabletotp": `Enable or disable temporary one-time passwords for the account`,
	"user.metadata":   `Metadata`,
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
