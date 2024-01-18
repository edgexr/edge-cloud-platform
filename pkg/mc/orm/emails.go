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
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"mime/multipart"
	"net/smtp"
	"strings"
	"text/template"
	"time"

	"github.com/edgexr/edge-cloud-platform/api/ormapi"
	"github.com/edgexr/edge-cloud-platform/pkg/cloudcommon"
	"github.com/edgexr/edge-cloud-platform/pkg/echoutil"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/edgexr/edge-cloud-platform/pkg/util"
	jwt "github.com/golang-jwt/jwt/v4"
	"github.com/labstack/echo/v4"
)

// These are email templates. Eventually these should be pulled
// from a registry or perhaps the UI should provide them along
// with the associated API.

var passwordResetTmpl *template.Template
var passwordResetNoneTmpl *template.Template
var notifyTmpl *template.Template
var welcomeTmpl *template.Template
var addedTmpl *template.Template
var otpTmpl *template.Template
var operatorReportTmpl *template.Template

func init() {
	passwordResetTmpl = template.Must(template.New("pwdreset").Parse(passwordResetT))
	passwordResetNoneTmpl = template.Must(template.New("pwdresetnone").Parse(passwordResetNoneT))
	notifyTmpl = template.Must(template.New("notify").Parse(notifyT))
	welcomeTmpl = template.Must(template.New("welcome").Parse(welcomeT))
	addedTmpl = template.Must(template.New("added").Parse(addedT))
	otpTmpl = template.Must(template.New("otp").Parse(otpT))
	operatorReportTmpl = template.Must(template.New("operatorreport").Parse(operatorReportT))
}

type emailTmplArg struct {
	From    string
	To      string // used if not sending to account's email
	Subject string
	Name    string
	Email   string
	Token   string
	URL     string
	OS      string
	Browser string
	IP      string
	MCAddr  string
	Support string
}

// Use global variable to store func so that for unit-testing we
// can mock the sendEmail functionality. Look at MockSendMail obj
var sendMailFunc = sendEmail

type MockSendMail struct {
	From    *cloudcommon.EmailAccount
	To      string
	Message string
}

func (m *MockSendMail) Start() {
	sendMailFunc = m.SendEmail
}

func (m *MockSendMail) Stop() {
	sendMailFunc = sendEmail
}

func (m *MockSendMail) Reset() {
	m.From = nil
	m.To = ""
	m.Message = ""
}

func (m *MockSendMail) SendEmail(from *cloudcommon.EmailAccount, to string, contents *bytes.Buffer) error {
	m.From = from
	m.To = to
	m.Message = string(contents.Bytes())
	return nil
}

var passwordResetT = `From: {{.From}}
To: {{.Email}}
Subject: Password Reset Request

Hi {{.Name}},

You recently requested to reset your password for your Edge Cloud account. Use the link below to reset it. This password reset is only valid for the next 1 hour.

{{ if .URL}}
Reset your password: {{.URL}}
{{- else}}
Copy and paste to set your password:

{{ if .MCAddr}}
mcctl --addr {{.MCAddr}} user passwordreset token={{.Token}}
{{- else}}
mcctl user passwordreset token={{.Token}}
{{- end}}
{{- end}}

For security, this request was received from a {{.OS}} device using {{.Browser}} with IP {{.IP}}. If you did not request this password reset, please ignore this email or contact {{.Support}} for assistance.

Thanks!
Edge Cloud Team
`

var passwordResetNoneT = `From: {{.From}}
To: {{.Email}}
Subject: Password Reset Request

Hi,

A password reset request was submitted to Edge Cloud for this email ({{.Email}}), but no user account is associated with this email. If you submitted a password request recently, perhaps your account is using a different email address. Otherwise, you may ignore this email.

For security, this request was received from a {{.OS}} device using {{.Browser}} with IP {{.IP}}.

Thanks!
Edge Cloud Team
`

type notifyTmplArg struct {
	From    string
	To      string
	Subject string
	Message string
}

var notifyT = `From: {{.From}}
To: {{.To}}
Subject: {{.Subject}}

{{.Message}}
`

func sendNotify(ctx context.Context, to, subject, message string) error {
	if getSkipVerifyEmail(ctx, nil) {
		return nil
	}
	if to == "" {
		return fmt.Errorf("cannot send notify email as to field is blank, fix mc config")
	}

	noreply, err := cloudcommon.GetNoreply(serverConfig.vaultConfig)
	if err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelApi, "send notify email",
		"from", noreply.Email, "to", to, "subject", subject)
	arg := notifyTmplArg{
		From:    noreply.Email,
		To:      to,
		Subject: subject,
		Message: message,
	}
	buf := bytes.Buffer{}
	if err := notifyTmpl.Execute(&buf, &arg); err != nil {
		return err
	}
	return sendMailFunc(noreply, to, &buf)
}

var welcomeT = `From: {{.From}}
To: {{.To}}
Subject: Welcome to Edge Cloud!

Hi {{.Name}},

Thanks for creating an Edge Cloud account! You are now one step away from utilizing the power of the edge. Please verify this email account by clicking on the link below. Then you'll be able to login and get started.

{{ if .URL}}
Click to verify: {{.URL}}
{{ else}}
Copy and paste to verify your email:

{{ if .MCAddr}}
mcctl --addr {{.MCAddr}} user verifyemail token={{.Token}}
{{ else}}
mcctl user verifyemail token={{.Token}}
{{- end}}
{{- end}}

For security, this request was received for {{.Email}} from a {{.OS}} device using {{.Browser}} with IP {{.IP}}. If you are not expecting this email, please ignore this email or contact {{.Support}} for assistance.

Thanks!
Edge Cloud Team
`

func sendVerifyEmail(c echo.Context, username string, req *ormapi.EmailRequest) error {
	ctx := echoutil.GetContext(c)
	if getSkipVerifyEmail(ctx, nil) {
		return nil
	}
	noreply, err := cloudcommon.GetNoreply(serverConfig.vaultConfig)
	if err != nil {
		return err
	}
	config, err := getConfig(ctx)
	if err != nil {
		return err
	}
	claims := EmailClaims{
		StandardClaims: jwt.StandardClaims{
			IssuedAt: time.Now().Unix(),
			// expires in 24 hours
			ExpiresAt: time.Now().AddDate(0, 0, 1).Unix(),
		},
		Email:    req.Email,
		Username: username,
	}
	cookie, err := Jwks.GenerateCookie(&claims)
	if err != nil {
		return err
	}

	clientIP, browser, os := GetClientDetailsFromRequestHeaders(c)
	arg := emailTmplArg{
		From:    noreply.Email,
		To:      req.Email,
		Name:    username,
		Email:   req.Email,
		Token:   cookie,
		OS:      os,
		Browser: browser,
		IP:      clientIP,
		MCAddr:  serverConfig.PublicAddr,
		Support: emailGetSupportString(config),
	}
	if serverConfig.ConsoleAddr != "" && serverConfig.VerifyEmailConsolePath != "" {
		arg.URL = serverConfig.ConsoleAddr + serverConfig.VerifyEmailConsolePath + "?token=" + cookie
	}
	buf := bytes.Buffer{}
	if err := welcomeTmpl.Execute(&buf, &arg); err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelApi, "send verify email",
		"from", noreply.Email, "to", req.Email)
	return sendMailFunc(noreply, req.Email, &buf)
}

// sendEmail is only tested with gmail's smtp server.
func sendEmail(from *cloudcommon.EmailAccount, to string, contents *bytes.Buffer) error {
	auth := smtp.PlainAuth("", from.User, from.Pass, from.Smtp)

	client, err := smtp.Dial(from.Smtp + ":" + from.SmtpPort)
	if err != nil {
		return err
	}
	defer client.Close()

	tlsconfig := &tls.Config{
		ServerName: from.Smtp,
	}
	if err = client.StartTLS(tlsconfig); err != nil {
		return err
	}
	if err = client.Auth(auth); err != nil {
		return err
	}
	if err = client.Mail(from.Email); err != nil {
		return err
	}
	if err = client.Rcpt(to); err != nil {
		return err
	}
	wr, err := client.Data()
	if err != nil {
		return err
	}
	defer wr.Close()

	_, err = wr.Write(contents.Bytes())
	return err
}

type EmailClaims struct {
	jwt.StandardClaims
	Username string `json:"username"`
	Email    string `json:"email"`
	Kid      int    `json:"kid"`
}

func (s *EmailClaims) GetKid() (int, error) {
	return s.Kid, nil
}

func (s *EmailClaims) SetKid(kid int) {
	s.Kid = kid
}

func ValidEmailRequest(c echo.Context, e *ormapi.EmailRequest) error {
	if !util.ValidEmail(e.Email) {
		return fmt.Errorf("Invalid email address")
	}
	return nil
}

type addedTmplArg struct {
	From  string
	Admin string
	Name  string
	Email string
	Org   string
	Role  string
}

var addedT = `From: {{.From}}
To: {{.Email}}
Subject: Added to {{.Org}}!

Hi {{.Name}},

User {{.Admin}} has added you ({{.Email}}) to Organization {{.Org}}! Resources and permissions corresponding to your role {{.Role}} are now available to you.

Edge Cloud Team
`

func sendAddedEmail(ctx context.Context, admin, name, email, org, role string) error {
	if getSkipVerifyEmail(ctx, nil) {
		return nil
	}
	noreply, err := cloudcommon.GetNoreply(serverConfig.vaultConfig)
	if err != nil {
		return err
	}
	arg := addedTmplArg{
		From:  noreply.Email,
		Admin: admin,
		Name:  name,
		Email: email,
		Org:   org,
		Role:  role,
	}
	buf := bytes.Buffer{}
	if err := addedTmpl.Execute(&buf, &arg); err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelApi, "send added email",
		"from", noreply.Email, "to", email)
	return sendMailFunc(noreply, email, &buf)
}

func getSkipVerifyEmail(ctx context.Context, config *ormapi.Config) bool {
	if serverConfig.SkipVerifyEmail {
		return true
	}
	if config == nil {
		var err error
		config, err = getConfig(ctx)
		if err != nil {
			log.SpanLog(ctx, log.DebugLevelApi, "unable to check config for skipVerifyEmail", "err", err)
			return false
		}
	}
	return config.SkipVerifyEmail
}

type otpTmplArg struct {
	From               string
	To                 string
	Name               string
	TOTP               string
	TOTPExpirationTime string
	Support            string
}

var otpT = `From: {{.From}}
To: {{.To}}
Subject: One Time Password (OTP) for you Edge Cloud account login

Hi {{.Name}},

The One Time Password (OTP) for your account login is {{.TOTP}}.
This OTP is valid for {{.TOTPExpirationTime}}.

In case you have not requested for OTP, please contact {{.Support}} for assistance.

Thanks!
Edge Cloud Team
`

func sendOTPEmail(ctx context.Context, username, email, totp, totpExpTime string) error {
	if getSkipVerifyEmail(ctx, nil) {
		return nil
	}
	noreply, err := cloudcommon.GetNoreply(serverConfig.vaultConfig)
	if err != nil {
		return err
	}
	config, err := getConfig(ctx)
	if err != nil {
		return err
	}
	arg := otpTmplArg{
		From:               noreply.Email,
		To:                 email,
		Name:               username,
		TOTP:               totp,
		TOTPExpirationTime: totpExpTime,
		Support:            emailGetSupportString(config),
	}
	buf := bytes.Buffer{}
	if err := otpTmpl.Execute(&buf, &arg); err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelApi, "send otp email",
		"from", noreply.Email, "to", email)
	return sendMailFunc(noreply, email, &buf)
}

type operatorReportTmplArg struct {
	From         string
	To           string
	Name         string
	ReporterName string
	Org          string
	StartDate    string
	EndDate      string
	Boundary     string
	FileName     string
	Attachment   string
	Timezone     string
	Support      string
}

var operatorReportT = `Content-Type: multipart/mixed; boundary="{{.Boundary}}"
MIME-Version: 1.0
From: {{.From}}
To: {{.To}}
Subject: [{{.ReporterName}}] Cloudlet Usage Report for {{.Org}} for the period {{.StartDate}} to {{.EndDate}} (Timezone: {{.Timezone}})

--{{.Boundary}}
Content-Type: text/plain; charset="utf-8"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit

Hi {{.Name}},

Please find the attached report generated for cloudlets part of {{.Org}} organization for the period {{.StartDate}} to {{.EndDate}}

This report was automatically generated by the configured reporter: {{.ReporterName}}
If you did not request this report, please contact {{.Support}} for assistance.

Thanks!
Edge Cloud Team

--{{.Boundary}}
Content-Type: application/octet-stream
MIME-Version: 1.0
Content-Transfer-Encoding: base64
Content-Disposition: attachment; filename={{.FileName}}

{{.Attachment}}
--{{.Boundary}}--
`

func sendOperatorReportEmail(ctx context.Context, username, email, reporterName string, report *ormapi.GenerateReport, pdfFileName string, pdfFileBytes []byte) error {
	if getSkipVerifyEmail(ctx, nil) {
		return nil
	}
	noreply, err := cloudcommon.GetNoreply(serverConfig.vaultConfig)
	if err != nil {
		return err
	}
	config, err := getConfig(ctx)
	if err != nil {
		return err
	}
	writer := multipart.NewWriter(nil)
	boundary := writer.Boundary()

	attachment := base64.StdEncoding.EncodeToString(pdfFileBytes)
	pdfFileName = strings.ReplaceAll(pdfFileName, "/", "_")

	arg := operatorReportTmplArg{
		From:         noreply.Email,
		To:           email,
		Name:         username,
		ReporterName: reporterName,
		Org:          report.Org,
		StartDate:    report.StartTime.Format(ormapi.TimeFormatDate),
		EndDate:      report.EndTime.Format(ormapi.TimeFormatDate),
		Boundary:     boundary,
		FileName:     pdfFileName,
		Attachment:   attachment,
		Timezone:     report.Timezone,
		Support:      emailGetSupportString(config),
	}
	buf := bytes.Buffer{}
	if err := operatorReportTmpl.Execute(&buf, &arg); err != nil {
		return err
	}

	log.SpanLog(ctx, log.DebugLevelApi, "send operator report email",
		"from", noreply.Email, "to", email, "report file", pdfFileName)
	return sendMailFunc(noreply, email, &buf)
}

func emailGetSupportString(config *ormapi.Config) string {
	if config.SupportEmail != "" {
		return config.SupportEmail
	}
	return "support"
}
