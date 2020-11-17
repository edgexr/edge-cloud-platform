package orm

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net/smtp"
	"text/template"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/labstack/echo"
	"github.com/mobiledgex/edge-cloud-infra/mc/ormapi"
	"github.com/mobiledgex/edge-cloud/log"
	"github.com/mobiledgex/edge-cloud/util"
	"github.com/mobiledgex/edge-cloud/vault"
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

func init() {
	passwordResetTmpl = template.Must(template.New("pwdreset").Parse(passwordResetT))
	passwordResetNoneTmpl = template.Must(template.New("pwdresetnone").Parse(passwordResetNoneT))
	notifyTmpl = template.Must(template.New("notify").Parse(notifyT))
	welcomeTmpl = template.Must(template.New("welcome").Parse(welcomeT))
	addedTmpl = template.Must(template.New("added").Parse(addedT))
	otpTmpl = template.Must(template.New("added").Parse(otpT))
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
}

var passwordResetT = `From: {{.From}}
To: {{.Email}}
Subject: Password Reset Request

Hi {{.Name}},

You recently requested to reset your password for your MobiledgeX account. Use the link below to reset it. This password reset is only valid for the next 1 hour.

{{ if .URL}}
Reset your password: {{.URL}}
{{- else}}
Copy and paste to set your password:

mcctl user passwordreset token={{.Token}}
{{- end}}

For security, this request was received from a {{.OS}} device using {{.Browser}} with IP {{.IP}}. If you did not request this password reset, please ignore this email or contact MobiledgeX support for assistance.

Thanks!
MobiledgeX Team
`

var passwordResetNoneT = `From: {{.From}}
To: {{.Email}}
Subject: Password Reset Request

Hi,

A password reset request was submitted to MobiledgeX for this email ({{.Email}}), but no user account is associated with this email. If you submitted a password request recently, perhaps your account is using a different email address. Otherwise, you may ignore this email.

For security, this request was received from a {{.OS}} device using {{.Browser}} with IP {{.IP}}.

Thanks!
MobiledgeX Team
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
	noreply, err := getNoreply(ctx)
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
	return sendEmail(noreply, to, &buf)
}

var welcomeT = `From: {{.From}}
To: {{.To}}
Subject: Welcome to MobiledgeX!

Hi {{.Name}},

Thanks for creating a MobiledgeX account! You are now one step away from utilizing the power of the edge. Please verify this email account by clicking on the link below. Then you'll be able to login and get started.

{{ if .URL}}
Click to verify: {{.URL}}
{{ else}}
Copy and paste to verify your email:

mcctl user verifyemail token={{.Token}}
{{- end}}

For security, this request was received for {{.Email}} from a {{.OS}} device using {{.Browser}} with IP {{.IP}}. If you are not expecting this email, please ignore this email or contact MobiledgeX support for assistance.

Thanks!
MobiledgeX Team
`

func sendVerifyEmail(ctx context.Context, username string, req *ormapi.EmailRequest) error {
	if getSkipVerifyEmail(ctx, nil) {
		return nil
	}
	noreply, err := getNoreply(ctx)
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

	arg := emailTmplArg{
		From:    noreply.Email,
		To:      req.Email,
		Name:    username,
		Email:   req.Email,
		Token:   cookie,
		OS:      req.OperatingSystem,
		Browser: req.Browser,
		IP:      req.ClientIP,
	}
	if req.CallbackURL != "" {
		arg.URL = req.CallbackURL + "?token=" + cookie
	}
	buf := bytes.Buffer{}
	if err := welcomeTmpl.Execute(&buf, &arg); err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelApi, "send verify email",
		"from", noreply.Email, "to", req.Email)
	return sendEmail(noreply, req.Email, &buf)
}

type emailAccount struct {
	Email string `json:"email"`
	User  string `json:"user"`
	Pass  string `json:"pass"`
	Smtp  string `json:"smtp"`
}

func getNoreply(ctx context.Context) (*emailAccount, error) {
	log.SpanLog(ctx, log.DebugLevelApi, "lookup Vault email account")
	noreply := emailAccount{}
	err := vault.GetData(serverConfig.vaultConfig,
		"/secret/data/accounts/noreplyemail", 0, &noreply)
	if err != nil {
		return nil, err
	}
	return &noreply, nil
}

// sendEmail is only tested with gmail's smtp server.
func sendEmail(from *emailAccount, to string, contents *bytes.Buffer) error {
	auth := smtp.PlainAuth("", from.User, from.Pass, from.Smtp)

	client, err := smtp.Dial(from.Smtp + ":587")
	if err != nil {
		return err
	}
	defer client.Close()

	tlsconfig := &tls.Config{
		ServerName: from.Smtp,
	}
	client.StartTLS(tlsconfig)
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
	if e.ClientIP == "" {
		e.ClientIP = c.RealIP()
	}
	if e.OperatingSystem == "" {
		e.OperatingSystem = "unspecified OS"
	}
	if e.Browser == "" {
		e.Browser = "unspecified browser"
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

MobiledgeX Team
`

func sendAddedEmail(ctx context.Context, admin, name, email, org, role string) error {
	if getSkipVerifyEmail(ctx, nil) {
		return nil
	}
	noreply, err := getNoreply(ctx)
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
	return sendEmail(noreply, email, &buf)
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
}

var otpT = `From: {{.From}}
To: {{.To}}
Subject: One Time Password (OTP) for you MobiledgeX account login

Hi {{.Name}},

The One Time Password (OTP) for your account login is {{.TOTP}}.
This OTP is valid for {{.TOTPExpirationTime}}.

In case you have not requested for OTP, please contact us at support@mobiledgex.com

Thanks!
MobiledgeX Team
`

func sendOTPEmail(ctx context.Context, username, email, totp, totpExpTime string) error {
	if getSkipVerifyEmail(ctx, nil) {
		return nil
	}
	noreply, err := getNoreply(ctx)
	if err != nil {
		return err
	}
	arg := otpTmplArg{
		From:               noreply.Email,
		To:                 email,
		Name:               username,
		TOTP:               totp,
		TOTPExpirationTime: totpExpTime,
	}
	buf := bytes.Buffer{}
	if err := otpTmpl.Execute(&buf, &arg); err != nil {
		return err
	}
	log.SpanLog(ctx, log.DebugLevelApi, "send otp email",
		"from", noreply.Email, "to", email)
	return sendEmail(noreply, email, &buf)
}
