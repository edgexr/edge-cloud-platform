package orm

import (
	"bytes"
	"crypto/tls"
	"html/template"
	"net/smtp"
)

// These are email templates. Eventually these should be pulled
// from a registry or perhaps the UI should provide them along
// with the associated API.

var passwordResetTmpl *template.Template
var passwordResetNoneTmpl *template.Template

func init() {
	passwordResetTmpl = template.Must(template.New("pwdreset").Parse(passwordResetT))
	passwordResetNoneTmpl = template.Must(template.New("pwdresetnone").Parse(passwordResetNoneT))
}

type passwordTmplArg struct {
	From    string
	Subject string
	Name    string
	Email   string
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

Reset your password: {{.URL}}

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

type emailAccount struct {
	Email string `json:"email"`
	Pass  string `json:"pass"`
	Smtp  string `json:"smtp"`
}

// sendEmail is only tested with gmail's smtp server.
func sendEmail(from *emailAccount, to string, contents *bytes.Buffer) error {
	auth := smtp.PlainAuth("", from.Email, from.Pass, from.Smtp)

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
