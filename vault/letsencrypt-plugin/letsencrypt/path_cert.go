package letsencrypt

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/go-resty/resty/v2"
)

func (b *backend) pathCert(_ context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var t tls

	domain := d.Get("domain").(string)

	client := resty.New()
	resp, err := client.R().
			SetResult(&t).
			Get("http://127.0.0.1:" + CertGenPort + "/cert/" + domain)
	if err != nil {
		b.Logger().Error(err.Error())
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}
	if resp.IsError() || t.Cert == "" || t.Key == "" {
		b.Logger().Warn(resp.String())
		return logical.ErrorResponse("Failed to retrieve cert: " + resp.String()),
			logical.ErrInvalidRequest
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"cert":  t.Cert,
			"key": t.Key,
			"ttl": t.Ttl,
		},
	}, nil
}
