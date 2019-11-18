package letsencrypt

import (
	"context"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/go-resty/resty/v2"
)

func (b *backend) pathCertList(_ context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	var t certlist

	client := resty.New()
	resp, err := client.R().
			SetResult(&t).
			Get("http://127.0.0.1:" + CertGenPort + "/certs")
	if err != nil {
		b.Logger().Error(err.Error())
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}
	if resp.IsError() {
		b.Logger().Warn(resp.String())
		return logical.ErrorResponse("Failed to retrieve cer list: " + resp.String()),
			logical.ErrInvalidRequest
	}

	return &logical.Response{
		Data: t,
	}, nil
}
