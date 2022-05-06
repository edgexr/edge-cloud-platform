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
