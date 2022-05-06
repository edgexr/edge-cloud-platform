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
	"os"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/pkg/errors"
)

type tls struct {
	Cert string `json:"cert"`
	Key string `json:"key"`
	Ttl int `json:"ttl"`
}

type certlist map[string]interface{}

var CertGenPort string

// Factory creates a new usable instance of this secrets engine.
func Factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(c)
	if err := b.Setup(ctx, c); err != nil {
		return nil, errors.Wrap(err, "failed to create factory")
	}
	return b, nil
}

// backend is the actual backend.
type backend struct {
	*framework.Backend
}

// Backend creates a new backend.
func Backend(c *logical.BackendConfig) *backend {
	var b backend
	var ok bool

	CertGenPort, ok = os.LookupEnv("CERTGEN_PORT")
	if ! ok {
		CertGenPort = "4567"
	}

	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help: `

The letsencrypt secrets acts as a front-end for generating and retrieving certbot
certificates.

		`,
		Paths: []*framework.Path{
			&framework.Path{
				Pattern:      "info",
				HelpSynopsis: "Display information about this plugin",
				HelpDescription: `

Displays information about the plugin, such as the plugin version and git commit.

`,
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.ReadOperation: b.pathInfo,
				},
			},

			&framework.Path{
				Pattern:      "cert/" + framework.MatchAllRegex("domain"),
				HelpSynopsis: "Retrieve a letsencrypt cert",
				HelpDescription: `

Return the letsencrypt cert for the given domain(s), generating it if it is not present.

`,
				Fields: map[string]*framework.FieldSchema{
					"domain": {
						Type:		framework.TypeString,
						Description:	"Domain(s) (comma-separated) for the cert",
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.ReadOperation: b.pathCert,
				},
			},

			&framework.Path{
				Pattern:      "list",
				HelpSynopsis: "List all managed certs",
				HelpDescription: `

Return a list of all known certs.

`,
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.ReadOperation: b.pathCertList,
				},
			},
		},
	}

	return &b
}
