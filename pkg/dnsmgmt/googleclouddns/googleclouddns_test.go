// Copyright 2024 EdgeXR, Inc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package googleclouddns

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/edgexr/edge-cloud-platform/pkg/dnsmgmt/dnsapitest"
	"github.com/edgexr/edge-cloud-platform/pkg/log"
	"github.com/stretchr/testify/require"
)

func TestGoogleCloudDNS(t *testing.T) {
	// skip unless needed to debug
	t.Skip("skipping google cloud DNS test")

	log.SetDebugLevel(log.DebugLevelInfra)
	log.InitTracer(nil)
	defer log.FinishTracer()
	ctx := log.StartTestSpan(context.Background())

	domain := os.Getenv("DOMAIN")
	require.NotEmpty(t, domain, "DOMAIN env var must be set")

	creds, err := os.ReadFile("./creds.json")
	require.Nil(t, err)
	data := map[string]string{}
	err = json.Unmarshal(creds, &data)
	require.Nil(t, err)

	prov, err := GetProvider(ctx, "", data)
	require.Nil(t, err)

	dnsapitest.ProviderTest(t, ctx, prov, domain)
}
