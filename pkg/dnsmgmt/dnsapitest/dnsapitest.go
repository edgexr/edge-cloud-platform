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

package dnsapitest

import (
	"context"
	"testing"

	"github.com/edgexr/edge-cloud-platform/pkg/dnsmgmt/dnsapi"
	"github.com/stretchr/testify/require"
)

func ProviderTest(t *testing.T, ctx context.Context, prov dnsapi.Provider, domain string) {

	testEntry := "unittest." + domain

	// create test entry
	ip := "127.0.0.1"
	err := prov.CreateOrUpdateDNSRecord(ctx, domain, testEntry, "A", ip, 3000, false)
	require.Nil(t, err)
	// check that it was created
	records, err := prov.GetDNSRecords(ctx, domain, testEntry)
	require.Nil(t, err)
	require.Equal(t, 1, len(records))
	require.Equal(t, testEntry, records[0].Name)
	require.Equal(t, 1, len(records[0].Content))
	require.Equal(t, ip, records[0].Content[0])

	// test updating existing entry
	ip = "192.0.0.1"
	err = prov.CreateOrUpdateDNSRecord(ctx, domain, testEntry, "A", ip, 3000, false)
	require.Nil(t, err)
	// check that it was updated
	records, err = prov.GetDNSRecords(ctx, domain, testEntry)
	require.Nil(t, err)
	require.Equal(t, 1, len(records))
	require.Equal(t, testEntry, records[0].Name)
	require.Equal(t, 1, len(records[0].Content))
	require.Equal(t, ip, records[0].Content[0])

	// delete the entry
	err = prov.DeleteDNSRecord(ctx, domain, testEntry)
	require.Nil(t, err)

	// verify it was deleted
	records, err = prov.GetDNSRecords(ctx, domain, testEntry)
	require.Nil(t, err)
	require.Equal(t, 0, len(records))
}
